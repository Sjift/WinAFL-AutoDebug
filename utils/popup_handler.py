"""
팝업 핸들러 모듈 (popup_handler.py)

범용적인 팝업 윈도우 자동 처리기.
ctypes Win32 API 직접 호출로 팝업 윈도우를 감지하고 닫는다.
데몬 스레드로 동작하며, 설정에서 타겟을 추가/수정/삭제할 수 있다.
"""

import re
import time
import ctypes
import ctypes.wintypes
import threading
import logging
from dataclasses import dataclass, field
from typing import Callable, Optional

logger = logging.getLogger(__name__)

# ============================================================
# Win32 API 상수 및 함수 바인딩
# ============================================================
WM_CLOSE = 0x0010
WM_SYSCOMMAND = 0x0112
SC_CLOSE = 0xF060

_user32 = ctypes.windll.user32

# EnumWindows 콜백 타입: BOOL CALLBACK(HWND, LPARAM)
_WNDENUMPROC = ctypes.WINFUNCTYPE(
    ctypes.wintypes.BOOL,
    ctypes.wintypes.HWND,
    ctypes.wintypes.LPARAM,
)

# 자주 사용하는 Win32 함수 바인딩 (호출 오버헤드 최소화)
_EnumWindows = _user32.EnumWindows
_GetWindowTextW = _user32.GetWindowTextW
_GetWindowTextLengthW = _user32.GetWindowTextLengthW
_GetWindowRect = _user32.GetWindowRect
_IsWindowVisible = _user32.IsWindowVisible
_PostMessageW = _user32.PostMessageW
_SetForegroundWindow = _user32.SetForegroundWindow
_GetWindowThreadProcessId = _user32.GetWindowThreadProcessId


def _enum_visible_windows() -> list[tuple[int, str, int, int]]:
    """현재 보이는 모든 최상위 윈도우를 열거한다."""
    results = []
    _buf = ctypes.create_unicode_buffer(256)
    _rect = ctypes.wintypes.RECT()

    def _callback(hwnd, _lparam):
        """EnumWindows 콜백: 보이는 윈도우의 타이틀과 크기를 수집한다."""
        if not _IsWindowVisible(hwnd):
            return True
        length = _GetWindowTextLengthW(hwnd)
        if length == 0:
            return True
        _GetWindowTextW(hwnd, _buf, min(length + 1, 256))
        title = _buf.value
        _GetWindowRect(hwnd, ctypes.byref(_rect))
        width = _rect.right - _rect.left
        height = _rect.bottom - _rect.top
        results.append((hwnd, title, width, height))
        return True

    _EnumWindows(_WNDENUMPROC(_callback), 0)
    return results


def _get_pid_from_hwnd(hwnd: int) -> int:
    """hwnd로부터 프로세스 PID를 가져온다."""
    pid = ctypes.wintypes.DWORD()
    _GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return pid.value


@dataclass
class PopupTarget:
    """
    팝업 타겟 정의.
    title_pattern에 매칭되고 크기 조건을 만족하는 윈도우를 처리한다.
    """
    title_pattern: str         # 윈도우 제목 매칭 패턴 (정규식 또는 부분 문자열)
    max_width: int = 9999      # 최대 너비 (이하인 윈도우만 대상)
    max_height: int = 9999     # 최대 높이 (이하인 윈도우만 대상)
    action: str = 'close'      # 처리 액션: 'close' 또는 'kill'
    use_regex: bool = False    # True면 정규식, False면 부분 문자열 매칭

    def matches_title(self, title: str) -> bool:
        """윈도우 제목이 이 타겟의 패턴과 일치하는지 검사한다."""
        if not title:
            return False
        if self.use_regex:
            try:
                return bool(re.search(self.title_pattern, title))
            except re.error:
                return False
        else:
            return self.title_pattern in title

    def matches_size(self, width: int, height: int) -> bool:
        """윈도우 크기가 조건을 만족하는지 검사한다."""
        return width <= self.max_width and height <= self.max_height


def _kill_process_by_pid(pid: int):
    """프로세스를 강제 종료한다. taskkill /F /T로 프로세스 트리 전체를 종료."""
    import subprocess
    try:
        subprocess.run(
            ['taskkill', '/F', '/T', '/PID', str(pid)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
        )
    except OSError:
        pass


class PopupHandler:
    """
    범용 팝업 핸들러.
    데몬 스레드로 동작하며 지정된 타겟 패턴과 일치하는 팝업을 자동으로 처리한다.
    스캔 루프는 ctypes Win32 API 직접 호출로 ~1-3ms/회.
    """

    def __init__(
        self,
        targets: list = None,
        scan_interval: float = 0.1,
        enabled: bool = False,
    ):
        self._targets = targets or []
        self._targets_lock = threading.Lock()  # 타겟 리스트 동기화
        self._scan_interval = scan_interval
        self._enabled = enabled
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        # hwnd → (시도 횟수, 최초 감지 시각, 타이틀) — non-blocking 재시도 추적
        self._popup_attempts: dict[int, tuple[int, float, str]] = {}

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def targets(self) -> list:
        """타겟 리스트의 복사본을 반환한다. Lock으로 보호하여 스캔 루프와의 경합 방지."""
        with self._targets_lock:
            return list(self._targets)

    @targets.setter
    def targets(self, value: list):
        """타겟 리스트를 설정한다. Lock으로 보호하여 스캔 루프와의 경합 방지."""
        with self._targets_lock:
            self._targets = list(value)  # 복사본 저장

    def start(self):
        """팝업 핸들러 데몬 스레드를 시작한다."""
        if not self._enabled:
            return

        if not self._targets:
            logger.info("팝업 타겟이 없어 핸들러를 시작하지 않습니다.")
            return

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._scan_loop, daemon=True)
        self._thread.start()
        logger.info("팝업 핸들러 시작됨 (타겟 %d개, 주기 %.1f초)", len(self._targets), self._scan_interval)

    def stop(self):
        """팝업 핸들러를 정지한다."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        self._popup_attempts.clear()
        logger.info("팝업 핸들러 정지됨")

    def _scan_loop(self):
        """메인 스캔 루프. Non-blocking ctypes 직접 호출로 윈도우를 열거하고 처리한다."""
        while not self._stop_event.is_set():
            matched_hwnds = set()  # 이번 스캔에서 매칭된 hwnd 추적
            try:
                # 타겟 스냅샷: Lock 밖에서 순회하여 경합 최소화
                with self._targets_lock:
                    targets_snapshot = list(self._targets)

                # ctypes 직접 열거 — GetWindowTextW는 캐시 기반으로 블로킹 없음
                for hwnd, title, width, height in _enum_visible_windows():
                    for target in targets_snapshot:
                        if target.matches_title(title) and target.matches_size(width, height):
                            matched_hwnds.add(hwnd)
                            self._handle_popup(hwnd, target, title)
                            break  # 하나의 타겟만 매칭
            except Exception:
                pass  # 전체 순회 실패 시 무시하고 재시도

            # 이번 스캔에서 안 보인 hwnd → 닫힘 처리
            closed_hwnds = [h for h in self._popup_attempts if h not in matched_hwnds]
            for hwnd in closed_hwnds:
                self._popup_attempts.pop(hwnd)

            self._stop_event.wait(self._scan_interval)

    def _handle_popup(self, hwnd: int, target: PopupTarget, title: str):
        """매칭된 팝업 윈도우를 Non-blocking 방식으로 처리한다."""
        # 시도 횟수 추적 — (count, first_seen, title)
        now = time.time()
        if hwnd in self._popup_attempts:
            count, first_seen, _ = self._popup_attempts[hwnd]
            count += 1
            self._popup_attempts[hwnd] = (count, first_seen, title)
        else:
            # 최초 감지
            count = 1
            self._popup_attempts[hwnd] = (1, now, title)

        try:
            if target.action == 'close':
                # 첫 시도에만 포커스 활성화 (실패 무시)
                if count == 1:
                    try:
                        _SetForegroundWindow(hwnd)
                    except Exception:
                        pass

                # PostMessageW로 WM_CLOSE + SC_CLOSE 비동기 연속 발사
                # 두 메시지를 모두 보내 서로 다른 메시지 경로를 커버
                _PostMessageW(hwnd, WM_CLOSE, 0, 0)
                _PostMessageW(hwnd, WM_SYSCOMMAND, SC_CLOSE, 0)

            elif target.action == 'kill':
                # 강제 종료: hwnd에서 PID 추출 후 프로세스 트리 kill
                try:
                    pid = _get_pid_from_hwnd(hwnd)
                    if pid:
                        _kill_process_by_pid(pid)
                except Exception:
                    # fallback: WM_CLOSE라도 보내기
                    _PostMessageW(hwnd, WM_CLOSE, 0, 0)
                # kill은 즉시 처리 완료로 간주하여 추적에서 제거
                self._popup_attempts.pop(hwnd, None)
        except Exception:
            pass  # 윈도우가 이미 사라졌을 수 있음

    def scan_once(self) -> list:
        """테스트 모드: 타겟과 매칭되는 윈도우를 스캔하여 반환한다. 실제로 닫지는 않는다."""
        with self._targets_lock:
            targets_snapshot = list(self._targets)

        matches = []
        try:
            for hwnd, title, width, height in _enum_visible_windows():
                for target in targets_snapshot:
                    if target.matches_title(title) and target.matches_size(width, height):
                        matches.append((title, width, height, target.title_pattern))
                        break
        except Exception:
            pass

        return matches


def create_popup_handler(cfg: dict) -> PopupHandler:
    """설정 딕셔너리에서 PopupHandler를 생성한다."""
    # None 방어: cfg['popup_handler']가 None일 수 있음 (YAML 파싱 또는 취소된 다이얼로그)
    popup_cfg = cfg.get('popup_handler') or {}
    targets = []

    for t in popup_cfg.get('targets', []):
        targets.append(PopupTarget(
            title_pattern=t.get('title_pattern', ''),
            max_width=t.get('max_width', 9999),
            max_height=t.get('max_height', 9999),
            action=t.get('action', 'close'),
            use_regex=t.get('use_regex', False),
        ))

    return PopupHandler(
        targets=targets,
        scan_interval=popup_cfg.get('scan_interval', 0.1),
        enabled=popup_cfg.get('enabled', False),
    )
