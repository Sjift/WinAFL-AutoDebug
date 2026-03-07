"""
디버거 엔진 모듈 (debugger_engine.py)

CDB와 WinDbgX 디버거를 추상화하여 통일된 인터페이스를 제공한다.
Strategy 패턴으로 구현하여 설정에 따라 엔진을 교체할 수 있다.

두 엔진 모두 -logo 옵션으로 로그 파일에 직접 기록하는 방식을 사용한다.
stdout 파이프 방식은 파이프 버퍼 데드락 문제가 있어 사용하지 않는다.
"""

import shutil
import subprocess
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional


# CDB 자동 탐색 경로 (Windows SDK 설치 위치)
# x86 대상 디버깅이 일반적이므로 x86을 우선 탐색
CDB_SEARCH_PATHS = [
    Path(r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe"),
    Path(r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe"),
    Path(r"C:\Program Files (x86)\Windows Kits\10\Debuggers\arm64\cdb.exe"),
]


def _find_cdb() -> str:
    """
    CDB 실행 파일 경로를 자동 탐색한다.
    1. PATH 환경변수에서 탐색 (shutil.which)
    2. Windows SDK 설치 경로에서 탐색
    3. 실패 시 'cdb' 반환 (PATH에 의존)

    Returns:
        CDB 실행 파일 경로
    """
    # 1. PATH에서 탐색
    found = shutil.which('cdb')
    if found:
        return found

    # 2. Windows SDK 경로 탐색
    for path in CDB_SEARCH_PATHS:
        if path.is_file():
            return str(path)

    # 3. 폴백
    return 'cdb'


def _kill_process_tree(pid: int):
    """
    프로세스와 모든 자식 프로세스를 강제 종료한다.
    taskkill /F /T 로 프로세스 트리 전체를 종료하여
    디버거가 띄운 대상 프로그램(자식)이 남지 않도록 한다.

    Args:
        pid: 종료할 프로세스의 PID
    """
    try:
        subprocess.run(
            ['taskkill', '/F', '/T', '/PID', str(pid)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
        )
    except OSError:
        pass


def _is_log_complete(log_path: Path) -> bool:
    """
    로그 파일 끝에 'quit:' 마커가 있는지 확인한다.
    WinDbgX는 qq 명령 후에도 UI 프로세스가 종료되지 않으므로,
    로그 파일에 quit: 마커가 기록되면 분석 완료로 판단한다.

    파일 끝 64바이트만 읽으므로 I/O 부담 최소.

    Args:
        log_path: 로그 파일 경로

    Returns:
        True면 로그 기록 완료 (qq 실행됨)
    """
    try:
        if not log_path.exists():
            return False
        size = log_path.stat().st_size
        if size < 10:
            return False
        with log_path.open('rb') as f:
            f.seek(max(0, size - 64))
            tail = f.read().decode('utf-8', errors='replace')
        return 'quit:' in tail
    except OSError:
        return False


@dataclass
class DebugResult:
    """디버깅 결과를 담는 데이터 클래스"""
    crash_file: Path           # 원본 크래시 파일 경로
    output: str = ''           # 디버거 전체 출력
    timeout: bool = False      # 타임아웃 발생 여부
    error: Optional[str] = None  # 에러 메시지 (있으면)


class DebuggerEngine(ABC):
    """디버거 엔진 추상 기반 클래스"""

    @abstractmethod
    def run(
        self,
        exe_path: Path,
        crash_file: Path,
        log_path: Path,
        timeout: Optional[float] = None,
        stop_event: Optional[threading.Event] = None,
    ) -> DebugResult:
        """
        크래시 파일로 대상 프로그램을 디버거로 실행한다.

        Args:
            exe_path: 대상 실행 파일 경로
            crash_file: 크래시 입력 파일 경로
            log_path: 디버그 로그 저장 경로
            timeout: 타임아웃 (초). None이면 무제한.
            stop_event: 중지 시그널. set()되면 즉시 프로세스 종료.

        Returns:
            DebugResult 객체
        """
        pass

    @abstractmethod
    def get_engine_name(self) -> str:
        """엔진 이름을 반환한다."""
        pass

    @staticmethod
    def _poll_process(
        proc: subprocess.Popen,
        result: 'DebugResult',
        timeout: Optional[float],
        stop_event: Optional[threading.Event],
        early_complete_check: Optional[Callable[[], bool]] = None,
    ):
        """
        프로세스 완료를 폴링 방식으로 대기한다.
        CDB/WinDbgX 공통 폴링 루프를 통합한다.

        Args:
            proc: 실행 중인 프로세스
            result: 결과 객체 (timeout/error 필드가 설정됨)
            timeout: 타임아웃 (초). None이면 무제한.
            stop_event: 중지 시그널. set()되면 즉시 프로세스 종료.
            early_complete_check: 추가 완료 조건 콜백 (WinDbgX 로그 완료 감지용).
                                  True 반환 시 프로세스를 종료하고 정상 완료 처리.
        """
        start_time = time.time()
        while True:
            # 프로세스 종료 체크
            if proc.poll() is not None:
                break

            # 조기 완료 체크 (WinDbgX 로그 완료 감지)
            if early_complete_check is not None and early_complete_check():
                _kill_process_tree(proc.pid)
                proc.wait()
                break

            # 중지 요청 체크
            if stop_event is not None and stop_event.is_set():
                _kill_process_tree(proc.pid)
                proc.wait()
                result.error = "사용자 중지"
                return

            # 타임아웃 체크
            if timeout is not None and time.time() - start_time >= timeout:
                _kill_process_tree(proc.pid)
                proc.wait()
                result.timeout = True
                break

            time.sleep(0.1)

    @staticmethod
    def _read_log(result: 'DebugResult', log_path: Path, encoding: str = 'utf-8'):
        """
        로그 파일에서 디버거 출력을 읽어 result.output에 저장한다.
        encoding이 utf-8이 아니면 읽은 후 UTF-8로 재저장한다.

        Args:
            result: 결과 객체
            log_path: 로그 파일 경로
            encoding: 로그 파일 인코딩 (CDB: cp949, WinDbgX: utf-8)
        """
        try:
            if log_path.exists():
                result.output = log_path.read_text(encoding=encoding, errors='replace')
                # UTF-8이 아닌 경우 재저장 (다른 모듈에서 UTF-8로 읽으므로 통일)
                if encoding != 'utf-8':
                    log_path.write_text(result.output, encoding='utf-8')
        except OSError as e:
            result.error = f"로그 읽기 실패: {e}"


class CDBEngine(DebuggerEngine):
    """
    CDB (Console Debugger) 엔진.
    -logo 옵션으로 로그 파일에 직접 기록한다.
    stdout 파이프 방식은 파이프 버퍼 데드락 문제가 있어 사용하지 않는다.
    (파이프 64KB 버퍼 초과 시 CDB가 쓰기 블로킹 → 영구 멈춤)
    """

    def __init__(self, cdb_path: str = ''):
        """
        Args:
            cdb_path: CDB 실행 파일 경로. 빈 문자열이면 자동 탐색.
        """
        self._cdb_path = cdb_path if cdb_path else _find_cdb()

    def get_engine_name(self) -> str:
        return 'CDB'

    def run(
        self,
        exe_path: Path,
        crash_file: Path,
        log_path: Path,
        timeout: Optional[float] = None,
        stop_event: Optional[threading.Event] = None,
    ) -> DebugResult:
        """
        CDB로 크래시 파일을 디버깅한다.

        CDB 플래그:
        - -g: 초기 브레이크포인트(loader BP) 무시
        - -G: 최종 브레이크포인트(process exit BP) 무시
        - -o: 자식 프로세스 디버깅
        - -logo: 로그 파일에 출력 기록 (overwrite)
                 stdout 파이프 대신 사용하여 버퍼 데드락 방지.
                 파일에 실시간 기록되므로 타임아웃 시에도 부분 로그 확보 가능.

        -c 명령 시퀀스 (세미콜론 분리, 순차 실행):
        - g        : 프로그램 실행. 세미콜론 뒤 나머지 명령은 크래시(debug event) 발생까지 대기
        - .exr -1  : 마지막 예외 레코드 출력 (ExceptionCode, ExceptionAddress)
        - .ecxr    : 예외 발생 시점으로 컨텍스트 전환 (이후 kn이 실제 크래시 스택을 보여줌)
        - kn       : 프레임 번호 포함 스택 트레이스
        - !analyze -v : BUCKET_ID 등 종합 자동 분석
        - q        : 디버거 종료
        """
        command = [
            self._cdb_path,
            '-g', '-G', '-o',
            '-c', 'g; .exr -1; .ecxr; kn; !analyze -v; q',
            '-logo', str(log_path),
            str(exe_path),
            str(crash_file),
        ]

        result = DebugResult(crash_file=crash_file)
        creation_flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)

        try:
            proc = subprocess.Popen(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=creation_flags,
            )

            self._poll_process(proc, result, timeout, stop_event)
            if result.error:
                return result

            # CDB 출력은 시스템 로캘 인코딩 (cp949)
            self._read_log(result, log_path, encoding='cp949')

        except FileNotFoundError:
            result.error = f"CDB를 찾을 수 없습니다: {self._cdb_path}"
        except OSError as e:
            result.error = f"프로세스 실행 실패: {e}"

        return result


class WinDbgXEngine(DebuggerEngine):
    """
    WinDbgX (Preview) 엔진.
    GUI 기반 디버거로, -logo 옵션으로 로그 파일에 출력을 기록한다.
    로그 파일을 읽어서 결과를 반환한다.
    CDB와 동일한 명령 시퀀스를 사용하여 로그 포맷을 통일한다.
    """

    def __init__(self, windbgx_path: str = ''):
        """
        Args:
            windbgx_path: WinDbgX 실행 파일 경로. 빈 문자열이면 PATH에서 탐색.
        """
        self._windbgx_path = windbgx_path if windbgx_path else 'windbgx'

    def get_engine_name(self) -> str:
        return 'WinDbgX'

    def run(
        self,
        exe_path: Path,
        crash_file: Path,
        log_path: Path,
        timeout: Optional[float] = None,
        stop_event: Optional[threading.Event] = None,
    ) -> DebugResult:
        """
        WinDbgX로 크래시 파일을 디버깅한다.

        WinDbgX 플래그:
        - -g: 초기 브레이크포인트(loader BP) 무시
        - -G: 최종 브레이크포인트(process exit BP) 무시
        - -o: 자식 프로세스 디버깅
        - -Q: "Save Workspace?" 다이얼로그 억제 (자동화 차단 방지)

        -c 명령 시퀀스 (CDB와 동일, 단 종료 명령만 다름):
        - g        : 프로그램 실행. 나머지 명령은 크래시(debug event) 발생까지 대기
        - .exr -1  : 마지막 예외 레코드 출력 (ExceptionCode, ExceptionAddress)
        - .ecxr    : 예외 발생 시점으로 컨텍스트 전환
        - kn       : 프레임 번호 포함 스택 트레이스
        - !analyze -v : BUCKET_ID 등 종합 자동 분석
        - qq       : 디버거 강제 종료 (WinDbgX는 클라이언트-서버 구조라
                     q만 쓰면 클라이언트만 종료되고 서버가 남음. qq로 전체 종료)

        -logo: 기존 -loga(append)에서 overwrite로 변경.
               크래시별 개별 로그 파일을 사용하므로 덮어쓰기가 적절.
        """
        command = [
            self._windbgx_path,
            '-g', '-G', '-o', '-Q',
            '-c', 'g; .exr -1; .ecxr; kn; !analyze -v; qq',
            '-logo', str(log_path),
            str(exe_path),
            str(crash_file),
        ]

        result = DebugResult(crash_file=crash_file)
        creation_flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)

        try:
            proc = subprocess.Popen(command, creationflags=creation_flags)

            # qq 후에도 UI Host가 남으므로 로그 "quit:" 마커로 완료 감지
            self._poll_process(
                proc, result, timeout, stop_event,
                early_complete_check=lambda: _is_log_complete(log_path),
            )
            if result.error:
                return result

            self._read_log(result, log_path, encoding='utf-8')

        except FileNotFoundError:
            result.error = f"WinDbgX를 찾을 수 없습니다: {self._windbgx_path}"
        except OSError as e:
            result.error = f"프로세스 실행 실패: {e}"

        return result


def create_engine(cfg: dict) -> DebuggerEngine:
    """
    설정에 따라 적절한 디버거 엔진을 생성한다.

    Args:
        cfg: 전체 설정 딕셔너리 (debugger 섹션 사용)

    Returns:
        DebuggerEngine 인스턴스

    Raises:
        ValueError: 지원하지 않는 엔진 이름일 때
    """
    debugger_cfg = cfg.get('debugger', {})
    engine_name = debugger_cfg.get('engine', 'cdb').lower()

    if engine_name == 'cdb':
        return CDBEngine(cdb_path=debugger_cfg.get('cdb_path', ''))
    elif engine_name == 'windbgx':
        return WinDbgXEngine(windbgx_path=debugger_cfg.get('windbgx_path', ''))
    else:
        raise ValueError(f"지원하지 않는 디버거 엔진: {engine_name}")
