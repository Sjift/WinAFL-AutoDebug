"""
크래시 분석 오케스트레이션 모듈 (crash_analyzer.py)

모든 컴포넌트를 통합하여 크래시 분석 파이프라인을 실행한다.
ThreadPoolExecutor로 병렬 처리하며, 진행 콜백으로 GUI/CLI 양쪽을 지원한다.

파이프라인:
1. 설정 로드 및 검증
2. 크래시 파일 수집 (제외 패턴 적용)
3. 팝업 핸들러 시작 (활성화된 경우)
4. 디버거 엔진으로 각 파일 분석 (병렬)
5. 시그니처 추출 및 크래시 판별
6. 결과 출력 (요약 + 폴더 분류)
"""

import dataclasses
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Optional
from dataclasses import dataclass

from core.config_manager import load_config, validate_config, save_config
from core.debugger_engine import create_engine, DebuggerEngine
from core.signature_extractor import extract_signature, is_real_crash
from utils.file_collector import collect_crash_files, detect_exclude_candidates, get_new_exclude_candidates
from utils.popup_handler import create_popup_handler, PopupHandler
from utils.result_writer import AnalysisEntry, AnalysisResult, write_results


@dataclass
class AnalysisProgress:
    """분석 진행 상태 데이터"""
    total: int = 0             # 전체 파일 수
    completed: int = 0         # 완료된 파일 수
    current_file: str = ''     # 현재 분석 중인 파일명
    crashes_found: int = 0     # 발견된 크래시 수
    timeouts: int = 0          # 타임아웃 수
    errors: int = 0            # 에러 수


class CrashAnalyzer:
    """
    크래시 분석기.
    설정에 따라 디버거 엔진, 팝업 핸들러, 시그니처 전략을 구성하고
    크래시 파일들을 병렬로 분석한다.
    """

    def __init__(self, cfg: dict):
        """
        Args:
            cfg: 전체 설정 딕셔너리
        """
        self._cfg = cfg
        self._engine: DebuggerEngine = create_engine(cfg)
        self._popup_handler: PopupHandler = create_popup_handler(cfg)
        self._strategy = cfg.get('signature', {}).get('strategy', 'last')
        self._timeout = self._parse_timeout(cfg.get('timeout', 15))
        self._parallel = max(1, int(cfg.get('parallel', 4)))
        self._output_mode = cfg.get('output', {}).get('mode', 'both')

        # 분석 상태 관리
        self._stop_event = threading.Event()
        self._progress = AnalysisProgress()
        self._progress_lock = threading.Lock()

    @staticmethod
    def _parse_timeout(value) -> Optional[float]:
        """타임아웃 값을 파싱한다. 0 이하면 None (무제한)."""
        try:
            val = float(value)
            return val if val > 0 else None
        except (TypeError, ValueError):
            return 15.0

    @property
    def progress(self) -> AnalysisProgress:
        """현재 진행 상태를 반환한다."""
        return self._progress

    def stop(self):
        """분석을 중지 요청한다."""
        self._stop_event.set()

    def analyze(
        self,
        crash_dir: Path,
        out_path: Path,
        exclude_patterns: list,
        progress_callback: Optional[Callable] = None,
    ) -> AnalysisResult:
        """
        크래시 파일들을 분석한다.

        Args:
            crash_dir: 크래시 파일 디렉터리
            out_path: 결과 출력 디렉터리
            exclude_patterns: 제외 패턴 리스트
            progress_callback: 진행 콜백 (AnalysisProgress) -> None

        Returns:
            AnalysisResult 객체
        """
        self._stop_event.clear()

        # 크래시 파일 수집
        crash_files = collect_crash_files(crash_dir, exclude_patterns)
        total = len(crash_files)

        if total == 0:
            print("[INFO] 분석할 크래시 파일이 없습니다.")
            return AnalysisResult(out_path=out_path)

        # 출력 디렉터리 생성
        log_dir = out_path / 'logs'
        log_dir.mkdir(parents=True, exist_ok=True)

        # 진행 상태 초기화
        with self._progress_lock:
            self._progress = AnalysisProgress(total=total)

        print(f"[INFO] {total}개 파일을 {self._parallel}개 스레드로 분석 시작")
        print(f"[INFO] 디버거: {self._engine.get_engine_name()}, "
              f"시그니처 전략: {self._strategy}, 타임아웃: {self._timeout}초")

        # 팝업 핸들러 시작
        self._popup_handler.start()

        result = AnalysisResult(out_path=out_path)

        try:
            with ThreadPoolExecutor(max_workers=self._parallel) as executor:
                futures = {}
                for crash_file in crash_files:
                    if self._stop_event.is_set():
                        break
                    log_name = self._get_log_filename(crash_file, crash_dir)
                    log_path = log_dir / log_name

                    future = executor.submit(
                        self._analyze_one, crash_file, log_path
                    )
                    futures[future] = crash_file

                # 결과 수집
                for future in as_completed(futures):
                    if self._stop_event.is_set():
                        # 아직 시작되지 않은 작업만 취소
                        for f in futures:
                            if not f.done():
                                f.cancel()
                        break

                    crash_file = futures[future]
                    try:
                        entry = future.result()
                        result.entries.append(entry)
                    except Exception as e:
                        # 예외 발생 시 에러 엔트리 생성
                        result.entries.append(AnalysisEntry(
                            crash_file=crash_file,
                            error=str(e),
                        ))
                        with self._progress_lock:
                            self._progress.errors += 1

                    # 진행 콜백 호출 (락 안에서 복사본 생성하여 데이터 레이스 방지)
                    if progress_callback:
                        with self._progress_lock:
                            snapshot = dataclasses.replace(self._progress)
                        progress_callback(snapshot)

        finally:
            self._popup_handler.stop()

        # 결과 출력
        if not self._stop_event.is_set():
            write_results(result, out_path, self._output_mode)

        return result

    def _analyze_one(self, crash_file: Path, log_path: Path) -> AnalysisEntry:
        """
        단일 크래시 파일을 분석한다.

        Args:
            crash_file: 크래시 파일 경로
            log_path: 로그 저장 경로

        Returns:
            AnalysisEntry 객체
        """
        with self._progress_lock:
            self._progress.current_file = crash_file.name

        # 디버거 실행
        debug_result = self._engine.run(
            exe_path=Path(self._cfg['exe_path']),
            crash_file=crash_file,
            log_path=log_path,
            timeout=self._timeout,
            stop_event=self._stop_event,
        )

        # 시그니처 추출 및 엔트리 생성
        crash_info = extract_signature(debug_result.output, self._strategy)
        entry = AnalysisEntry(
            crash_file=crash_file,
            log_file=log_path if log_path.exists() else None,
            is_crash=crash_info.is_crash,
            signature=crash_info.signature if crash_info.is_crash else 'UNKNOWN',
            faulting_instruction=crash_info.faulting_instruction,
            deferred_signature=crash_info.deferred_signature,
            signature_mismatch=crash_info.signature_mismatch,
            exception_code=crash_info.exception_code,
            exception_type=crash_info.exception_type,
            timeout=debug_result.timeout,
            error=debug_result.error,
        )

        # 진행 상태 업데이트
        with self._progress_lock:
            self._progress.completed += 1
            if entry.is_crash:
                self._progress.crashes_found += 1
            if entry.timeout:
                self._progress.timeouts += 1

            completed = self._progress.completed
            total = self._progress.total
            crashes = self._progress.crashes_found

        # 로그 출력
        if entry.is_crash:
            print(f"[+] 크래시 발견 ({completed}/{total}, 누적 {crashes}개): "
                  f"{crash_file.name} -> {entry.signature}")
        elif entry.timeout:
            print(f"[!] 타임아웃 ({completed}/{total}): {crash_file.name}")
        elif entry.error:
            print(f"[!] 에러 ({completed}/{total}): {crash_file.name} - {entry.error}")

        return entry

    @staticmethod
    def _get_log_filename(crash_file: Path, crash_dir: Path) -> str:
        """
        크래시 파일 경로에서 로그 파일명을 생성한다.
        경로 구분자를 '_'로 치환하여 플랫 파일명으로 변환한다.

        Args:
            crash_file: 크래시 파일 경로
            crash_dir: 크래시 파일 기본 디렉터리

        Returns:
            로그 파일명 (예: "master_crash_001.txt")
        """
        try:
            relative = crash_file.relative_to(crash_dir)
        except ValueError:
            relative = Path(crash_file.name)
        return str(relative).replace('\\', '_').replace('/', '_') + '.txt'
