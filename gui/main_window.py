"""
메인 대시보드 윈도우 (main_window.py)

CustomTkinter 기반 AutoDebug v3 메인 GUI.
설정, 분석 제어, 진행 상태, 결과 요약, 로그를 한 화면에 표시한다.
threading.Queue로 스레드 안전한 GUI 업데이트를 수행한다.
"""

import os
import queue
import threading
import time
import tkinter as tk
from pathlib import Path
from typing import Optional

import customtkinter as ctk

from core.config_manager import load_config, save_config, validate_config, DEFAULT_CONFIG, deep_merge
from core.crash_analyzer import CrashAnalyzer, AnalysisProgress
from utils.file_collector import collect_crash_files, detect_exclude_candidates, get_new_exclude_candidates
from utils.result_writer import AnalysisResult
from gui.exclude_dialog import ExcludeCandidateDialog


class MainWindow(ctk.CTk):
    """AutoDebug v3 메인 대시보드 윈도우"""

    def __init__(self, config_path: str = 'config.yaml'):
        super().__init__()

        self._config_path = Path(config_path)
        self._cfg = load_config(self._config_path)
        self._analyzer: Optional[CrashAnalyzer] = None
        self._analysis_thread: Optional[threading.Thread] = None
        self._result: Optional[AnalysisResult] = None

        self._update_queue = queue.Queue()

        from core import __version__
        self.title(f"AutoDebug v{__version__} - Crash Analysis Tool")
        self.geometry("900x750")
        self.minsize(800, 650)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self._build_ui()
        self._load_config_to_ui()

        # 설정 변경 감지용 스냅샷 (UI 로드 완료 후)
        self._saved_cfg = self._ui_to_config()
        self._poll_updates()

    # ============================================================
    # UI 구성
    # ============================================================

    def _build_ui(self):
        """전체 UI를 구성한다."""
        # 메인 스크롤 프레임
        self._main_frame = ctk.CTkFrame(self)
        self._main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self._build_config_section()
        self._build_analysis_section()
        self._build_progress_section()
        self._build_results_section()
        self._build_log_section()

    def _build_config_section(self):
        """설정 섹션을 구성한다."""
        frame = ctk.CTkFrame(self._main_frame)
        frame.pack(fill="x", padx=5, pady=(5, 2))

        ctk.CTkLabel(frame, text="설정", font=("", 14, "bold")).pack(anchor="w", padx=10, pady=(5, 2))

        # 경로 입력 행들
        paths_frame = ctk.CTkFrame(frame, fg_color="transparent")
        paths_frame.pack(fill="x", padx=10, pady=2)

        # Crash Directory
        row1 = ctk.CTkFrame(paths_frame, fg_color="transparent")
        row1.pack(fill="x", pady=1)
        ctk.CTkLabel(row1, text="Crash Dir:", width=80, anchor="w").pack(side="left")
        self._crash_dir_var = ctk.StringVar()
        ctk.CTkEntry(row1, textvariable=self._crash_dir_var, width=500).pack(side="left", padx=5, fill="x", expand=True)
        ctk.CTkButton(row1, text="찾기", width=60, command=lambda: self._browse_dir(self._crash_dir_var)).pack(side="left")

        # Executable
        row2 = ctk.CTkFrame(paths_frame, fg_color="transparent")
        row2.pack(fill="x", pady=1)
        ctk.CTkLabel(row2, text="Exe Path:", width=80, anchor="w").pack(side="left")
        self._exe_path_var = ctk.StringVar()
        ctk.CTkEntry(row2, textvariable=self._exe_path_var, width=500).pack(side="left", padx=5, fill="x", expand=True)
        ctk.CTkButton(row2, text="찾기", width=60, command=lambda: self._browse_file(self._exe_path_var)).pack(side="left")

        # Output Directory
        row3 = ctk.CTkFrame(paths_frame, fg_color="transparent")
        row3.pack(fill="x", pady=1)
        ctk.CTkLabel(row3, text="Out Path:", width=80, anchor="w").pack(side="left")
        self._out_path_var = ctk.StringVar()
        ctk.CTkEntry(row3, textvariable=self._out_path_var, width=500).pack(side="left", padx=5, fill="x", expand=True)
        ctk.CTkButton(row3, text="찾기", width=60, command=lambda: self._browse_dir(self._out_path_var)).pack(side="left")

        # 옵션 행
        opts_frame = ctk.CTkFrame(frame, fg_color="transparent")
        opts_frame.pack(fill="x", padx=10, pady=2)

        ctk.CTkLabel(opts_frame, text="Timeout:", width=60, anchor="w").pack(side="left")
        self._timeout_var = ctk.StringVar()
        ctk.CTkEntry(opts_frame, textvariable=self._timeout_var, width=50).pack(side="left", padx=(0, 5))
        ctk.CTkLabel(opts_frame, text="초", width=20).pack(side="left", padx=(0, 15))

        ctk.CTkLabel(opts_frame, text="Parallel:", width=60, anchor="w").pack(side="left")
        self._parallel_var = ctk.StringVar()
        ctk.CTkEntry(opts_frame, textvariable=self._parallel_var, width=50).pack(side="left", padx=(0, 15))

        ctk.CTkLabel(opts_frame, text="Debugger:", width=65, anchor="w").pack(side="left")
        self._debugger_var = ctk.StringVar()
        ctk.CTkComboBox(opts_frame, variable=self._debugger_var, values=["cdb", "windbgx"],
                        width=100, state="readonly").pack(side="left", padx=(0, 15))

        ctk.CTkLabel(opts_frame, text="Strategy:", width=60, anchor="w").pack(side="left")
        self._strategy_var = ctk.StringVar()
        ctk.CTkComboBox(opts_frame, variable=self._strategy_var, values=["last", "first"],
                        width=80, state="readonly").pack(side="left", padx=(0, 15))

        # 버튼 행
        btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
        btn_frame.pack(fill="x", padx=10, pady=(2, 5))

        ctk.CTkButton(btn_frame, text="설정 저장", width=100, command=self._save_config).pack(side="left", padx=2)
        ctk.CTkButton(btn_frame, text="설정 새로고침", width=100, command=self._reload_config).pack(side="left", padx=2)
        ctk.CTkButton(btn_frame, text="팝업 설정", width=100, command=self._open_popup_config).pack(side="left", padx=2)

        # 출력 모드
        ctk.CTkLabel(btn_frame, text="출력:", width=35, anchor="w").pack(side="left", padx=(15, 0))
        self._output_mode_var = ctk.StringVar()
        ctk.CTkComboBox(btn_frame, variable=self._output_mode_var,
                        values=["both", "summary", "folders"],
                        width=100, state="readonly").pack(side="left", padx=2)

    def _build_analysis_section(self):
        """분석 제어 섹션을 구성한다."""
        frame = ctk.CTkFrame(self._main_frame)
        frame.pack(fill="x", padx=5, pady=2)

        inner = ctk.CTkFrame(frame, fg_color="transparent")
        inner.pack(fill="x", padx=10, pady=5)

        self._file_count_label = ctk.CTkLabel(inner, text="파일: - 개", width=150, anchor="w")
        self._file_count_label.pack(side="left")

        self._start_btn = ctk.CTkButton(inner, text="분석 시작", width=120,
                                        fg_color="#28a745", hover_color="#218838",
                                        command=self._start_analysis)
        self._start_btn.pack(side="left", padx=5)

        self._stop_btn = ctk.CTkButton(inner, text="중지", width=80,
                                       fg_color="#dc3545", hover_color="#c82333",
                                       command=self._stop_analysis, state="disabled")
        self._stop_btn.pack(side="left", padx=5)

        ctk.CTkButton(inner, text="파일 스캔", width=100,
                      command=self._scan_files).pack(side="left", padx=5)

        ctk.CTkButton(inner, text="출력 폴더 열기", width=120,
                      command=self._open_output_dir).pack(side="right", padx=5)

    def _build_progress_section(self):
        """진행 상태 섹션을 구성한다."""
        frame = ctk.CTkFrame(self._main_frame)
        frame.pack(fill="x", padx=5, pady=2)

        ctk.CTkLabel(frame, text="진행", font=("", 14, "bold")).pack(anchor="w", padx=10, pady=(5, 2))

        self._progress_bar = ctk.CTkProgressBar(frame, width=400)
        self._progress_bar.pack(fill="x", padx=10, pady=2)
        self._progress_bar.set(0)

        info_frame = ctk.CTkFrame(frame, fg_color="transparent")
        info_frame.pack(fill="x", padx=10, pady=(0, 5))

        self._progress_label = ctk.CTkLabel(info_frame, text="대기 중", anchor="w")
        self._progress_label.pack(side="left")

        self._elapsed_label = ctk.CTkLabel(info_frame, text="", anchor="e")
        self._elapsed_label.pack(side="right")

    def _build_results_section(self):
        """결과 요약 섹션을 구성한다."""
        frame = ctk.CTkFrame(self._main_frame)
        frame.pack(fill="x", padx=5, pady=2)

        ctk.CTkLabel(frame, text="결과", font=("", 14, "bold")).pack(anchor="w", padx=10, pady=(5, 2))

        stats_frame = ctk.CTkFrame(frame, fg_color="transparent")
        stats_frame.pack(fill="x", padx=10, pady=2)

        self._stats_labels = {}
        for name, label_text in [
            ('unique', '고유 크래시:'), ('total', '총 크래시:'),
            ('timeout', '타임아웃:'), ('fp', 'False Positive:'),
        ]:
            lf = ctk.CTkFrame(stats_frame, fg_color="transparent")
            lf.pack(side="left", padx=10)
            ctk.CTkLabel(lf, text=label_text, anchor="w").pack(side="left")
            lbl = ctk.CTkLabel(lf, text="-", anchor="w", font=("", 13, "bold"))
            lbl.pack(side="left", padx=5)
            self._stats_labels[name] = lbl

        # 상위 시그니처 리스트
        self._sig_textbox = ctk.CTkTextbox(frame, height=100, state="disabled")
        self._sig_textbox.pack(fill="x", padx=10, pady=(2, 5))

    def _build_log_section(self):
        """로그 출력 섹션을 구성한다."""
        frame = ctk.CTkFrame(self._main_frame)
        frame.pack(fill="both", expand=True, padx=5, pady=(2, 5))

        header = ctk.CTkFrame(frame, fg_color="transparent")
        header.pack(fill="x", padx=10, pady=(5, 2))
        ctk.CTkLabel(header, text="로그", font=("", 14, "bold")).pack(side="left")
        ctk.CTkButton(header, text="지우기", width=60,
                      command=self._clear_log).pack(side="right")

        self._log_textbox = ctk.CTkTextbox(frame, height=120)
        self._log_textbox.pack(fill="both", expand=True, padx=10, pady=(0, 5))

    # ============================================================
    # 설정 관리
    # ============================================================

    def _load_config_to_ui(self):
        """설정값을 UI에 반영한다."""
        self._crash_dir_var.set(self._cfg.get('crash_dir', ''))
        self._exe_path_var.set(self._cfg.get('exe_path', ''))
        self._out_path_var.set(self._cfg.get('out_path', ''))
        self._timeout_var.set(str(self._cfg.get('timeout', 15)))
        self._parallel_var.set(str(self._cfg.get('parallel', 4)))
        self._debugger_var.set(self._cfg.get('debugger', {}).get('engine', 'cdb'))
        self._strategy_var.set(self._cfg.get('signature', {}).get('strategy', 'last'))
        self._output_mode_var.set(self._cfg.get('output', {}).get('mode', 'both'))

    def _save_config(self):
        """UI의 설정값을 config.yaml에 저장한다."""
        self._cfg = self._ui_to_config()
        save_config(self._config_path, self._cfg)
        # 저장 완료 후 스냅샷 갱신 (변경 감지 기준점 업데이트)
        self._saved_cfg = self._ui_to_config()
        self._log("설정이 저장되었습니다.")

    def _reload_config(self):
        """config.yaml을 다시 로드한다."""
        self._cfg = load_config(self._config_path)
        self._load_config_to_ui()
        # 새로고침 후 스냅샷 갱신 (변경 감지 기준점 업데이트)
        self._saved_cfg = self._ui_to_config()
        self._log("설정이 새로고침되었습니다.")

    def _ui_to_config(self) -> dict:
        """현재 UI 값을 설정 딕셔너리로 변환한다."""
        cfg = deep_merge(DEFAULT_CONFIG, self._cfg)
        cfg['crash_dir'] = self._crash_dir_var.get()
        cfg['exe_path'] = self._exe_path_var.get()
        cfg['out_path'] = self._out_path_var.get()

        try:
            cfg['timeout'] = int(self._timeout_var.get())
        except ValueError:
            cfg['timeout'] = 15
        try:
            cfg['parallel'] = int(self._parallel_var.get())
        except ValueError:
            cfg['parallel'] = 4

        cfg.setdefault('debugger', {})['engine'] = self._debugger_var.get()
        cfg.setdefault('signature', {})['strategy'] = self._strategy_var.get()
        cfg.setdefault('output', {})['mode'] = self._output_mode_var.get()

        return cfg

    # ============================================================
    # 파일 탐색기 다이얼로그
    # ============================================================

    def _browse_dir(self, var: ctk.StringVar):
        """디렉터리 선택 다이얼로그를 연다. 기존 경로가 있으면 해당 위치에서 시작."""
        initial = var.get()
        # 현재 값이 유효한 디렉터리면 그곳에서 시작, 아니면 부모 디렉터리 시도
        if initial and Path(initial).is_dir():
            initialdir = initial
        elif initial and Path(initial).parent.is_dir():
            initialdir = str(Path(initial).parent)
        else:
            initialdir = None
        path = tk.filedialog.askdirectory(title="디렉터리 선택", initialdir=initialdir)
        if path:
            var.set(path)

    def _browse_file(self, var: ctk.StringVar):
        """파일 선택 다이얼로그를 연다. 기존 경로가 있으면 해당 위치에서 시작."""
        initial = var.get()
        if initial and Path(initial).is_file():
            initialdir = str(Path(initial).parent)
        elif initial and Path(initial).is_dir():
            initialdir = initial
        elif initial and Path(initial).parent.is_dir():
            initialdir = str(Path(initial).parent)
        else:
            initialdir = None
        path = tk.filedialog.askopenfilename(
            title="실행 파일 선택",
            initialdir=initialdir,
            filetypes=[("실행 파일", "*.exe"), ("모든 파일", "*.*")])
        if path:
            var.set(path)

    # ============================================================
    # 제외 패턴 자동 감지
    # ============================================================

    def _detect_and_show_excludes(self, crash_dir: Path) -> bool:
        """
        제외 패턴 후보를 감지하고, 새 후보가 있으면 다이얼로그로 선택받는다.
        선택된 패턴은 _auto_exclude에 추가되고 config에 저장된다.

        Args:
            crash_dir: 크래시 파일 디렉터리

        Returns:
            True: 패턴이 추가됨, False: 추가 없음 (후보 없음 또는 무시/취소)
        """
        # 기존 제외 패턴 취합
        user_exclude = self._cfg.get('exclude', [])
        if not isinstance(user_exclude, list):
            user_exclude = []
        auto_exclude = self._cfg.get('_auto_exclude', [])
        if not isinstance(auto_exclude, list):
            auto_exclude = []
        existing_patterns = user_exclude + auto_exclude

        # 후보 감지
        candidates, total_files = detect_exclude_candidates(crash_dir)
        new_candidates = get_new_exclude_candidates(candidates, existing_patterns)

        if not new_candidates:
            return False

        # 다이얼로그 표시
        dialog = ExcludeCandidateDialog(self, new_candidates, total_files)
        self.wait_window(dialog)

        if dialog.selected_patterns is None or not dialog.selected_patterns:
            return False

        # 선택된 패턴을 _auto_exclude에 추가 및 저장
        auto_exclude.extend(dialog.selected_patterns)
        self._cfg['_auto_exclude'] = auto_exclude
        self._cfg['_last_crash_dir'] = str(crash_dir)
        save_config(self._config_path, self._cfg)
        self._log(f"[INFO] {len(dialog.selected_patterns)}개 제외 패턴이 추가되었습니다.")
        return True

    # ============================================================
    # 분석 제어
    # ============================================================

    def _scan_files(self):
        """크래시 파일 수를 스캔하여 표시한다. 제외 후보 감지도 함께 수행."""
        cfg = self._ui_to_config()
        crash_dir = cfg.get('crash_dir', '')
        if not crash_dir or not Path(crash_dir).is_dir():
            self._log("[ERROR] 유효한 crash_dir을 설정하세요.")
            return

        crash_dir_path = Path(crash_dir)

        # 제외 패턴 자동 감지 및 선택
        self._detect_and_show_excludes(crash_dir_path)

        # 패턴 적용 후 파일 수집 (감지에서 추가된 패턴 반영)
        exclude = self._cfg.get('exclude', []) + self._cfg.get('_auto_exclude', [])
        files = collect_crash_files(crash_dir_path, exclude)
        self._file_count_label.configure(text=f"파일: {len(files)} 개")
        self._log(f"파일 스캔 완료: {len(files)}개 발견")

    def _reset_results(self):
        """이전 분석 결과를 초기화한다. 새 분석 시작 전에 호출."""
        # 통계 라벨
        for label in self._stats_labels.values():
            label.configure(text="-")
        # 시그니처 목록
        self._sig_textbox.configure(state="normal")
        self._sig_textbox.delete("1.0", "end")
        self._sig_textbox.configure(state="disabled")
        # 경과 시간 및 결과 객체
        self._elapsed_label.configure(text="")
        self._result = None

    def _start_analysis(self):
        """분석을 시작한다. 시작 전 제외 패턴 후보를 자동 감지한다."""
        cfg = self._ui_to_config()

        errors = validate_config(cfg)
        if errors:
            for err in errors:
                self._log(f"[ERROR] {err}")
            return

        # 분석 시작 전 제외 패턴 자동 감지
        crash_dir_path = Path(cfg['crash_dir'])
        self._detect_and_show_excludes(crash_dir_path)

        # 이전 결과 초기화 및 UI 상태 변경
        self._reset_results()
        self._start_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")
        self._progress_bar.set(0)
        self._progress_label.configure(text="분석 시작 중...")

        # 출력 경로
        out_path_cfg = cfg.get('out_path', '')
        if out_path_cfg:
            out_path = Path(out_path_cfg)
        else:
            out_path = Path(cfg['crash_dir']).parent / 'DbgLogs'

        # 분석 스레드 시작
        exclude = self._cfg.get('exclude', []) + self._cfg.get('_auto_exclude', [])
        self._analyzer = CrashAnalyzer(cfg)
        self._start_time = time.time()

        self._analysis_thread = threading.Thread(
            target=self._run_analysis,
            args=(cfg, out_path, exclude),
            daemon=True,
        )
        self._analysis_thread.start()
        self._update_elapsed()

    def _run_analysis(self, cfg: dict, out_path: Path, exclude: list):
        """분석 스레드에서 실행되는 메인 로직."""
        try:
            crash_dir = Path(cfg['crash_dir'])
            result = self._analyzer.analyze(
                crash_dir=crash_dir,
                out_path=out_path,
                exclude_patterns=exclude,
                progress_callback=self._on_progress,
            )
            self._update_queue.put(('analysis_done', result))
        except Exception as e:
            self._update_queue.put(('analysis_error', str(e)))

    def _stop_analysis(self):
        """분석을 중지한다."""
        if self._analyzer:
            self._analyzer.stop()
            self._log("분석 중지 요청됨...")

    def _on_progress(self, progress: AnalysisProgress):
        """진행 콜백 (분석 스레드에서 호출됨 → 큐로 전달). 스냅샷 복사로 데이터 레이스 방지."""
        import dataclasses
        self._update_queue.put(('progress', dataclasses.replace(progress)))

    # ============================================================
    # GUI 업데이트 (메인 스레드)
    # ============================================================

    def _poll_updates(self):
        """큐에서 업데이트 메시지를 폴링한다. 개별 메시지 처리 실패 시에도 루프 유지."""
        try:
            while True:
                msg_type, data = self._update_queue.get_nowait()
                try:
                    if msg_type == 'progress':
                        self._update_progress(data)
                    elif msg_type == 'analysis_done':
                        self._on_analysis_done(data)
                    elif msg_type == 'analysis_error':
                        self._on_analysis_error(data)
                    elif msg_type == 'log':
                        self._append_log(data)
                except Exception:
                    pass  # 개별 메시지 처리 실패 시 다음 메시지 계속 처리
        except queue.Empty:
            pass
        self.after(100, self._poll_updates)

    def _update_progress(self, progress: AnalysisProgress):
        """진행 상태 UI를 업데이트한다."""
        if progress.total > 0:
            ratio = progress.completed / progress.total
            self._progress_bar.set(ratio)
            pct = int(ratio * 100)
            self._progress_label.configure(
                text=f"{progress.completed}/{progress.total} ({pct}%) "
                     f"| 크래시: {progress.crashes_found} | 타임아웃: {progress.timeouts}"
            )

    def _update_elapsed(self):
        """경과 시간을 업데이트한다."""
        if self._analysis_thread and self._analysis_thread.is_alive():
            elapsed = time.time() - self._start_time
            mins, secs = divmod(int(elapsed), 60)
            self._elapsed_label.configure(text=f"경과: {mins:02d}:{secs:02d}")
            self.after(1000, self._update_elapsed)

    def _on_analysis_done(self, result: AnalysisResult):
        """분석 완료 시 UI를 업데이트한다."""
        self._result = result
        self._start_btn.configure(state="normal")
        self._stop_btn.configure(state="disabled")
        self._progress_bar.set(1.0)
        self._progress_label.configure(text="분석 완료")

        # 통계 및 시그니처 표시
        if result.entries:
            groups = result.crash_groups
            self._stats_labels['unique'].configure(text=str(len(groups)))
            self._stats_labels['total'].configure(text=str(len(result.crash_entries)))
            self._stats_labels['timeout'].configure(text=str(len(result.timeout_entries)))
            self._stats_labels['fp'].configure(text=str(len(result.false_positive_entries)))

            self._sig_textbox.configure(state="normal")
            self._sig_textbox.delete("1.0", "end")
            sorted_groups = sorted(groups.items(), key=lambda x: len(x[1]), reverse=True)
            for sig, entries in sorted_groups[:10]:
                self._sig_textbox.insert("end", f"  {sig}  ({len(entries)} files)\n")
            self._sig_textbox.configure(state="disabled")

        elapsed = time.time() - self._start_time
        mins, secs = divmod(int(elapsed), 60)
        self._log(f"분석 완료! ({mins}분 {secs}초)")

    def _on_analysis_error(self, error_msg: str):
        """분석 에러 시 UI를 업데이트한다."""
        self._start_btn.configure(state="normal")
        self._stop_btn.configure(state="disabled")
        self._progress_label.configure(text="분석 실패")
        self._log(f"[ERROR] {error_msg}")

    # ============================================================
    # 팝업 설정 다이얼로그
    # ============================================================

    def _open_popup_config(self):
        """팝업 설정 다이얼로그를 연다."""
        from gui.popup_config_dialog import PopupConfigDialog
        dialog = PopupConfigDialog(self, self._cfg)
        self.wait_window(dialog)
        # 다이얼로그에서 "저장"을 눌렀을 때만 설정 반영
        # (취소/X 닫기 시 updated_config는 None이므로 무시)
        if hasattr(dialog, 'updated_config') and dialog.updated_config is not None:
            self._cfg['popup_handler'] = dialog.updated_config
            self._log("팝업 설정이 업데이트되었습니다.")

    # ============================================================
    # 로그
    # ============================================================

    # 로그 텍스트박스 최대 줄 수 (메모리/렌더링 성능 보호)
    _LOG_MAX_LINES = 1000

    def _log(self, message: str):
        """로그 메시지를 추가한다. 최대 줄 수 초과 시 상위 라인을 삭제한다."""
        timestamp = time.strftime("%H:%M:%S")
        self._log_textbox.insert("end", f"[{timestamp}] {message}\n")

        # 최대 줄 수 초과 시 상위 삭제
        line_count = int(self._log_textbox.index("end-1c").split(".")[0])
        if line_count > self._LOG_MAX_LINES:
            overflow = line_count - self._LOG_MAX_LINES
            self._log_textbox.delete("1.0", f"{overflow + 1}.0")

        self._log_textbox.see("end")

    def _append_log(self, message: str):
        """큐에서 받은 로그를 추가한다."""
        self._log(message)

    def _clear_log(self):
        """로그를 지운다."""
        self._log_textbox.delete("1.0", "end")

    # ============================================================
    # 윈도우 종료 처리
    # ============================================================

    def _has_unsaved_changes(self) -> bool:
        """현재 UI 값이 마지막 저장 시점과 다른지 확인한다."""
        current = self._ui_to_config()
        # 비교 대상 키 목록 (내부/자동 필드 제외)
        for key in ('crash_dir', 'exe_path', 'out_path', 'timeout', 'parallel'):
            if current.get(key) != self._saved_cfg.get(key):
                return True
        # 중첩 설정 비교
        for section, subkey in [
            ('debugger', 'engine'), ('signature', 'strategy'), ('output', 'mode')
        ]:
            if current.get(section, {}).get(subkey) != self._saved_cfg.get(section, {}).get(subkey):
                return True
        # 팝업 핸들러 설정 비교 (다이얼로그에서 변경된 경우)
        if current.get('popup_handler') != self._saved_cfg.get('popup_handler'):
            return True
        return False

    def destroy(self):
        """윈도우 종료 시 미저장 변경 확인 후 안전하게 정리한다."""
        # 미저장 변경 확인
        if self._has_unsaved_changes():
            from tkinter import messagebox
            answer = messagebox.askyesnocancel(
                "설정 변경 확인",
                "설정이 변경되었습니다. 저장하시겠습니까?",
                parent=self,
            )
            if answer is None:  # Cancel → 종료 취소
                return
            if answer:  # Yes → 저장 후 종료
                self._save_config()
            # No → 저장하지 않고 종료

        # 분석 중이면 중지 요청 후 스레드 종료 대기
        if self._analyzer:
            self._analyzer.stop()
        if self._analysis_thread and self._analysis_thread.is_alive():
            self._analysis_thread.join(timeout=5.0)
        super().destroy()

    # ============================================================
    # 유틸리티
    # ============================================================

    def _open_output_dir(self):
        """출력 디렉터리를 탐색기로 연다."""
        out_path = self._out_path_var.get()
        if not out_path:
            crash_dir = self._crash_dir_var.get()
            if crash_dir:
                out_path = str(Path(crash_dir).parent / 'DbgLogs')

        if out_path and Path(out_path).is_dir():
            os.startfile(out_path)
        else:
            self._log("[WARN] 출력 디렉터리가 존재하지 않습니다.")
