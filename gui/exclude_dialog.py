"""
제외 패턴 후보 선택 다이얼로그 (exclude_dialog.py)

자동 감지된 비크래시 파일 제외 후보를 체크박스로 표시하고,
사용자가 선택한 패턴을 반환한다.
"""

import customtkinter as ctk


class ExcludeCandidateDialog(ctk.CTkToplevel):
    """
    제외 패턴 후보 선택 다이얼로그.

    detect_exclude_candidates() + get_new_exclude_candidates()가 반환한
    새로운 후보 항목을 체크박스로 표시한다.
    사용자가 선택 후 "적용"을 누르면 selected_patterns에 결과가 저장된다.
    """

    # 후보 타입별 한국어 라벨
    _TYPE_LABELS = {'file': '파일', 'ext': '확장자', 'folder': '폴더'}

    def __init__(self, parent, candidates: list, total_files: int = 0):
        """
        Args:
            parent: 부모 윈도우
            candidates: [(pattern, count, type), ...] 새로운 제외 후보 리스트
            total_files: 전체 스캔 파일 수 (정보 표시용)
        """
        super().__init__(parent)

        self.title("제외 패턴 감지")
        self.geometry("500x400")
        self.transient(parent)
        self.grab_set()

        self._candidates = candidates
        self._total_files = total_files
        self.selected_patterns = None  # None=취소, []=빈 선택, [...]= 선택된 패턴

        self._check_vars = []  # BooleanVar 리스트

        self._build_ui()

    def _build_ui(self):
        """UI를 구성한다."""
        # 안내 메시지
        info_text = "비크래시 파일로 추정되는 패턴이 감지되었습니다."
        if self._total_files > 0:
            info_text += f"\n(전체 파일: {self._total_files}개)"
        ctk.CTkLabel(self, text=info_text, justify="left").pack(
            anchor="w", padx=15, pady=(10, 5))

        # 전체 선택/해제 버튼
        select_frame = ctk.CTkFrame(self, fg_color="transparent")
        select_frame.pack(fill="x", padx=15, pady=(0, 5))
        ctk.CTkButton(select_frame, text="전체 선택", width=80,
                      command=self._select_all).pack(side="left", padx=2)
        ctk.CTkButton(select_frame, text="전체 해제", width=80,
                      command=self._deselect_all).pack(side="left", padx=2)

        # 스크롤 가능한 체크박스 영역
        scroll_frame = ctk.CTkScrollableFrame(self, height=220)
        scroll_frame.pack(fill="both", expand=True, padx=15, pady=5)

        for pattern, count, ptype in self._candidates:
            var = ctk.BooleanVar(value=True)  # 기본 선택
            self._check_vars.append(var)

            type_label = self._TYPE_LABELS.get(ptype, ptype)
            if count > 0:
                text = f"{pattern}  ({type_label}, {count}개)"
            else:
                text = f"{pattern}  ({type_label})"

            ctk.CTkCheckBox(scroll_frame, text=text, variable=var).pack(
                anchor="w", padx=5, pady=2)

        # 하단 버튼
        bottom = ctk.CTkFrame(self, fg_color="transparent")
        bottom.pack(fill="x", padx=15, pady=10)

        ctk.CTkButton(bottom, text="적용", width=100,
                      fg_color="#28a745", hover_color="#218838",
                      command=self._apply).pack(side="right", padx=5)
        ctk.CTkButton(bottom, text="무시", width=100,
                      command=self._skip).pack(side="right", padx=5)

    def _select_all(self):
        """모든 체크박스를 선택한다."""
        for var in self._check_vars:
            var.set(True)

    def _deselect_all(self):
        """모든 체크박스를 해제한다."""
        for var in self._check_vars:
            var.set(False)

    def _apply(self):
        """선택된 패턴을 저장하고 다이얼로그를 닫는다."""
        self.selected_patterns = []
        for i, var in enumerate(self._check_vars):
            if var.get():
                self.selected_patterns.append(self._candidates[i][0])
        self.destroy()

    def _skip(self):
        """아무것도 선택하지 않고 다이얼로그를 닫는다."""
        self.selected_patterns = []
        self.destroy()
