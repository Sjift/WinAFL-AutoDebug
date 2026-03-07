"""
팝업 설정 다이얼로그 (popup_config_dialog.py)

팝업 타겟을 추가/수정/삭제할 수 있는 다이얼로그.
테스트 모드로 현재 열린 윈도우 중 매칭되는 것을 확인할 수 있다.
"""

import customtkinter as ctk
from typing import Optional


class PopupConfigDialog(ctk.CTkToplevel):
    """팝업 핸들러 설정 다이얼로그"""

    def __init__(self, parent, cfg: dict):
        super().__init__(parent)

        self.title("팝업 핸들러 설정")
        self.geometry("600x500")
        self.transient(parent)
        self.grab_set()

        popup_cfg = cfg.get('popup_handler', {})
        self._enabled = popup_cfg.get('enabled', False)
        self._scan_interval = popup_cfg.get('scan_interval', 0.1)
        self._targets = list(popup_cfg.get('targets', []))
        self.updated_config = None

        self._build_ui()
        self._refresh_target_list()

    def _build_ui(self):
        """UI를 구성한다."""
        # 활성화 토글
        top_frame = ctk.CTkFrame(self)
        top_frame.pack(fill="x", padx=10, pady=5)

        self._enabled_var = ctk.BooleanVar(value=self._enabled)
        ctk.CTkSwitch(top_frame, text="팝업 핸들러 활성화",
                      variable=self._enabled_var).pack(side="left", padx=10)

        ctk.CTkLabel(top_frame, text="스캔 주기:").pack(side="left", padx=(20, 5))
        self._interval_var = ctk.StringVar(value=str(self._scan_interval))
        ctk.CTkEntry(top_frame, textvariable=self._interval_var, width=50).pack(side="left")
        ctk.CTkLabel(top_frame, text="초").pack(side="left", padx=5)

        # 타겟 리스트
        list_frame = ctk.CTkFrame(self)
        list_frame.pack(fill="both", expand=True, padx=10, pady=5)

        ctk.CTkLabel(list_frame, text="팝업 타겟 목록", font=("", 13, "bold")).pack(anchor="w", padx=10, pady=5)

        self._target_textbox = ctk.CTkTextbox(list_frame, height=200, state="disabled")
        self._target_textbox.pack(fill="both", expand=True, padx=10, pady=5)

        # 버튼들
        btn_frame = ctk.CTkFrame(list_frame, fg_color="transparent")
        btn_frame.pack(fill="x", padx=10, pady=5)

        ctk.CTkButton(btn_frame, text="추가", width=80, command=self._add_target).pack(side="left", padx=2)
        ctk.CTkButton(btn_frame, text="삭제(마지막)", width=100, command=self._remove_last).pack(side="left", padx=2)
        ctk.CTkButton(btn_frame, text="전체 삭제", width=80,
                      fg_color="#dc3545", hover_color="#c82333",
                      command=self._clear_all).pack(side="left", padx=2)

        # 추가 입력 영역
        add_frame = ctk.CTkFrame(self)
        add_frame.pack(fill="x", padx=10, pady=5)

        ctk.CTkLabel(add_frame, text="새 타겟", font=("", 13, "bold")).pack(anchor="w", padx=10, pady=(5, 2))

        row1 = ctk.CTkFrame(add_frame, fg_color="transparent")
        row1.pack(fill="x", padx=10, pady=2)
        ctk.CTkLabel(row1, text="제목 패턴:", width=80, anchor="w").pack(side="left")
        self._new_pattern_var = ctk.StringVar()
        ctk.CTkEntry(row1, textvariable=self._new_pattern_var, width=300).pack(side="left", padx=5)

        row2 = ctk.CTkFrame(add_frame, fg_color="transparent")
        row2.pack(fill="x", padx=10, pady=2)
        ctk.CTkLabel(row2, text="최대 크기:", width=80, anchor="w").pack(side="left")
        self._new_width_var = ctk.StringVar(value="600")
        ctk.CTkEntry(row2, textvariable=self._new_width_var, width=60).pack(side="left", padx=2)
        ctk.CTkLabel(row2, text="x").pack(side="left")
        self._new_height_var = ctk.StringVar(value="400")
        ctk.CTkEntry(row2, textvariable=self._new_height_var, width=60).pack(side="left", padx=2)

        ctk.CTkLabel(row2, text="액션:").pack(side="left", padx=(15, 5))
        self._new_action_var = ctk.StringVar(value="close")
        ctk.CTkComboBox(row2, variable=self._new_action_var,
                        values=["close", "kill"], width=80, state="readonly").pack(side="left")

        self._new_regex_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(row2, text="정규식", variable=self._new_regex_var,
                        width=70).pack(side="left", padx=(15, 0))

        # 하단 버튼
        bottom = ctk.CTkFrame(self, fg_color="transparent")
        bottom.pack(fill="x", padx=10, pady=10)

        ctk.CTkButton(bottom, text="저장", width=100,
                      fg_color="#28a745", hover_color="#218838",
                      command=self._save).pack(side="right", padx=5)
        ctk.CTkButton(bottom, text="취소", width=100,
                      command=self.destroy).pack(side="right", padx=5)

    def _refresh_target_list(self):
        """타겟 리스트를 새로고침한다."""
        self._target_textbox.configure(state="normal")
        self._target_textbox.delete("1.0", "end")

        if not self._targets:
            self._target_textbox.insert("end", "(타겟 없음)")
        else:
            for i, t in enumerate(self._targets, 1):
                pattern = t.get('title_pattern', '')
                w = t.get('max_width', 9999)
                h = t.get('max_height', 9999)
                action = t.get('action', 'close')
                use_regex = t.get('use_regex', False)
                size_str = f"{w}x{h}" if w < 9999 or h < 9999 else "제한없음"
                regex_str = " [정규식]" if use_regex else ""
                self._target_textbox.insert(
                    "end", f"  [{i}] \"{pattern}\"{regex_str} | 크기: {size_str} | 액션: {action}\n"
                )

        self._target_textbox.configure(state="disabled")

    def _add_target(self):
        """새 타겟을 추가한다."""
        pattern = self._new_pattern_var.get().strip()
        if not pattern:
            return

        try:
            max_w = int(self._new_width_var.get())
        except ValueError:
            max_w = 9999
        try:
            max_h = int(self._new_height_var.get())
        except ValueError:
            max_h = 9999

        self._targets.append({
            'title_pattern': pattern,
            'max_width': max_w,
            'max_height': max_h,
            'action': self._new_action_var.get(),
            'use_regex': self._new_regex_var.get(),
        })

        self._new_pattern_var.set('')
        self._refresh_target_list()

    def _remove_last(self):
        """마지막 타겟을 삭제한다."""
        if self._targets:
            self._targets.pop()
            self._refresh_target_list()

    def _clear_all(self):
        """모든 타겟을 삭제한다."""
        self._targets.clear()
        self._refresh_target_list()

    def _save(self):
        """설정을 저장하고 다이얼로그를 닫는다."""
        try:
            interval = float(self._interval_var.get())
        except ValueError:
            interval = 0.1

        self.updated_config = {
            'enabled': self._enabled_var.get(),
            'scan_interval': interval,
            'targets': self._targets,
        }
        self.destroy()
