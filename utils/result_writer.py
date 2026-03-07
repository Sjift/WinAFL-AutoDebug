"""
결과 출력 모듈 (result_writer.py)

크래시 분석 결과를 다양한 형식으로 출력한다.
- CrashSummary.md: 마크다운 통합 보고서 (통계, 크래시, 타임아웃, FP 전부 포함)
- AnalysisReport.html: 오프라인 HTML 시각 보고서 (다크 테마, 접기/펼치기)
- 시그니처별 폴더 분류: real_crashes/, timeouts/, false_positives/
"""

import time
import shutil
from html import escape as html_escape
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field

from core.signature_extractor import get_crash_folder_name


@dataclass
class AnalysisEntry:
    """단일 크래시 분석 결과 엔트리"""
    crash_file: Path               # 원본 크래시 파일 경로
    log_file: Optional[Path]       # 디버그 로그 파일 경로
    is_crash: bool = False         # 진짜 크래시 여부
    signature: str = 'UNKNOWN'     # 크래시 시그니처 (primary: g; 이전 AV 덤프)
    faulting_instruction: str = '' # g; 이전 AV 덤프의 어셈블리 명령어
    deferred_signature: str = 'UNKNOWN'  # secondary: g; 이후 kn frame 00
    signature_mismatch: bool = False     # g; 이전 vs g; 이후 크래시 지점 불일치
    exception_code: str = ''       # 예외 코드 (예: "c0000005")
    exception_type: str = ''       # 예외 종류 (예: "Access violation")
    timeout: bool = False          # 타임아웃 여부
    error: Optional[str] = None    # 에러 메시지


@dataclass
class AnalysisResult:
    """전체 분석 결과"""
    entries: list = field(default_factory=list)  # AnalysisEntry 리스트
    out_path: Optional[Path] = None              # 출력 디렉터리

    @property
    def crash_entries(self) -> list:
        """진짜 크래시인 엔트리를 반환한다."""
        return [e for e in self.entries if e.is_crash]

    @property
    def false_positive_entries(self) -> list:
        """false positive (재현 안 됨) 엔트리를 반환한다."""
        return [e for e in self.entries if not e.is_crash and not e.timeout]

    @property
    def timeout_entries(self) -> list:
        """타임아웃이면서 크래시 정보가 없는 엔트리를 반환한다."""
        return [e for e in self.entries if e.timeout and not e.is_crash]

    @property
    def crash_groups(self) -> dict:
        """시그니처별로 크래시를 그룹화한다."""
        groups = {}
        for entry in self.crash_entries:
            groups.setdefault(entry.signature, []).append(entry)
        return groups


# ============================================================
# CrashSummary.md — 마크다운 통합 보고서
# ============================================================

def write_crash_summary_md(result: AnalysisResult, out_path: Path):
    """마크다운 통합 보고서(CrashSummary.md)를 생성한다."""
    summary_path = out_path / 'CrashSummary.md'
    groups = result.crash_groups
    total = len(result.entries)
    crash_count = len(result.crash_entries)
    timeout_count = len(result.timeout_entries)
    fp_count = len(result.false_positive_entries)

    # TIMEOUT으로 시작하는 시그니처 제외한 실제 크래시 유형 수
    crash_types = len([s for s in groups.keys() if not s.startswith('TIMEOUT')])

    def pct(n):
        return f"{n * 100 / total:.1f}%" if total > 0 else "0.0%"

    with summary_path.open('w', encoding='utf-8') as f:
        # 헤더 및 통계 테이블
        f.write("# AutoDebug v3 - 분석 결과 보고서\n\n")
        f.write(f"- **분석 일시**: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"- **총 분석 파일**: {total}개\n\n")
        f.write("## 통계\n\n")
        f.write("| 분류 | 파일 수 | 비율 |\n")
        f.write("|------|------:|-----:|\n")
        f.write(f"| 진짜 크래시 | {crash_count} ({crash_types}개 유형) | {pct(crash_count)} |\n")
        f.write(f"| 타임아웃 | {timeout_count} | {pct(timeout_count)} |\n")
        f.write(f"| False Positive | {fp_count} | {pct(fp_count)} |\n\n")
        f.write("---\n\n")

        # 크래시 분류 섹션
        # TIMEOUT 제외 그룹을 파일 수 내림차순 정렬
        normal_groups = [(s, e) for s, e in groups.items() if not s.startswith('TIMEOUT')]
        sorted_groups = sorted(normal_groups, key=lambda x: len(x[1]), reverse=True)

        if sorted_groups:
            f.write(f"## 크래시 분류 ({crash_types}개 유형, {crash_count}개 파일)\n\n")

            for sig, entries in sorted_groups:
                # 마크다운 특수문자 이스케이프 (! _ 등)
                sig_escaped = sig.replace('!', '\\!').replace('_', '\\_')
                f.write(f"### {sig_escaped} — {len(entries)} files\n\n")

                # 예외 종류 (그룹 내 예외 코드 집계)
                exc_counts = {}
                for e in entries:
                    if e.exception_code:
                        label = f"{e.exception_type} ({e.exception_code})" if e.exception_type else e.exception_code
                        exc_counts[label] = exc_counts.get(label, 0) + 1
                if exc_counts:
                    exc_parts = [f"{label}: {cnt}개" if len(exc_counts) > 1 else label
                                 for label, cnt in exc_counts.items()]
                    f.write(f"> Exception: {', '.join(exc_parts)}\n")

                # 어셈블리 명령어
                first_asm = next(
                    (e.faulting_instruction for e in entries if e.faulting_instruction),
                    ''
                )
                if first_asm:
                    f.write(f"> Faulting: `{first_asm}`\n")

                f.write("\n")

                # 파일 테이블
                f.write("| # | 파일명 | 비고 |\n")
                f.write("|---|--------|------|\n")
                for i, entry in enumerate(entries, 1):
                    name = entry.crash_file.name
                    notes = []
                    if entry.timeout:
                        notes.append("TIMEOUT")
                    if entry.signature_mismatch:
                        deferred_escaped = entry.deferred_signature.replace('!', '\\!').replace('_', '\\_')
                        notes.append(f"⚠ 불일치: {deferred_escaped}")
                    note_str = ", ".join(notes)
                    f.write(f"| {i} | {name} | {note_str} |\n")
                f.write("\n")

            f.write("---\n\n")

        # 타임아웃 섹션
        timeout_entries = result.timeout_entries
        if timeout_entries:
            f.write(f"## 타임아웃 — 크래시 미발생 ({timeout_count}개 파일)\n\n")
            f.write("> 디버깅 시간 초과 후 크래시(예외)가 감지되지 않은 파일\n\n")
            f.write("| # | 파일명 |\n")
            f.write("|---|--------|\n")
            for i, entry in enumerate(sorted(timeout_entries, key=lambda e: e.crash_file.name), 1):
                f.write(f"| {i} | {entry.crash_file.name} |\n")
            f.write("\n---\n\n")

        # False Positive 섹션
        fp_entries = result.false_positive_entries
        if fp_entries:
            f.write(f"## False Positive — 재현 안 됨 ({fp_count}개 파일)\n\n")
            f.write("> 디버깅 완료 후 크래시가 재현되지 않은 파일\n\n")
            f.write("| # | 파일명 |\n")
            f.write("|---|--------|\n")
            for i, entry in enumerate(sorted(fp_entries, key=lambda e: e.crash_file.name), 1):
                f.write(f"| {i} | {entry.crash_file.name} |\n")
            f.write("\n")

    print(f"[INFO] CrashSummary.md 생성됨: {summary_path}")
    print(f"[INFO] 분류된 크래시: {crash_types}개 유형, 총 {crash_count}개 파일")
    if timeout_count > 0:
        print(f"[INFO] 타임아웃 (크래시 미발생): {timeout_count}개")
    if fp_count > 0:
        print(f"[INFO] False Positive: {fp_count}개")


# ============================================================
# AnalysisReport.html — 오프라인 HTML 시각 보고서
# ============================================================

# 임베딩 CSS (다크 테마 대시보드 스타일)
_HTML_CSS = """
:root {
    --bg-primary: #1a1b2e;
    --bg-secondary: #232440;
    --bg-card: #2a2b4a;
    --bg-table-row: #2f3052;
    --bg-table-hover: #383964;
    --text-primary: #e8e8f0;
    --text-secondary: #a0a0b8;
    --text-muted: #707088;
    --border: #3a3b5a;
    --accent-red: #ff6b6b;
    --accent-red-bg: rgba(255, 107, 107, 0.15);
    --accent-yellow: #ffd93d;
    --accent-yellow-bg: rgba(255, 217, 61, 0.15);
    --accent-green: #6bcb77;
    --accent-green-bg: rgba(107, 203, 119, 0.15);
    --accent-blue: #4d96ff;
    --accent-blue-bg: rgba(77, 150, 255, 0.15);
    --radius: 8px;
    --shadow: 0 2px 8px rgba(0,0,0,0.3);
}

* { margin: 0; padding: 0; box-sizing: border-box; }

body {
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.6;
    padding: 24px;
    max-width: 1200px;
    margin: 0 auto;
}

/* 헤더 */
.header {
    text-align: center;
    padding: 24px 0 16px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 24px;
}
.header h1 {
    font-size: 1.5rem;
    font-weight: 600;
    color: var(--text-primary);
    margin-bottom: 8px;
}
.header .meta {
    font-size: 0.85rem;
    color: var(--text-secondary);
}

/* 통계 카드 */
.stats {
    display: flex;
    gap: 16px;
    margin-bottom: 24px;
    flex-wrap: wrap;
}
.stat-card {
    flex: 1;
    min-width: 180px;
    background: var(--bg-card);
    border-radius: var(--radius);
    padding: 20px;
    box-shadow: var(--shadow);
    border-left: 4px solid transparent;
}
.stat-card.crash { border-left-color: var(--accent-red); background: var(--accent-red-bg); }
.stat-card.timeout { border-left-color: var(--accent-yellow); background: var(--accent-yellow-bg); }
.stat-card.fp { border-left-color: var(--accent-green); background: var(--accent-green-bg); }
.stat-card .label {
    font-size: 0.8rem;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 4px;
}
.stat-card .value {
    font-size: 1.8rem;
    font-weight: 700;
}
.stat-card.crash .value { color: var(--accent-red); }
.stat-card.timeout .value { color: var(--accent-yellow); }
.stat-card.fp .value { color: var(--accent-green); }
.stat-card .sub {
    font-size: 0.8rem;
    color: var(--text-muted);
    margin-top: 2px;
}

/* 섹션 */
.section {
    background: var(--bg-secondary);
    border-radius: var(--radius);
    margin-bottom: 16px;
    box-shadow: var(--shadow);
    overflow: hidden;
}
.section-title {
    font-size: 1rem;
    font-weight: 600;
    padding: 14px 20px;
    background: var(--bg-card);
    border-bottom: 1px solid var(--border);
}

/* details/summary 접기/펼치기 */
details {
    border-bottom: 1px solid var(--border);
}
details:last-child { border-bottom: none; }
summary {
    padding: 12px 20px;
    cursor: pointer;
    font-weight: 500;
    display: flex;
    align-items: center;
    gap: 8px;
    user-select: none;
    transition: background 0.15s;
}
summary:hover { background: var(--bg-table-hover); }
summary::marker { color: var(--accent-blue); }
.sig-name { flex: 1; font-family: 'Consolas', 'Courier New', monospace; font-size: 0.9rem; }
.count-badge {
    background: var(--accent-blue-bg);
    color: var(--accent-blue);
    padding: 2px 10px;
    border-radius: 12px;
    font-size: 0.8rem;
    font-weight: 600;
}
.faulting {
    padding: 8px 20px;
    font-size: 0.82rem;
    color: var(--text-secondary);
    background: var(--bg-primary);
    font-family: 'Consolas', 'Courier New', monospace;
}

/* 테이블 */
table {
    width: 100%;
    border-collapse: collapse;
}
th {
    background: var(--bg-card);
    padding: 8px 16px;
    text-align: left;
    font-size: 0.8rem;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    font-weight: 600;
}
td {
    padding: 8px 16px;
    font-size: 0.85rem;
    border-top: 1px solid var(--border);
}
tr:nth-child(even) td { background: var(--bg-table-row); }
tr:hover td { background: var(--bg-table-hover); }
td.mono { font-family: 'Consolas', 'Courier New', monospace; font-size: 0.82rem; }

/* 배지 */
.badge {
    display: inline-block;
    padding: 1px 8px;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
}
.badge-timeout { background: var(--accent-yellow-bg); color: var(--accent-yellow); }
.badge-warn { background: var(--accent-red-bg); color: var(--accent-red); }

/* 심플 리스트 (타임아웃/FP) */
.file-list {
    padding: 12px 20px;
}
.file-list table { margin: 0; }

/* 푸터 */
.footer {
    text-align: center;
    padding: 16px;
    color: var(--text-muted);
    font-size: 0.75rem;
}
"""


def _build_html_crash_section(groups: dict) -> str:
    """크래시 시그니처 섹션 HTML을 생성한다."""
    normal_groups = [(s, e) for s, e in groups.items() if not s.startswith('TIMEOUT')]
    sorted_groups = sorted(normal_groups, key=lambda x: len(x[1]), reverse=True)

    if not sorted_groups:
        return ""

    crash_count = sum(len(e) for _, e in sorted_groups)
    html = f'<div class="section">\n'
    html += f'<div class="section-title">크래시 분류 — {len(sorted_groups)}개 유형, {crash_count}개 파일</div>\n'

    for sig, entries in sorted_groups:
        sig_safe = html_escape(sig)
        first_asm = next(
            (e.faulting_instruction for e in entries if e.faulting_instruction), ''
        )

        # 예외 종류 집계
        exc_counts = {}
        for e in entries:
            if e.exception_code:
                label = f"{e.exception_type} ({e.exception_code})" if e.exception_type else e.exception_code
                exc_counts[label] = exc_counts.get(label, 0) + 1

        html += '<details>\n'
        html += f'<summary><span class="sig-name">{sig_safe}</span>'
        html += f'<span class="count-badge">{len(entries)} files</span></summary>\n'

        if exc_counts:
            exc_parts = [f"{html_escape(label)}: {cnt}개" if len(exc_counts) > 1
                         else html_escape(label) for label, cnt in exc_counts.items()]
            html += f'<div class="faulting">Exception: {", ".join(exc_parts)}</div>\n'

        if first_asm:
            html += f'<div class="faulting">Faulting: {html_escape(first_asm)}</div>\n'

        html += '<table><tr><th>#</th><th>파일명</th><th>비고</th></tr>\n'
        for i, entry in enumerate(entries, 1):
            name = html_escape(entry.crash_file.name)
            notes = []
            if entry.timeout:
                notes.append('<span class="badge badge-timeout">TIMEOUT</span>')
            if entry.signature_mismatch:
                deferred = html_escape(entry.deferred_signature)
                notes.append(f'<span class="badge badge-warn">⚠ 불일치: {deferred}</span>')
            note_html = " ".join(notes)
            html += f'<tr><td>{i}</td><td class="mono">{name}</td><td>{note_html}</td></tr>\n'
        html += '</table>\n</details>\n'

    html += '</div>\n'
    return html


def _build_html_list_section(title: str, entries: list) -> str:
    """타임아웃/FP 섹션 HTML을 생성한다."""
    if not entries:
        return ""
    sorted_entries = sorted(entries, key=lambda e: e.crash_file.name)

    html = f'<div class="section">\n'
    html += f'<details>\n'
    html += f'<summary><span class="sig-name">{html_escape(title)}</span>'
    html += f'<span class="count-badge">{len(entries)} files</span></summary>\n'
    html += '<div class="file-list"><table><tr><th>#</th><th>파일명</th></tr>\n'
    for i, entry in enumerate(sorted_entries, 1):
        name = html_escape(entry.crash_file.name)
        html += f'<tr><td>{i}</td><td class="mono">{name}</td></tr>\n'
    html += '</table></div>\n</details>\n</div>\n'
    return html


def write_html_report(result: AnalysisResult, out_path: Path):
    """오프라인 HTML 시각 보고서(AnalysisReport.html)를 생성한다."""
    report_path = out_path / 'AnalysisReport.html'
    total = len(result.entries)
    crash_count = len(result.crash_entries)
    timeout_count = len(result.timeout_entries)
    fp_count = len(result.false_positive_entries)
    groups = result.crash_groups
    crash_types = len([s for s in groups.keys() if not s.startswith('TIMEOUT')])

    def pct(n):
        return f"{n * 100 / total:.1f}%" if total > 0 else "0.0%"

    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')

    # HTML 조립
    html = f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AutoDebug v3 - 분석 결과</title>
<style>{_HTML_CSS}</style>
</head>
<body>

<div class="header">
    <h1>AutoDebug v3 - 분석 결과 보고서</h1>
    <div class="meta">{timestamp} | 총 {total}개 파일 분석</div>
</div>

<div class="stats">
    <div class="stat-card crash">
        <div class="label">진짜 크래시</div>
        <div class="value">{crash_count}</div>
        <div class="sub">{crash_types}개 유형 | {pct(crash_count)}</div>
    </div>
    <div class="stat-card timeout">
        <div class="label">타임아웃</div>
        <div class="value">{timeout_count}</div>
        <div class="sub">{pct(timeout_count)}</div>
    </div>
    <div class="stat-card fp">
        <div class="label">False Positive</div>
        <div class="value">{fp_count}</div>
        <div class="sub">{pct(fp_count)}</div>
    </div>
</div>

{_build_html_crash_section(groups)}
{_build_html_list_section("타임아웃 — 크래시 미발생", result.timeout_entries)}
{_build_html_list_section("False Positive — 재현 안 됨", result.false_positive_entries)}

<div class="footer">Generated by AutoDebug v3</div>

</body>
</html>"""

    report_path.write_text(html, encoding='utf-8')
    print(f"[INFO] AnalysisReport.html 생성됨: {report_path}")


# ============================================================
# 폴더 분류
# ============================================================

def copy_crashes_to_folders(result: AnalysisResult, out_path: Path):
    """시그니처별 폴더를 생성하고 크래시 파일 + 로그를 복사한다."""
    real_dir = out_path / 'real_crashes'
    timeout_dir = out_path / 'timeouts'
    false_dir = out_path / 'false_positives'
    real_dir.mkdir(parents=True, exist_ok=True)
    timeout_dir.mkdir(parents=True, exist_ok=True)
    false_dir.mkdir(parents=True, exist_ok=True)

    for entry in result.entries:
        if entry.is_crash:
            folder_name = get_crash_folder_name(entry.signature)
            target_dir = real_dir / folder_name
            target_dir.mkdir(parents=True, exist_ok=True)

            try:
                shutil.copy2(entry.crash_file, target_dir / entry.crash_file.name)
            except OSError as e:
                print(f"[WARN] 크래시 파일 복사 실패: {entry.crash_file.name} - {e}")

            if entry.log_file and entry.log_file.exists():
                log_dest = target_dir / f"{entry.crash_file.name}.txt"
                try:
                    shutil.copy2(entry.log_file, log_dest)
                except OSError as e:
                    print(f"[WARN] 로그 파일 복사 실패: {log_dest.name} - {e}")

        elif entry.timeout:
            try:
                shutil.copy2(entry.crash_file, timeout_dir / entry.crash_file.name)
            except OSError as e:
                print(f"[WARN] 타임아웃 파일 복사 실패: {entry.crash_file.name} - {e}")

        else:
            try:
                shutil.copy2(entry.crash_file, false_dir / entry.crash_file.name)
            except OSError as e:
                print(f"[WARN] false positive 복사 실패: {entry.crash_file.name} - {e}")


# ============================================================
# 통합 출력 함수
# ============================================================

def write_results(result: AnalysisResult, out_path: Path, mode: str = 'both'):
    """설정에 따라 적절한 출력 방식으로 결과를 저장한다."""
    out_path.mkdir(parents=True, exist_ok=True)

    if mode in ('summary', 'both'):
        write_crash_summary_md(result, out_path)
        write_html_report(result, out_path)

    if mode in ('folders', 'both'):
        copy_crashes_to_folders(result, out_path)
