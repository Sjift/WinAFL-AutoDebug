# WinAFL-AutoDebug

Automated crash triage tool for [WinAFL](https://github.com/googleprojectzero/winafl) fuzzing results.
Replays crash files with CDB/WinDbgX, verifies reproducibility, extracts crash signatures (`module!function+offset`), and groups duplicates.

## Features

- **Automated Debugging** — CDB 또는 WinDbgX로 크래시 파일을 자동 재현하고 디버거 출력을 수집
- **Crash Classification** — 진짜 크래시 / False Positive / 타임아웃 3분류 자동 판별
- **Signature Extraction** — `module!function+offset` 기반 크래시 지점 추출 및 동일 시그니처 그룹화
- **Exception Analysis** — ExceptionCode(Access Violation, Divide-by-zero, C++ throw 등) 자동 추출 및 보고서 표시
- **Parallel Processing** — ThreadPoolExecutor 기반 병렬 디버깅 (기본 4개 동시)
- **Popup Handler** — 디버깅 중 발생하는 에러 팝업 자동 닫기 (정규식 매칭, 3단계 닫기 전략)
- **Dual Reports** — Markdown (`CrashSummary.md`) + HTML (`AnalysisReport.html`) 보고서 생성
- **GUI Dashboard** — CustomTkinter 기반 대시보드 (설정, 실행, 결과 확인 통합)

## Requirements

- **OS**: Windows 10/11 (디버거 실행 환경, VM 권장)
- **Python**: 3.10+
- **Debugger**: [CDB](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/) (Windows SDK 포함) 또는 WinDbgX

## Installation

```bash
git clone https://github.com/<your-username>/WinAFL-AutoDebug.git
cd WinAFL-AutoDebug
pip install -r requirements.txt
```

### Dependencies

| 패키지 | 용도 | 필수 |
|--------|------|------|
| PyYAML | config.yaml 설정 관리 | O |
| customtkinter | GUI 대시보드 | O (GUI 사용 시) |
| pywinauto | 팝업 자동 닫기 | X (팝업 핸들러 사용 시만) |

## Usage

### GUI Mode

```bash
python main_gui.py
```

또는 `bin/AutoDebug.exe` 실행 (Python 설치 불필요)

### CLI Mode

```bash
# 대화형 실행 (설정 확인 후 진행)
python main.py

# 배치 모드 (프롬프트 없이 즉시 실행)
python main.py --batch

# 커스텀 설정 파일
python main.py --config my_config.yaml

# 자동 제외 패턴 초기화
python main.py --reset-exclude
```

## Configuration

첫 실행 시 `config.yaml`이 자동 생성됩니다. GUI에서도 모든 설정을 변경할 수 있습니다.

```yaml
crash_dir: "C:/fuzzing/crashes"     # 크래시 파일 디렉터리
exe_path: "C:/target/app.exe"       # 디버깅 대상 실행 파일
out_path: ""                        # 출력 경로 (빈 값 → crash_dir 상위에 DbgLogs)
timeout: 15                         # 프로세스 타임아웃 (초)
parallel: 4                         # 병렬 디버거 수

debugger:
  engine: "cdb"                     # "cdb" 또는 "windbgx"
  cdb_path: ""                      # CDB 경로 (빈 값 → 자동 탐색)

signature:
  strategy: "first"                 # kn fallback 전략: "first" (frame 00) / "last" (최하단)

output:
  mode: "both"                      # "summary" / "folders" / "both"
  copy_crashes: true                # 크래시 파일을 시그니처 폴더에 복사

popup_handler:
  enabled: false                    # 팝업 핸들러 활성화
  scan_interval: 0.1                # 스캔 주기 (초)
  targets: []                       # [{title_pattern, max_width, max_height, action}]

exclude: []                         # gitignore 스타일 제외 패턴
```

## Output

```
DbgLogs/
├── logs/                           # 디버거 원본 로그
├── CrashSummary.md                 # Markdown 보고서
├── AnalysisReport.html             # HTML 보고서 (다크 테마)
├── real_crashes/                   # 시그니처별 폴더 분류
│   ├── ModuleA_FuncX+0x1234/
│   │   ├── crash_001.hwp           # 크래시 파일 복사본
│   │   └── crash_001.hwp.txt       # 디버거 로그
│   └── ModuleB_FuncY+0xABCD/
├── timeouts/                       # 타임아웃 파일
└── false_positives/                # False Positive 파일
```

### CrashSummary.md Example

```markdown
## 크래시 분류 (3개 유형, 25개 파일)

### HwpApp!HncGetEqEditPluginProxy+0x463d7 — 16 files

> Exception: Integer divide-by-zero (c0000094)
> Faulting: `idiv eax,ecx`

| # | 파일명 | 비고 |
|---|--------|------|
| 1 | id_000067_00_EXCEPTION_INT_DIVIDE_BY_ZERO |  |
| 2 | id_000072_00_EXCEPTION_INT_DIVIDE_BY_ZERO |  |
...
```

## Architecture

```
main.py / main_gui.py              # 진입점 (CLI / GUI)
core/
├── config_manager.py              # YAML 설정 로드/저장/검증/마이그레이션
├── crash_analyzer.py              # 분석 오케스트레이션 (ThreadPoolExecutor)
├── debugger_engine.py             # CDB/WinDbgX 엔진 추상화 (Strategy 패턴)
└── signature_extractor.py         # 시그니처 추출 + 크래시 판별
gui/
├── main_window.py                 # 메인 대시보드 (CustomTkinter)
├── popup_config_dialog.py         # 팝업 타겟 관리 다이얼로그
└── exclude_dialog.py              # 제외 패턴 선택 다이얼로그
utils/
├── file_collector.py              # 파일 수집 + gitignore 제외 패턴
├── popup_handler.py               # 팝업 자동 닫기 (데몬 스레드)
└── result_writer.py               # 보고서 생성 (Markdown + HTML + 폴더 분류)
```

### Crash Detection (3-stage)

```
1. "##########" + "total:" 존재 → False Positive (WinAFL 통계 출력)
2. FAILURE_BUCKET_ID 존재     → Real Crash (!analyze -v 완료)
3. ExceptionCode 'c' prefix   → Real Crash (타임아웃으로 !analyze 미완료 시 백업)
4. 위 조건 모두 불충족         → False Positive
```

### Signature Extraction Priority

```
1. g; 이전 AV 덤프        — first-chance exception의 module!function+offset
2. ExceptionAddress        — .exr -1 출력의 예외 주소
3. kn frame 00             — 콜스택 최상위 프레임
4. UNKNOWN                 — 추출 실패
```

범용 예외 전달 함수(`KERNELBASE!RaiseException`, `VCRUNTIME140!CxxThrowException` 등)는 자동으로 건너뛰고 실제 크래시 원인 함수를 추출합니다.

## AI
Claude Code 활용하여 개발하였음.

## License

[MIT](LICENSE)
