# WinAFL-AutoDebug

An automation tool that automatically debugs [WinAFL](https://github.com/googleprojectzero/winafl) crash files to verify reproducibility, classify crash points, and group duplicates.

## Development Background

After performing fuzzing using WinAFL, the following tasks must be performed manually on the generated crash files:

1. **Verify Reproducibility** — Re-execute the crash file in a debugger to validate if the crash actually occurs
2. **Identify Crash Points** — Determine the location where the exception occurred (`module!function+offset`) and the exception type
3. **Deduplication** — Group and classify files originating from the same crash point

However, fuzzing typically generates over 100 crash files. Manually processing each file individually consumes excessive time and resources. To eliminate this inefficiency in repetitive tasks, we developed a script using Claude Code to automate the entire process.

## Features

- **Automated Debugging** — Automatically replays crash files with CDB or WinDbgX and collects debugger output
- **Crash Classification** — Automatically classifies crashes into three types: real crash / false positive / timeout
- **Signature Extraction** — Extracts crash points based on `module!function+offset` and groups identical signatures
- **Exception Analysis** — Automatically extracts ExceptionCode (Access Violation, Divide-by-zero, C++ throw, etc.) and displays in reports
- **Parallel Processing** — Parallel debugging via ThreadPoolExecutor (4 concurrent threads by default)
- **Popup Handler** — Automatically closes error popups during debugging (regular expression matching, 3-stage close strategy)
- **Dual Reports** — Generates Markdown (`CrashSummary.md`) + HTML (`AnalysisReport.html`) reports
- **GUI Dashboard** — CustomTkinter-based dashboard (integrated settings, execution, and result review)

## Requirements

- **OS**: Windows 10/11 (debugger execution environment, VM recommended)
- **Python**: 3.10+
- **Debugger**: [CDB](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/) (included in Windows SDK) or WinDbgX

## Installation

```bash
git clone https://github.com/Sjift/WinAFL-AutoDebug.git
cd WinAFL-AutoDebug
pip install -r requirements.txt
```

### Dependencies

| Package | Purpose | Required |
|---------|---------|----------|
| PyYAML | config.yaml management | Yes |
| customtkinter | GUI dashboard | Yes (for GUI use) |
| pywinauto | Auto-close popups | No (only for popup handler) |

## Usage

### GUI Mode

```bash
python main_gui.py
```

Or run `bin/AutoDebug.exe` (no Python installation required)

### CLI Mode

```bash
# Interactive mode (proceed after checking settings)
python main.py

# Batch mode (run immediately without prompts)
python main.py --batch

# Custom configuration file
python main.py --config my_config.yaml

# Reset auto-exclusion patterns
python main.py --reset-exclude
```

## Configuration

`config.yaml` is auto-generated on first run. All settings can also be changed from the GUI.

```yaml
crash_dir: "C:/fuzzing/crashes"     # Crash file directory
exe_path: "C:/target/app.exe"       # Target executable to debug
out_path: ""                        # Output path (empty → DbgLogs in crash_dir parent directory)
timeout: 15                         # Process timeout (seconds)
parallel: 4                         # Number of parallel debuggers

debugger:
  engine: "cdb"                     # "cdb" or "windbgx"
  cdb_path: ""                      # CDB path (empty → auto-detect)

signature:
  strategy: "first"                 # kn fallback strategy: "first" (frame 00) / "last" (bottom frame)

output:
  mode: "both"                      # "summary" / "folders" / "both"
  copy_crashes: true                # Copy crash files to signature folder

popup_handler:
  enabled: false                    # Enable popup handler
  scan_interval: 0.1                # Scan interval (seconds)
  targets: []                       # [{title_pattern, max_width, max_height, action}]

exclude: []                         # gitignore-style exclusion patterns
```

## Output

```
DbgLogs/
├── logs/                           # Original debugger logs
├── CrashSummary.md                 # Markdown report
├── AnalysisReport.html             # HTML report (dark theme)
├── real_crashes/                   # Folders classified by signature
│   ├── ModuleA_FuncX+0x1234/
│   │   ├── crash_001.hwp           # Crash file copy
│   │   └── crash_001.hwp.txt       # Debugger log
│   └── ModuleB_FuncY+0xABCD/
├── timeouts/                       # Timeout files
└── false_positives/                # False positive files
```

### CrashSummary.md Example

```markdown
## Crash Classification (3 types, 25 files)

### HwpApp!HncGetEqEditPluginProxy+0x463d7 — 16 files

> Exception: Integer divide-by-zero (c0000094)
> Faulting: `idiv eax,ecx`

| # | Filename | Notes |
|---|----------|-------|
| 1 | id_000067_00_EXCEPTION_INT_DIVIDE_BY_ZERO |  |
| 2 | id_000072_00_EXCEPTION_INT_DIVIDE_BY_ZERO |  |
...
```

## Architecture

```
main.py / main_gui.py              # Entry points (CLI / GUI)
core/
├── config_manager.py              # YAML configuration load/save/validate/migrate
├── crash_analyzer.py              # Analysis orchestration (ThreadPoolExecutor)
├── debugger_engine.py             # CDB/WinDbgX engine abstraction (Strategy pattern)
└── signature_extractor.py         # Signature extraction + crash determination
gui/
├── main_window.py                 # Main dashboard (CustomTkinter)
├── popup_config_dialog.py         # Popup target management dialog
└── exclude_dialog.py              # Exclusion pattern selection dialog
utils/
├── file_collector.py              # File collection + gitignore exclusion patterns
├── popup_handler.py               # Popup auto-close (daemon thread)
└── result_writer.py               # Report generation (Markdown + HTML + folder classification)
```

### Crash Detection (3-stage)

```
1. "##########" + "total:" present  → False Positive (WinAFL statistics output)
2. FAILURE_BUCKET_ID present        → Real Crash (!analyze -v completed)
3. ExceptionCode with 'c' prefix    → Real Crash (backup when !analyze incomplete due to timeout)
4. None of the above conditions met → False Positive
```

### Signature Extraction Priority

```
1. AV dump before g;       — module!function+offset of first-chance exception
2. ExceptionAddress        — exception address from .exr -1 output
3. kn frame 00             — topmost frame in call stack
4. UNKNOWN                 — extraction failed
```

General-purpose exception dispatch functions (`KERNELBASE!RaiseException`, `VCRUNTIME140!CxxThrowException`, etc.) are automatically skipped, and the actual crash-causing function is extracted.

## AI

Developed with Claude Code.

## License

[MIT](LICENSE)
