"""
설정 관리 모듈 (config_manager.py)

YAML 기반 설정 파일의 로드, 저장, 검증, 마이그레이션을 담당한다.
"""

import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


# ============================================================
# 기본 설정 스키마
# ============================================================

DEFAULT_CONFIG = {
    # 필수 설정
    'crash_dir': '',           # 크래시 파일 디렉터리 (재귀 탐색)
    'exe_path': '',            # 디버깅 대상 실행 파일 경로

    # 선택 설정
    'out_path': '',            # 로그 저장 경로 (빈 값이면 crash_dir 상위에 DbgLogs 생성)
    'timeout': 15,             # 각 프로세스 타임아웃 (초)
    'parallel': 4,             # 병렬 실행할 디버거 프로세스 수

    # 디버거 엔진 설정
    'debugger': {
        'engine': 'cdb',       # 'cdb' 또는 'windbgx'
        'cdb_path': '',        # CDB 실행 파일 경로 (빈 값이면 PATH에서 탐색)
        'windbgx_path': '',    # WinDbgX 실행 파일 경로 (빈 값이면 PATH에서 탐색)
    },

    # 시그니처 추출 설정
    'signature': {
        'strategy': 'first',   # 'first' (kn frame 00, 기본) 또는 'last' (kn 최하단)
    },

    # 출력 설정
    'output': {
        'mode': 'both',        # 'summary' (요약만), 'folders' (폴더 분류만), 'both' (둘 다)
        'copy_crashes': True,  # 크래시 파일을 시그니처 폴더에 복사할지 여부
    },

    # 팝업 핸들러 설정
    'popup_handler': {
        'enabled': False,           # 팝업 핸들러 활성화 여부
        'scan_interval': 0.1,       # 팝업 스캔 주기 (초)
        'targets': [],              # 팝업 타겟 리스트
    },

    # 제외 패턴 (gitignore 스타일)
    'exclude': [],             # 사용자 정의 제외 패턴
    '_auto_exclude': [],       # 자동 감지된 제외 패턴 (crash_dir 변경 시 초기화)
    '_last_crash_dir': '',     # 마지막으로 사용한 crash_dir (변경 감지용)
}


# ============================================================
# config.yaml 초기 생성 시 사용할 템플릿 (주석 포함)
# ============================================================

CONFIG_TEMPLATE = """# AutoDebug v3 설정 파일
# 크래시 자동 분석 도구 설정

# ============================================================
# 필수 설정
# ============================================================
crash_dir: ""      # 크래시 파일이 위치한 디렉터리 (재귀 탐색)
exe_path: ""       # 디버깅할 실행 파일 경로

# ============================================================
# 선택 설정
# ============================================================
out_path: ""       # 로그 저장 경로 (빈 값이면 crash_dir 상위에 DbgLogs 생성)
timeout: 15        # 각 프로세스 타임아웃 (초)
parallel: 4        # 병렬 실행할 디버거 프로세스 수

# ============================================================
# 디버거 엔진 설정
# ============================================================
debugger:
  engine: "cdb"          # 사용할 디버거: "cdb" 또는 "windbgx"
  cdb_path: ""           # CDB 경로 (빈 값이면 PATH에서 탐색)
  windbgx_path: ""       # WinDbgX 경로 (빈 값이면 PATH에서 탐색)

# ============================================================
# 시그니처 추출 설정
# ============================================================
signature:
  strategy: "first"      # "first" (kn frame 00, 기본) 또는 "last" (kn 최하단)

# ============================================================
# 출력 설정
# ============================================================
output:
  mode: "both"           # "summary" (요약만), "folders" (폴더 분류만), "both" (둘 다)
  copy_crashes: true     # 크래시 파일을 시그니처 폴더에 복사

# ============================================================
# 팝업 핸들러 설정
# ============================================================
popup_handler:
  enabled: false         # 팝업 핸들러 활성화 여부
  scan_interval: 0.1     # 팝업 스캔 주기 (초)
  targets: []            # 팝업 타겟 리스트

# ============================================================
# 제외 패턴 (gitignore 스타일)
# ============================================================
exclude: []

# ============================================================
# 내부 설정 (자동 관리, 수동 수정 불필요)
# ============================================================
_auto_exclude: []    # 자동 감지된 제외 패턴 (crash_dir 변경 시 초기화)
_last_crash_dir: ""  # 마지막으로 사용한 crash_dir (변경 감지용)
"""


def deep_merge(base: dict, override: dict) -> dict:
    """두 딕셔너리를 재귀적으로 깊은 병합한다."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(path: Path) -> dict:
    """설정 파일을 로드한다. 파일이 없으면 템플릿으로 생성 후 기본값을 반환한다."""
    if not path.exists():
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('w', encoding='utf-8') as f:
                f.write(CONFIG_TEMPLATE)
            print(f"[INFO] 기본 설정 파일 생성됨: {path}")
        except OSError as e:
            print(f"[WARN] 기본 설정 파일 생성 실패: {e}")
        return deep_merge(DEFAULT_CONFIG, {})

    try:
        raw = yaml.safe_load(path.read_text(encoding='utf-8')) or {}
        return deep_merge(DEFAULT_CONFIG, raw)
    except yaml.YAMLError as e:
        print(f"[WARN] 설정 파일 파싱 실패({e}) - 기본값 사용")
        return deep_merge(DEFAULT_CONFIG, {})
    except OSError as e:
        print(f"[WARN] 설정 파일 읽기 실패({e}) - 기본값 사용")
        return deep_merge(DEFAULT_CONFIG, {})


def save_config(config_path: Path, cfg: dict):
    """설정을 파일에 저장한다."""
    try:
        # 주석 보존 대신 전체 재생성 (정확성 우선)
        content = _generate_config_yaml(cfg)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with config_path.open('w', encoding='utf-8') as f:
            f.write(content)
    except OSError as e:
        print(f"[WARN] 설정 파일 저장 실패: {e}")


def _generate_config_yaml(cfg: dict) -> str:
    """설정 딕셔너리를 주석이 포함된 YAML 문자열로 변환한다."""
    lines = []
    lines.append("# AutoDebug v3 설정 파일")
    lines.append("# 크래시 자동 분석 도구 설정")
    lines.append("")
    lines.append("# ============================================================")
    lines.append("# 필수 설정")
    lines.append("# ============================================================")
    lines.append(f"crash_dir: '{cfg.get('crash_dir', '')}'      # 크래시 파일이 위치한 디렉터리")
    lines.append(f"exe_path: '{cfg.get('exe_path', '')}'       # 디버깅할 실행 파일 경로")
    lines.append("")
    lines.append("# ============================================================")
    lines.append("# 선택 설정")
    lines.append("# ============================================================")
    lines.append(f"out_path: '{cfg.get('out_path', '')}'       # 로그 저장 경로")
    lines.append(f'timeout: {cfg.get("timeout", 15)}        # 각 프로세스 타임아웃 (초)')
    lines.append(f'parallel: {cfg.get("parallel", 4)}        # 병렬 실행 수')
    lines.append("")

    dbg = cfg.get('debugger', DEFAULT_CONFIG['debugger'])
    lines.append("# ============================================================")
    lines.append("# 디버거 엔진 설정")
    lines.append("# ============================================================")
    lines.append("debugger:")
    lines.append(f'  engine: "{dbg.get("engine", "cdb")}"          # "cdb" 또는 "windbgx"')
    lines.append(f"  cdb_path: '{dbg.get('cdb_path', '')}'")
    lines.append(f"  windbgx_path: '{dbg.get('windbgx_path', '')}'")

    lines.append("")

    sig = cfg.get('signature', DEFAULT_CONFIG['signature'])
    lines.append("# ============================================================")
    lines.append("# 시그니처 추출 설정")
    lines.append("# ============================================================")
    lines.append("signature:")
    lines.append(f'  strategy: "{sig.get("strategy", "first")}"      # "first" (기본) 또는 "last"')
    lines.append("")

    out = cfg.get('output', DEFAULT_CONFIG['output'])
    lines.append("# ============================================================")
    lines.append("# 출력 설정")
    lines.append("# ============================================================")
    lines.append("output:")
    lines.append(f'  mode: "{out.get("mode", "both")}"           # "summary", "folders", "both"')
    lines.append(f'  copy_crashes: {str(out.get("copy_crashes", True)).lower()}')
    lines.append("")

    # YAML에서 popup_handler: 만 있으면 None이 되므로 방어
    popup = cfg.get('popup_handler') or DEFAULT_CONFIG['popup_handler']
    lines.append("# ============================================================")
    lines.append("# 팝업 핸들러 설정")
    lines.append("# ============================================================")
    lines.append("popup_handler:")
    lines.append(f'  enabled: {str(popup.get("enabled", False)).lower()}')
    lines.append(f'  scan_interval: {popup.get("scan_interval", 0.1)}')
    targets = popup.get('targets', [])
    if not targets:
        lines.append("  targets: []")
    else:
        lines.append("  targets:")
        for t in targets:
            lines.append(f"    - title_pattern: '{t.get('title_pattern', '')}'")

            if 'max_width' in t:
                lines.append(f'      max_width: {t["max_width"]}')
            if 'max_height' in t:
                lines.append(f'      max_height: {t["max_height"]}')
            lines.append(f'      action: "{t.get("action", "close")}"')
    lines.append("")
    lines.append("# ============================================================")
    lines.append("# 제외 패턴 (gitignore 스타일)")
    lines.append("# ============================================================")
    exclude = cfg.get('exclude', [])
    if not exclude:
        lines.append("exclude: []")
    else:
        lines.append("exclude:")
        for pattern in exclude:
            lines.append(f"  - '{pattern}'")
    lines.append("")
    lines.append("# ============================================================")
    lines.append("# 내부 설정 (자동 관리)")
    lines.append("# ============================================================")
    auto_exc = cfg.get('_auto_exclude', [])
    if not auto_exc:
        lines.append("_auto_exclude: []")
    else:
        lines.append("_auto_exclude:")
        for pattern in auto_exc:
            lines.append(f"  - '{pattern}'")
    lines.append(f"_last_crash_dir: '{cfg.get('_last_crash_dir', '')}'")

    lines.append("")

    return '\n'.join(lines)


def validate_config(cfg: dict) -> list[str]:
    """설정값을 검증하여 오류 메시지 리스트를 반환한다. 빈 리스트면 유효."""
    errors = []

    # 필수 경로 검증
    crash_dir = cfg.get('crash_dir', '')
    if not crash_dir:
        errors.append("crash_dir: 크래시 파일 디렉터리가 설정되지 않았습니다.")
    elif not Path(crash_dir).is_dir():
        errors.append(f"crash_dir: 디렉터리를 찾을 수 없습니다 - {crash_dir}")

    exe_path = cfg.get('exe_path', '')
    if not exe_path:
        errors.append("exe_path: 실행 파일 경로가 설정되지 않았습니다.")
    elif not Path(exe_path).is_file():
        errors.append(f"exe_path: 파일을 찾을 수 없습니다 - {exe_path}")

    # 타임아웃 검증
    timeout = cfg.get('timeout', 15)
    try:
        timeout_val = float(timeout)
        if timeout_val <= 0:
            errors.append("timeout: 양수여야 합니다.")
    except (TypeError, ValueError):
        errors.append(f"timeout: 올바른 숫자가 아닙니다 - {timeout}")

    # 병렬 수 검증
    parallel = cfg.get('parallel', 4)
    try:
        parallel_val = int(parallel)
        if parallel_val < 1:
            errors.append("parallel: 1 이상이어야 합니다.")
    except (TypeError, ValueError):
        errors.append(f"parallel: 올바른 정수가 아닙니다 - {parallel}")

    # 디버거 엔진 검증
    debugger = cfg.get('debugger', {})
    engine = debugger.get('engine', 'cdb')
    if engine not in ('cdb', 'windbgx'):
        errors.append(f"debugger.engine: 'cdb' 또는 'windbgx'만 허용됩니다 - {engine}")

    # 시그니처 전략 검증
    signature = cfg.get('signature', {})
    strategy = signature.get('strategy', 'first')
    if strategy not in ('first', 'last'):
        errors.append(f"signature.strategy: 'first' 또는 'last'만 허용됩니다 - {strategy}")

    # 출력 모드 검증
    output = cfg.get('output', {})
    mode = output.get('mode', 'both')
    if mode not in ('summary', 'folders', 'both'):
        errors.append(f"output.mode: 'summary', 'folders', 'both'만 허용됩니다 - {mode}")

    return errors


def migrate_config(old_cfg: dict) -> dict:
    """기존 Auto_Debug v1 설정을 v3 형식으로 마이그레이션한다."""
    new_cfg = deep_merge(DEFAULT_CONFIG, {})

    # 기존 필드 이식
    for key in ('crash_dir', 'exe_path', 'out_path', 'timeout', 'parallel',
                'exclude', '_auto_exclude', '_last_crash_dir'):
        if key in old_cfg:
            new_cfg[key] = old_cfg[key]

    # v1은 windbgx만 사용했으므로 기본값을 windbgx로 설정
    if 'debugger' not in old_cfg:
        new_cfg['debugger']['engine'] = 'windbgx'

    return new_cfg
