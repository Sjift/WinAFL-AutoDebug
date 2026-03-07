"""
AutoDebug v3 - CLI 진입점 (main.py)

WinAFL 퍼징 크래시 자동 디버깅 도구.
크래시 파일을 자동으로 디버깅하여 재현 여부 확인,
크래시 지점 분류, 중복 그룹화를 수행한다.

사용법:
    python main.py                           # 기본 실행 (설정 확인 후 진행)
    python main.py --batch                   # 배치 모드 (프롬프트 없음)
    python main.py --config my_config.yaml   # 커스텀 설정 파일
    python main.py --reset-exclude           # 자동 제외 패턴 초기화
"""

import sys
import argparse
from pathlib import Path

from core.config_manager import load_config, validate_config, save_config, DEFAULT_CONFIG
from core.crash_analyzer import CrashAnalyzer
from utils.file_collector import (
    detect_exclude_candidates,
    get_new_exclude_candidates,
    prompt_user_selection,
)


def parse_args():
    """명령줄 인자를 파싱한다."""
    parser = argparse.ArgumentParser(
        description='AutoDebug v3 - WinAFL 크래시 자동 디버깅 도구',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""예시:
  python main.py                         기본 실행 (설정 확인 후 진행)
  python main.py --batch                 배치 모드 (프롬프트 없음)
  python main.py --config other.yaml     커스텀 설정 파일
  python main.py --reset-exclude         자동 제외 패턴 초기화 후 재분석
""",
    )
    parser.add_argument(
        '--batch', action='store_true',
        help='배치 모드 (자동 감지 비활성화, 확인 프롬프트 없음)',
    )
    parser.add_argument(
        '--reset-exclude', action='store_true',
        help='자동 감지 제외 패턴(_auto_exclude) 초기화 후 재분석',
    )
    parser.add_argument(
        '--config', default='config.yaml',
        help='설정 파일 경로 (기본값: config.yaml)',
    )
    return parser.parse_args()


def print_current_config(cfg: dict):
    """현재 설정값을 가독성 있게 출력한다."""
    dbg = cfg.get('debugger', {})
    sig = cfg.get('signature', {})
    out = cfg.get('output', {})
    popup = cfg.get('popup_handler') or {}

    print()
    print("=" * 60)
    print("  AutoDebug v3 - 현재 설정")
    print("=" * 60)
    print(f"  crash_dir     : {cfg.get('crash_dir', '') or '(미설정)'}")
    print(f"  exe_path      : {cfg.get('exe_path', '') or '(미설정)'}")
    print(f"  out_path      : {cfg.get('out_path', '') or '(자동: crash_dir 상위/DbgLogs)'}")
    print(f"  timeout       : {cfg.get('timeout', 15)}초")
    print(f"  parallel      : {cfg.get('parallel', 4)}개")
    print(f"  debugger      : {dbg.get('engine', 'cdb')}")
    print(f"  strategy      : {sig.get('strategy', 'last')}")
    print(f"  output mode   : {out.get('mode', 'both')}")
    print(f"  popup handler : {'활성화' if popup.get('enabled') else '비활성화'}")
    if popup.get('enabled') and popup.get('targets'):
        for t in popup['targets']:
            print(f"    - \"{t.get('title_pattern', '')}\" ({t.get('action', 'close')})")
    print("=" * 60)


def _input_with_default(prompt: str, default: str) -> str:
    """기본값이 있는 입력을 받는다. Enter만 누르면 기본값 사용."""
    if default:
        user_input = input(f"  {prompt} [{default}]: ").strip()
        return user_input if user_input else default
    else:
        return input(f"  {prompt}: ").strip()


def _input_choice(prompt: str, choices: list, default: str) -> str:
    """선택지 중 하나를 입력받는다."""
    choices_str = '/'.join(choices)
    while True:
        user_input = input(f"  {prompt} ({choices_str}) [{default}]: ").strip()
        if not user_input:
            return default
        if user_input in choices:
            return user_input
        print(f"    → {choices_str} 중 하나를 입력하세요.")


def interactive_setup(cfg: dict) -> dict:
    """
    사용자에게 설정 항목을 하나씩 순차적으로 입력받는다.
    각 항목마다 현재 설정값을 보여주고, Enter만 누르면 현재값을 유지한다.

    Args:
        cfg: 기존 설정 딕셔너리 (현재값 표시 및 유지용)

    Returns:
        새로 구성된 설정 딕셔너리
    """
    dbg = cfg.get('debugger', {})
    sig = cfg.get('signature', {})
    out = cfg.get('output', {})
    popup = cfg.get('popup_handler') or {}

    print()
    print("[설정] 각 항목을 입력하세요. Enter만 누르면 현재값을 유지합니다.")
    print("-" * 60)

    # 필수 설정
    print()
    print("  [필수 설정]")
    crash_dir = _input_with_default("크래시 파일 디렉터리 (crash_dir)", cfg.get('crash_dir', ''))
    exe_path = _input_with_default("대상 실행 파일 경로 (exe_path)", cfg.get('exe_path', ''))

    # 선택 설정
    print()
    print("  [선택 설정]")
    out_path = _input_with_default(
        "출력 경로 (빈 값=자동)", cfg.get('out_path', ''))
    timeout_str = _input_with_default("타임아웃 (초)", str(cfg.get('timeout', DEFAULT_CONFIG['timeout'])))
    try:
        timeout = int(timeout_str)
    except ValueError:
        timeout = cfg.get('timeout', DEFAULT_CONFIG['timeout'])
    parallel_str = _input_with_default("병렬 실행 수", str(cfg.get('parallel', DEFAULT_CONFIG['parallel'])))
    try:
        parallel = int(parallel_str)
    except ValueError:
        parallel = cfg.get('parallel', DEFAULT_CONFIG['parallel'])

    # 디버거 설정
    print()
    print("  [디버거 설정]")
    engine = _input_choice("디버거 엔진", ["cdb", "windbgx"], dbg.get('engine', 'cdb'))
    strategy = _input_choice("시그니처 전략", ["first", "last"], sig.get('strategy', 'last'))
    mode = _input_choice("출력 모드", ["both", "summary", "folders"], out.get('mode', 'both'))

    # 팝업 핸들러 (간단히 활성화 여부만)
    print()
    print("  [팝업 핸들러]")
    popup_default = "y" if popup.get('enabled') else "n"
    popup_yn = _input_choice("팝업 핸들러 활성화", ["y", "n"], popup_default)
    popup_enabled = (popup_yn == 'y')

    # 설정 딕셔너리 구성
    new_cfg = {
        'crash_dir': crash_dir,
        'exe_path': exe_path,
        'out_path': out_path,
        'timeout': timeout,
        'parallel': parallel,
        'debugger': {
            'engine': engine,
            'cdb_path': cfg.get('debugger', {}).get('cdb_path', ''),
            'windbgx_path': cfg.get('debugger', {}).get('windbgx_path', ''),
        },
        'signature': {'strategy': strategy},
        'output': {
            'mode': mode,
            'copy_crashes': cfg.get('output', {}).get('copy_crashes', True),
        },
        'popup_handler': {
            'enabled': popup_enabled,
            'scan_interval': cfg.get('popup_handler', {}).get('scan_interval', 0.1) if cfg.get('popup_handler') else 0.1,
            'targets': cfg.get('popup_handler', {}).get('targets', []) if cfg.get('popup_handler') else [],
        },
        'exclude': cfg.get('exclude', []),
        '_auto_exclude': [],
        '_last_crash_dir': '',
    }

    print()
    print("-" * 60)
    print("[설정] 입력 완료.")
    return new_cfg


def prompt_config_review(cfg: dict, config_path: Path) -> dict:
    """
    현재 설정을 출력하고, 유지 또는 재설정을 선택받는다.
    인자 없이 실행했을 때만 호출된다 (--batch 제외).

    Args:
        cfg: 현재 로드된 설정 딕셔너리
        config_path: 설정 파일 경로 (재설정 시 저장용)

    Returns:
        최종 설정 딕셔너리 (유지 또는 재설정된)
    """
    print_current_config(cfg)
    print()
    print("  [1] 현재 설정으로 진행")
    print("  [2] 설정 변경 후 진행 (항목별 현재값 유지/변경 선택)")
    print()

    while True:
        try:
            choice = input("  선택 (1/2): ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)

        if choice == '1':
            return cfg
        elif choice == '2':
            new_cfg = interactive_setup(cfg)
            save_config(config_path, new_cfg)
            print(f"[INFO] 새 설정이 {config_path}에 저장되었습니다.")
            return new_cfg
        else:
            print("    → 1 또는 2를 입력하세요.")


def cli_progress_callback(progress):
    """CLI용 진행 콜백. tqdm 없이 간단한 상태 출력."""
    # 10% 단위로만 출력하여 로그 과다 방지
    if progress.total > 0 and progress.completed % max(1, progress.total // 10) == 0:
        pct = progress.completed * 100 // progress.total
        print(f"[진행] {progress.completed}/{progress.total} ({pct}%) "
              f"크래시: {progress.crashes_found}, 타임아웃: {progress.timeouts}")


def main():
    """메인 실행 함수."""
    args = parse_args()
    config_path = Path(args.config)
    cfg = load_config(config_path)

    # 인자 없이 실행 시 설정 확인 및 재설정 프롬프트
    # (--batch, --reset-exclude 등 명시적 인자가 없는 경우)
    has_explicit_args = args.batch or args.reset_exclude or args.config != 'config.yaml'
    if not has_explicit_args:
        cfg = prompt_config_review(cfg, config_path)

    errors = validate_config(cfg)
    if errors:
        print("[ERROR] 설정 오류:")
        for err in errors:
            print(f"  - {err}")
        sys.exit(1)

    crash_dir = Path(cfg['crash_dir'])

    # ============================================================
    # 제외 패턴 처리
    # ============================================================
    user_exclude = cfg.get('exclude', [])
    if not isinstance(user_exclude, list):
        user_exclude = []

    auto_exclude = cfg.get('_auto_exclude', [])
    if not isinstance(auto_exclude, list):
        auto_exclude = []

    last_crash_dir = cfg.get('_last_crash_dir', '')

    # crash_dir 변경 감지 → auto_exclude 초기화
    crash_dir_changed = (str(crash_dir) != last_crash_dir)
    if crash_dir_changed and last_crash_dir:
        print("[INFO] crash_dir이 변경되었습니다. 자동 감지 설정을 초기화합니다.")
        auto_exclude = []

    if args.reset_exclude:
        print("[INFO] --reset-exclude: 자동 감지 설정을 초기화합니다.")
        auto_exclude = []

    # 배치 모드가 아니면 자동 감지 실행
    config_changed = False
    if not args.batch:
        existing_patterns = user_exclude + auto_exclude
        candidates, total_scanned = detect_exclude_candidates(crash_dir)
        new_candidates = get_new_exclude_candidates(candidates, existing_patterns)

        if new_candidates:
            selected = prompt_user_selection(new_candidates)
            if selected:
                auto_exclude.extend(selected)
                config_changed = True
                print(f"[INFO] {len(selected)}개 패턴이 추가되었습니다.")

    if config_changed or crash_dir_changed or args.reset_exclude:
        cfg['_auto_exclude'] = auto_exclude
        cfg['_last_crash_dir'] = str(crash_dir)
        save_config(config_path, cfg)

    exclude_patterns = user_exclude + auto_exclude

    # ============================================================
    # 출력 경로 설정
    # ============================================================
    out_path_cfg = cfg.get('out_path', '')
    if out_path_cfg:
        out_path = Path(out_path_cfg)
    else:
        out_path = crash_dir.parent / 'DbgLogs'

    # ============================================================
    # 분석 실행
    # ============================================================
    analyzer = CrashAnalyzer(cfg)
    result = analyzer.analyze(
        crash_dir=crash_dir,
        out_path=out_path,
        exclude_patterns=exclude_patterns,
        progress_callback=cli_progress_callback,
    )

    if result.entries:
        total = len(result.entries)
        crashes = len(result.crash_entries)
        fps = len(result.false_positive_entries)
        timeouts = len(result.timeout_entries)
        unique = len(result.crash_groups)

        print()
        print("=" * 50)
        print(f"분석 완료: 총 {total}개 파일")
        print(f"  진짜 크래시: {crashes}개 ({unique}개 유형)")
        print(f"  False Positive: {fps}개")
        print(f"  타임아웃: {timeouts}개")
        print(f"  출력 디렉터리: {out_path}")
        print("=" * 50)
    else:
        print("[INFO] 분석할 파일이 없습니다.")


if __name__ == '__main__':
    main()
