"""
파일 수집 모듈 (file_collector.py)

크래시 파일 디렉터리를 재귀 탐색하여 분석 대상 파일을 수집한다.
gitignore 스타일 패턴으로 비크래시 파일을 제외하고,
자동 감지 기능으로 제외 후보를 추천한다.

기존 Auto_Debug v1의 file_collector 로직을 이식/확장했다.
"""

import fnmatch
from pathlib import Path, PurePath
from collections import Counter
from typing import Callable, Optional


# 자동 감지에 사용되는 상수
TEXT_EXTENSIONS = {
    '.txt', '.md', '.log', '.json', '.xml',
    '.yml', '.yaml', '.ini', '.cfg', '.conf',
}
KNOWN_NON_CRASH_FILES = {
    'README.md', 'README.txt', 'LICENSE', 'LICENSE.txt', '.gitignore',
}


def match_exclude_pattern(relative_path: str, pattern: str) -> bool:
    """
    gitignore 스타일 패턴 매칭을 수행한다.

    지원 패턴:
    - 'README.md'      : 모든 위치의 README.md 파일
    - '*.log'          : 모든 위치의 .log 확장자 파일
    - '.state/'        : 경로에 .state 폴더가 포함된 모든 파일
    - '**/debug/'      : 경로에 debug 폴더가 포함된 모든 파일
    - 'master/*.tmp'   : master 폴더 바로 아래의 .tmp 파일

    Args:
        relative_path: crash_dir 기준 상대 경로
        pattern: 제외 패턴

    Returns:
        매칭 여부
    """
    path = PurePath(relative_path)
    parts = path.parts
    filename = path.name

    # 폴더 패턴 (슬래시로 끝남)
    if pattern.endswith('/'):
        folder_name = pattern.rstrip('/')
        if folder_name.startswith('**/'):
            folder_name = folder_name[3:]
        # 경로 어디든 해당 폴더가 포함되면 매칭
        return folder_name in parts[:-1]

    # 경로 패턴 (슬래시 포함)
    if '/' in pattern:
        normalized_path = relative_path.replace('\\', '/')
        return fnmatch.fnmatch(normalized_path, pattern)

    # 파일명/확장자 패턴
    return fnmatch.fnmatch(filename, pattern)


def collect_crash_files(crash_dir: Path, exclude_patterns: list) -> list:
    """
    crash_dir 하위의 모든 파일을 재귀적으로 탐색하여 크래시 파일 목록을 반환한다.
    제외 패턴에 매칭되는 파일은 건너뛴다.

    Args:
        crash_dir: 크래시 파일이 위치한 최상위 디렉터리
        exclude_patterns: 제외 패턴 리스트 (gitignore 스타일)

    Returns:
        크래시 파일 Path 객체 리스트 (정렬됨)
    """
    crash_files = []

    for path in crash_dir.rglob('*'):
        if not path.is_file():
            continue

        relative_path = str(path.relative_to(crash_dir))

        # 제외 패턴 체크 (any()는 short-circuit 평가로 첫 매칭 시 즉시 반환)
        if not any(match_exclude_pattern(relative_path, p) for p in exclude_patterns):
            crash_files.append(path)

    return sorted(crash_files)


def detect_exclude_candidates(crash_dir: Path) -> tuple:
    """
    crash_dir을 분석하여 비크래시 파일 제외 추천 항목을 반환한다.
    알려진 비크래시 파일(README.md 등), 텍스트 확장자, 메타 폴더를 감지한다.

    Args:
        crash_dir: 크래시 파일 디렉터리

    Returns:
        (candidates_dict, total_files) 튜플
        candidates_dict = {
            'files': [(filename, count), ...],
            'extensions': [(pattern, count), ...],
            'folders': [(pattern, 0), ...],
        }
    """
    file_counts = Counter()
    ext_counts = Counter()
    folder_set = set()
    total_files = 0

    for path in crash_dir.rglob('*'):
        if not path.is_file():
            continue

        total_files += 1
        relative = path.relative_to(crash_dir)
        filename = path.name
        ext = path.suffix.lower()
        parts = relative.parts

        # 알려진 비크래시 파일
        if filename in KNOWN_NON_CRASH_FILES:
            file_counts[filename] += 1

        # 텍스트 확장자
        if ext in TEXT_EXTENSIONS:
            ext_counts[f'*{ext}'] += 1

        # 메타 폴더 (점으로 시작)
        for part in parts[:-1]:
            if part.startswith('.'):
                folder_set.add(f'{part}/')

    result = {
        'files': [(f, c) for f, c in file_counts.most_common()],
        'extensions': [(e, c) for e, c in ext_counts.most_common()],
        'folders': [(f, 0) for f in sorted(folder_set)],
    }

    return result, total_files


def get_new_exclude_candidates(candidates: dict, existing_patterns: list) -> list:
    """
    기존 패턴에 없는 새로운 추천 항목만 반환한다.

    Args:
        candidates: detect_exclude_candidates()의 반환값
        existing_patterns: 기존 exclude + _auto_exclude 패턴 리스트

    Returns:
        새로운 추천 항목 리스트 [(pattern, count, type), ...]
    """
    new_items = []
    existing_set = set(existing_patterns)

    for filename, count in candidates['files']:
        if filename not in existing_set:
            new_items.append((filename, count, 'file'))

    for ext, count in candidates['extensions']:
        if ext not in existing_set:
            new_items.append((ext, count, 'ext'))

    for folder, _ in candidates['folders']:
        if folder not in existing_set:
            new_items.append((folder, 0, 'folder'))

    return new_items


def prompt_user_selection(
    new_candidates: list,
    batch_mode: bool = False,
    callback: Optional[Callable] = None,
) -> list:
    """
    사용자에게 제외 항목 선택을 요청한다.
    CLI 모드에서는 콘솔 프롬프트를, GUI 모드에서는 callback을 사용한다.

    Args:
        new_candidates: [(pattern, count, type), ...]
        batch_mode: True면 프롬프트 없이 빈 리스트 반환
        callback: GUI 모드용 콜백 함수. None이면 CLI 모드 사용.
                  callback(candidates) -> selected_patterns 형식

    Returns:
        사용자가 선택한 패턴 리스트
    """
    if batch_mode or not new_candidates:
        return []

    # GUI 모드: 콜백 사용
    if callback is not None:
        return callback(new_candidates)

    # CLI 모드: 콘솔 프롬프트
    print("\n[INFO] 제외 추천 항목:")
    for i, (pattern, count, ptype) in enumerate(new_candidates, 1):
        type_label = {'file': '파일', 'ext': '확장자', 'folder': '폴더'}.get(ptype, '')
        if count > 0:
            print(f"  [{i}] {pattern} ({type_label}, {count}개)")
        else:
            print(f"  [{i}] {pattern} ({type_label})")

    print()
    print("선택: [A]전체 적용 / [S]선택 적용 / [N]무시")

    try:
        choice = input(">>> ").strip().upper()
    except (EOFError, KeyboardInterrupt):
        print()
        return []

    if choice == 'A':
        return [item[0] for item in new_candidates]
    elif choice == 'S':
        print("적용할 번호를 입력하세요 (쉼표로 구분, 예: 1,3,4):")
        try:
            numbers_input = input(">>> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return []

        selected = []
        for num_str in numbers_input.split(','):
            try:
                num = int(num_str.strip())
                if 1 <= num <= len(new_candidates):
                    selected.append(new_candidates[num - 1][0])
            except ValueError:
                continue
        return selected
    else:
        return []
