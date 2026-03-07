"""
파일 수집 모듈 (file_collector.py)

크래시 파일 디렉터리를 재귀 탐색하여 분석 대상 파일을 수집한다.
gitignore 스타일 패턴으로 비크래시 파일을 제외하고,
자동 감지 기능으로 제외 후보를 추천한다.
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
    """gitignore 스타일 패턴 매칭을 수행한다."""
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
    """crash_dir 하위의 파일을 재귀 탐색하여 제외 패턴을 적용한 크래시 파일 목록을 반환한다."""
    crash_files = []

    for path in crash_dir.rglob('*'):
        if not path.is_file():
            continue

        relative_path = str(path.relative_to(crash_dir))

        # 제외 패턴 체크
        if not any(match_exclude_pattern(relative_path, p) for p in exclude_patterns):
            crash_files.append(path)

    return sorted(crash_files)


def detect_exclude_candidates(crash_dir: Path) -> tuple:
    """crash_dir을 분석하여 비크래시 파일 제외 추천 항목을 반환한다."""
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
    """기존 패턴에 없는 새로운 추천 항목만 반환한다."""
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
    """사용자에게 제외 항목 선택을 요청한다. CLI/GUI 양쪽 지원."""
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
