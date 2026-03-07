"""
시그니처 추출 모듈 (signature_extractor.py)

디버거 출력에서 크래시 시그니처를 추출하고 크래시 여부를 판별한다.

크래시 지점 추출 전략:
- Primary: g; 이전의 첫 AV 덤프에서 module!function+offset + 어셈블리 추출
  → g; 이후 deferred 명령이 다른 스레드의 예외를 캡처하는 문제를 회피
- Secondary: g; 이후 kn 스택 frame 00에서 deferred crash point 추출 (검증용)
- 불일치 시 CrashSummary에 두 크래시 지점 모두 표시
"""

import re
from dataclasses import dataclass
from typing import Optional, Tuple


# 무시할 범용 예외 처리/전달 함수
# 이 함수들은 예외 전달 메커니즘일 뿐 실제 크래시 원인이 아님
# g; 이전 추출, ExceptionAddress, kn fallback 모두에 적용
GENERIC_EXCEPTION_FUNCS = frozenset({
    'KERNELBASE!RaiseException',
    'ntdll!KiUserExceptionDispatcher',
    'ntdll!RtlDispatchException',
    'ntdll!RtlRaiseException',
    'VCRUNTIME140!CxxThrowException',  # MSVC C++ throw 메커니즘
})


# 모듈!함수+오프셋 패턴 (C++ 네임스페이스/클래스/연산자 포함)
# 예: HncFoundation!CHncPropertySection::Get+0x55
# 예: VCRUNTIME140!memset+0x3c
# 예: ntdll!RtlpWaitOnCriticalSection+0x1ae
# 예: HwpApp!CActionPreviewManagerImpl::operator=+0x2f502
# [^\s()+]+ → 공백/괄호/+ 제외 모든 문자 허용 (=, <, >, *, ~ 등 C++ 연산자)
# +를 제외하므로 오프셋 구분자 +0x와 충돌 없음
SIGNATURE_PATTERN = re.compile(
    r'([A-Za-z0-9_]+![^\s()+]+\+0x[0-9A-Fa-f]+)'
)

# 스택 트레이스 마커 (WinDbg/CDB 공통)
STACK_MARKER = ' # ChildEBP RetAddr'
# x64 환경 마커도 지원
STACK_MARKER_X64 = ' # Child-SP          RetAddr'

# g; deferred 명령 실행 라인 패턴
DEFERRED_CMD_PATTERN = re.compile(r'g;\s*\.exr')

# 디스어셈블리 라인 패턴
# 예: 69c5a798 663b470e        cmp     ax,word ptr [edi+0Eh]    ds:002b:1ae72000=????
# 그룹1: 주소, 그룹2: 바이트코드, 그룹3: 명령어 (segment descriptor 제외)
DISASM_PATTERN = re.compile(
    r'^([0-9a-f]{7,16})\s+([0-9a-f]+)\s{2,}(.+?)(?:\s{2,}[a-z]s:|\s*$)',
    re.IGNORECASE
)


@dataclass
class CrashInfo:
    """크래시 분석 결과 데이터 클래스"""
    is_crash: bool = False                # 진짜 크래시 여부
    signature: str = 'UNKNOWN'            # primary: g; 이전 AV 덤프 크래시 지점
    faulting_instruction: str = ''        # g; 이전 AV 덤프의 어셈블리 명령어
    deferred_signature: str = 'UNKNOWN'   # secondary: g; 이후 kn frame 00
    signature_mismatch: bool = False      # 두 크래시 지점 불일치 여부
    all_signatures: list = None           # kn 스택의 모든 시그니처 리스트
    has_stack_trace: bool = False         # 스택 트레이스 존재 여부
    exception_code: str = ''             # 예외 코드 (예: "c0000005")
    exception_type: str = ''             # 예외 종류 (예: "Access violation")

    def __post_init__(self):
        if self.all_signatures is None:
            self.all_signatures = []


def normalize_signature(sig: str) -> str:
    """
    시그니처의 오프셋 leading zero를 제거하여 정규화한다.
    ExceptionAddress(+0x00035c47)와 kn(+0x35c47)의 동일 오프셋을 통일한다.

    예: module!func+0x0002f502 → module!func+0x2f502
        module!func+0x20 → module!func+0x20 (변경 없음)

    Args:
        sig: module!function+offset 형식 시그니처

    Returns:
        정규화된 시그니처
    """
    m = re.match(r'^(.+\+0x)0*([0-9A-Fa-f]+)$', sig)
    if m:
        return m.group(1) + m.group(2)
    return sig


def extract_exception_address(output: str) -> str:
    """
    .exr -1 또는 !analyze -v 출력에서 ExceptionAddress의 심볼을 추출한다.

    형식: ExceptionAddress: 69881082 (HwpApp!CActionPreviewManagerImpl::operator=+0x0002f502)

    이 값은 실제 예외 발생 주소로, g; 이전 추출 실패 시 가장 정확한 fallback.
    g; 이후 deferred 명령 출력에서만 나타나므로, real crash에서만 존재한다.

    Args:
        output: 디버거 전체 출력

    Returns:
        module!function+offset (정규화됨). 없으면 빈 문자열.
    """
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith('ExceptionAddress:'):
            m = SIGNATURE_PATTERN.search(stripped)
            if m:
                return normalize_signature(m.group(1))
    return ''


def extract_exception_code(output: str) -> Tuple[str, str]:
    """
    g; 이후 deferred 명령 출력에서 ExceptionCode와 예외 종류를 추출한다.

    형식: ExceptionCode: c0000005 (Access violation)

    g; 이후 .exr -1 출력에서만 추출하여, g; 이전의 first-chance 예외와 혼동을 방지한다.

    Args:
        output: 디버거 전체 출력

    Returns:
        (exception_code, exception_type) 튜플.
        예: ("c0000005", "Access violation")
        추출 실패 시 ('', '') 반환
    """
    lines = output.splitlines()
    after_g = False

    for line in lines:
        if not after_g:
            if DEFERRED_CMD_PATTERN.search(line):
                after_g = True
            continue

        stripped = line.strip()
        if stripped.startswith('ExceptionCode:'):
            code_part = stripped[len('ExceptionCode:'):].strip()
            m = re.match(r'([0-9a-fA-F]+)\s*\((.+?)\)', code_part)
            if m:
                return (m.group(1).lower(), m.group(2))
            # 괄호 없는 경우 코드만 추출
            tokens = code_part.split()
            if tokens:
                return (tokens[0].lower(), '')
            return ('', '')

    return ('', '')


def is_real_crash(output: str) -> bool:
    """
    디버거 출력에서 진짜 크래시(재현 O) 여부를 판별한다.
    CDB/WinDbgX 공통으로 사용하는 통합 판별 로직이다.

    핵심 원리 — deferred 명령의 "전부 실행 또는 전부 미실행":
      -c "g; .exr -1; .ecxr; kn; !analyze -v; q" 에서
      g; 이후 나머지 명령은 크래시(debug event) 발생까지 대기(deferred)
      - 크래시 발생(real) → deferred 명령 전부 실행 → 분석 출력 존재
      - 크래시 미발생(fake) → 프로세스 정상 종료 → deferred 명령 전부 미실행 → 분석 출력 없음

    판별 기준 (3단계):
    1. AFL 퍼저 통계 (##########, total:) → false positive
    2. FAILURE_BUCKET_ID: 존재 → real crash (!analyze -v 완료)
    3. ExceptionCode: c 존재 → real crash (타임아웃으로 !analyze 미완료 시 백업)
       - .exr -1 출력 형식: "   ExceptionCode: c0000005 (Access violation)"
       - fake는 deferred 미실행 → ExceptionCode 출력 자체가 없음 → 오판 불가
    4. 나머지 → false positive

    ※ second chance는 판별 기준에서 제외:
       id_000087처럼 second chance 없이도 real crash인 경우 존재
       (g; 이후 별개의 새 예외가 first-chance로 발생 → deferred 실행)
       ExceptionCode 체크가 second chance를 완전히 포함(상위 호환)함

    Args:
        output: 디버거 전체 출력

    Returns:
        진짜 크래시(재현 O)이면 True
    """
    # Step 1: AFL/퍼저 통계 출력 → false positive
    if "##########" in output and "total:" in output:
        return False

    # Step 2: !analyze -v 완료 → real crash (최우선 지표)
    # FAILURE_BUCKET_ID는 !analyze -v의 최종 분석 결과에만 나타남
    if "FAILURE_BUCKET_ID:" in output:
        return True

    # Step 3: 타임아웃으로 !analyze -v 미완료, 하지만 크래시는 발생함
    # .exr -1 출력의 ExceptionCode: c → deferred 명령이 실행됨 = 크래시 발생
    # fake 파일은 deferred 명령 미실행 → ExceptionCode 출력 없음 → 오판 불가
    if "ExceptionCode:" in output:  # 사전 체크로 불필요한 라인 순회 회피
        for line in output.splitlines():
            stripped = line.strip()
            if stripped.startswith("ExceptionCode:"):
                # c0000005 (Access violation), c0000374 (Heap corruption) 등
                code_part = stripped[len("ExceptionCode:"):].strip().lower()
                if code_part.startswith("c") or code_part.startswith("0xc"):
                    return True

    # Step 4: 나머지 → false positive
    # - first-chance Access violation만 있는 경우 (뷰어 내부 handled exception)
    # - 빈 로그, 모듈 로드만 있는 경우
    return False


def extract_first_av_info(output: str) -> Tuple[str, str]:
    """
    g; 이전의 첫 AV 덤프에서 크래시 지점과 어셈블리 명령어를 추출한다.

    g; 명령 실행 라인 이전에 나타나는 레지스터 덤프 + 디스어셈블리에서 추출:
      module!function+offset:              ← 크래시 지점
      address bytes        instruction     ← 어셈블리 명령어
      0:NNN> g; .exr -1; ...               ← g; 명령 라인

    이 정보는 CDB/WinDbg가 첫 번째 예외에서 브레이크할 때 출력되며,
    g; 이후 deferred 명령이 다른 스레드의 예외를 캡처하는 문제를 회피한다.

    Args:
        output: 디버거 전체 출력

    Returns:
        (crash_point, faulting_instruction) 튜플.
        crash_point: module!function+offset (예: "HwpApp!...Release+0xbdaa3")
        faulting_instruction: 어셈블리 명령어 (예: "mov eax,dword ptr [esi+60h]")
        추출 실패 시 ('', '') 반환
    """
    lines = output.splitlines()

    # g; 명령 라인 찾기 (deferred 명령 실행 라인)
    g_cmd_idx = -1
    for i, line in enumerate(lines):
        if DEFERRED_CMD_PATTERN.search(line):
            g_cmd_idx = i
            break

    if g_cmd_idx < 2:
        return ('', '')

    # g; 이전 영역에서 역방향 탐색:
    # 디스어셈블리 라인 → 그 바로 위에 module!function+offset: 라인
    for i in range(g_cmd_idx - 1, max(g_cmd_idx - 10, -1), -1):
        line = lines[i].strip()
        disasm_match = DISASM_PATTERN.match(line)
        if disasm_match:
            # 디스어셈블리 라인 발견 → 명령어 추출 + 정규화
            raw_instruction = disasm_match.group(3)
            faulting_instruction = ' '.join(raw_instruction.split())

            # 위쪽으로 심볼 줄 탐색 (*** WARNING 줄 스킵, 최대 3줄)
            for k in range(1, 4):
                if i - k < 0:
                    break
                symbol_line = lines[i - k].strip()
                # 줄 끝의 ':' 제거 후 시그니처 패턴 매칭
                if symbol_line.endswith(':'):
                    symbol_candidate = symbol_line[:-1]
                    sig_match = SIGNATURE_PATTERN.search(symbol_candidate)
                    if sig_match:
                        return (normalize_signature(sig_match.group(1)),
                                faulting_instruction)
                    break  # ':' 끝이지만 시그니처 아님 → 중단
                # *** WARNING 줄은 스킵
                if symbol_line.startswith('***'):
                    continue
                break  # 레지스터/기타 줄 → 심볼 없음

            return ('', faulting_instruction)

    return ('', '')


def extract_signature(output: str, strategy: str = 'first') -> CrashInfo:
    """
    디버거 출력에서 크래시 시그니처를 추출한다.

    추출 우선순위:
    1. g; 이전 AV 덤프 (범용 함수 필터링 적용)
    2. ExceptionAddress (.exr -1 / !analyze -v 출력)
    3. kn 스택 frame 00 (strategy='first') 또는 최하단 (strategy='last')
    4. UNKNOWN

    Args:
        output: 디버거 전체 출력
        strategy: 'first' (kn frame 00, 기본) 또는 'last' (kn 최하단)

    Returns:
        CrashInfo 객체
    """
    info = CrashInfo()
    info.is_crash = is_real_crash(output)

    # ExceptionCode 추출 (예외 종류 판별용)
    info.exception_code, info.exception_type = extract_exception_code(output)

    # 1. g; 이전 AV 덤프에서 primary crash point + assembly 추출
    cp_first, asm = extract_first_av_info(output)
    info.faulting_instruction = asm

    # 범용 예외 함수 필터링 (KERNELBASE!RaiseException 등)
    if cp_first:
        func_part = cp_first.rsplit('+', 1)[0]
        if func_part in GENERIC_EXCEPTION_FUNCS:
            cp_first = ''  # 범용 함수 → fallback으로 전환

    # 2. ExceptionAddress 추출 (.exr -1 / !analyze -v)
    exc_addr = extract_exception_address(output)

    # ExceptionAddress도 범용 예외 함수 필터링
    # .ecxr 실패 시 ExceptionAddress가 KERNELBASE!RaiseException을 가리킬 수 있음
    if exc_addr:
        func_part = exc_addr.rsplit('+', 1)[0]
        if func_part in GENERIC_EXCEPTION_FUNCS:
            exc_addr = ''

    # 3. kn 스택에서 deferred crash point 추출
    found_marker = False
    all_matches = []

    for line in output.splitlines():
        if not found_marker:
            if STACK_MARKER in line or STACK_MARKER_X64 in line:
                found_marker = True
            continue

        # 마커 이후의 모든 module!func+offset 패턴 수집
        for match in SIGNATURE_PATTERN.findall(line):
            all_matches.append(normalize_signature(match))

    info.has_stack_trace = found_marker
    info.all_signatures = all_matches

    # kn frame 00 = deferred crash point
    if all_matches:
        info.deferred_signature = all_matches[0]

    # 4. Primary signature 결정 (우선순위: g;이전 → ExcAddr → kn)
    if cp_first:
        info.signature = cp_first
    elif exc_addr:
        info.signature = exc_addr
    elif all_matches:
        # kn fallback: 범용 예외 함수 프레임을 건너뛰고 첫 실제 크래시 프레임 선택
        non_generic = [s for s in all_matches
                       if s.rsplit('+', 1)[0] not in GENERIC_EXCEPTION_FUNCS]
        if strategy == 'first':
            info.signature = non_generic[0] if non_generic else all_matches[0]
        else:
            info.signature = non_generic[-1] if non_generic else all_matches[-1]
    else:
        info.signature = 'UNKNOWN'

    # 5. 불일치 감지 (primary vs kn frame 00)
    # deferred_signature가 범용 예외 함수면 비교 무의미 (필터링 결과 차이일 뿐)
    deferred_func = info.deferred_signature.rsplit('+', 1)[0] if '+' in info.deferred_signature else ''
    if (info.signature != 'UNKNOWN' and info.deferred_signature != 'UNKNOWN'
            and info.signature != info.deferred_signature
            and deferred_func not in GENERIC_EXCEPTION_FUNCS):
        info.signature_mismatch = True

    return info


def get_crash_folder_name(signature: str) -> str:
    """
    시그니처를 폴더명으로 사용할 수 있는 형식으로 변환한다.
    '!'와 ':'를 '_'로 대체한다.

    예: "HncFilter!CFilter::Parse+0x1234" → "HncFilter_CFilter__Parse+0x1234"

    Args:
        signature: module!function+offset 형식 시그니처

    Returns:
        파일시스템 안전한 폴더명
    """
    return signature.replace('!', '_').replace(':', '_')
