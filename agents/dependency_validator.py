"""
agents/dependency_validator.py — 2단계: 의존성 검증
LLM 없이 순수 API 호출로 처리 → 비용 0원

수행 내용:
  1. 소스 코드에서 import 구문 파싱
  2. PyPI / npm 에 실제 존재하는지 확인 (슬롭스쿼팅 탐지)
  3. OSV API로 알려진 CVE 대조
"""

import re
import requests
from models import DependencyRisk
from agents.collector import ChangedFile

OSV_API = "https://api.osv.dev/v1/query"
PYPI_API = "https://pypi.org/pypi/{}/json"
NPM_API = "https://registry.npmjs.org/{}"

# 알려진 슬롭스쿼팅 오타 패턴 (실제 사례 기반)
KNOWN_TYPOSQUATS = {
    "tensorflow": ["tensorfow", "tensorflw", "tensroflow"],
    "langchain": ["langchian", "langchainn", "lanchain"],
    "torch": ["toch", "troch"],
    "torchvision": ["torchvison", "torchviosn"],
    "requests": ["requets", "reqeusts", "rquests"],
    "numpy": ["nump", "unmpy", "nnumpy"],
}
# 역방향 매핑: 오타 → 정상 패키지
TYPOSQUAT_MAP = {
    typo: correct for correct, typos in KNOWN_TYPOSQUATS.items() for typo in typos
}


# ── Import 파싱 ──────────────────────────────────────────────────────────────


def extract_python_imports(code: str) -> list[str]:
    """Python import 구문에서 패키지명 추출"""
    packages = set()
    # import X, from X import Y
    for m in re.finditer(r"^\s*(?:import|from)\s+([\w]+)", code, re.MULTILINE):
        pkg = m.group(1).split(".")[0]
        # 표준 라이브러리 제외 (간단한 필터)
        if pkg not in _STDLIB:
            packages.add(pkg)
    return list(packages)


def extract_npm_imports(code: str) -> list[str]:
    """JS/TS require / import 구문에서 패키지명 추출"""
    packages = set()
    patterns = [
        r'require\(["\']([^./][^"\']*)["\']',
        r'from\s+["\']([^./][^"\']*)["\']',
        r'import\s+["\']([^./][^"\']*)["\']',
    ]
    for p in patterns:
        for m in re.finditer(p, code):
            pkg = m.group(1).split("/")[0]  # @scope/pkg → @scope/pkg 유지
            packages.add(pkg)
    return list(packages)


# ── 존재 여부 확인 ────────────────────────────────────────────────────────────


def check_pypi(package: str) -> bool:
    try:
        r = requests.get(PYPI_API.format(package), timeout=5)
        return r.status_code == 200
    except Exception:
        return False


def check_npm(package: str) -> bool:
    try:
        r = requests.get(NPM_API.format(package), timeout=5)
        return r.status_code == 200
    except Exception:
        return False


# ── CVE 조회 ─────────────────────────────────────────────────────────────────


def query_osv(package: str, ecosystem: str) -> list[str]:
    """OSV API로 CVE 목록 반환. ecosystem: 'PyPI' | 'npm'"""
    try:
        resp = requests.post(
            OSV_API,
            json={"package": {"name": package, "ecosystem": ecosystem}},
            timeout=8,
        )
        data = resp.json()
        return [v["id"] for v in data.get("vulns", [])][:5]  # 최대 5개
    except Exception:
        return []


# ── 메인 검증 로직 ────────────────────────────────────────────────────────────


def validate_dependencies(files: list[ChangedFile]) -> list[DependencyRisk]:
    risks = []
    checked = set()  # 중복 제거

    for file in files:
        ext = file.path.split(".")[-1].lower()

        if ext == "py":
            packages = extract_python_imports(file.content)
            ecosystem = "PyPI"
            checker = check_pypi
        elif ext in ("js", "ts", "jsx", "tsx"):
            packages = extract_npm_imports(file.content)
            ecosystem = "npm"
            checker = check_npm
        else:
            continue

        for pkg in packages:
            key = f"{ecosystem}:{pkg}"
            if key in checked:
                continue
            checked.add(key)

            exists = checker(pkg)
            cve_ids = query_osv(pkg, ecosystem) if exists else []
            is_typo = pkg in TYPOSQUAT_MAP
            risk_reason = None

            if not exists:
                risk_reason = (
                    f"패키지 '{pkg}'가 {ecosystem}에 존재하지 않음 — 슬롭스쿼팅 위험"
                )
            elif is_typo:
                correct = TYPOSQUAT_MAP[pkg]
                risk_reason = (
                    f"'{pkg}'는 '{correct}'의 오타일 가능성 — 악성 패키지 설치 위험"
                )

            if not exists or is_typo or cve_ids:
                risks.append(
                    DependencyRisk(
                        package_name=pkg,
                        ecosystem=ecosystem,
                        exists=exists,
                        cve_ids=cve_ids,
                        is_slopsquatting_risk=not exists or is_typo,
                        risk_reason=risk_reason,
                    )
                )

    return risks


# ── 표준 라이브러리 목록 (간략) ──────────────────────────────────────────────
_STDLIB = {
    "os",
    "sys",
    "re",
    "json",
    "math",
    "time",
    "datetime",
    "collections",
    "itertools",
    "functools",
    "pathlib",
    "io",
    "abc",
    "copy",
    "enum",
    "typing",
    "dataclasses",
    "contextlib",
    "logging",
    "unittest",
    "hashlib",
    "hmac",
    "base64",
    "struct",
    "socket",
    "threading",
    "subprocess",
    "multiprocessing",
    "asyncio",
    "http",
    "urllib",
    "email",
    "html",
    "xml",
    "csv",
    "sqlite3",
    "random",
    "string",
    "textwrap",
    "traceback",
    "inspect",
    "importlib",
    "pkgutil",
    "warnings",
    "weakref",
    "gc",
}
