"""
agents/security_analyzer.py — 3단계: LLM 보안 분석
OWASP Top 10 기준으로 취약점을 탐지합니다.
Ollama(로컬) 또는 Claude API를 투명하게 사용합니다.
"""

from __future__ import annotations
import json
from models import Vulnerability, Severity, OwaspCategory
from llm_client import chat_json
from agents.collector import ChangedFile

# ── 시스템 프롬프트 ────────────────────────────────────────────────────────────
# 체크리스트를 시스템 프롬프트에 고정 → 프롬프트 캐싱 효과 (Claude API 시 90% 절감)

SYSTEM_PROMPT = """You are a senior application security engineer specializing in code review.
Analyze the provided code for security vulnerabilities based on OWASP Top 10 2025.

Focus on these vulnerability categories:
- A01: Broken Access Control (missing auth checks, IDOR, privilege escalation, SSRF — SSRF is merged into A01 in 2025)
- A02: Security Misconfiguration (debug mode, default creds, overly permissive CORS, exposed config)
- A03: Software Supply Chain Failures (typosquatted packages, malicious deps, compromised build tools)
- A04: Cryptographic Failures (hardcoded secrets, weak algorithms like MD5/SHA1, plaintext sensitive data)
- A05: Injection (SQL, command, LDAP, XPath injection via string concatenation or f-strings)
- A06: Insecure Design (missing rate limiting, business logic flaws, lack of threat modeling)
- A07: Authentication Failures (broken session management, weak passwords allowed, no MFA enforcement)
- A08: Software or Data Integrity Failures (unsafe deserialization, untrusted code execution, CI/CD bypass)
- A09: Security Logging and Alerting Failures (no logging on sensitive operations, insufficient audit trail)
- A10: Mishandling of Exceptional Conditions (bare except, swallowed exceptions, info disclosure via error messages)
- HardcodedSecret: API keys, passwords, tokens hardcoded in source

For each finding, you MUST provide:
1. The exact OWASP category from the list above
2. Severity: critical | high | medium | low | info
3. The specific file path and line number
4. A clear description of WHY this is a vulnerability
5. A concrete fix recommendation
6. Confidence score 0.0-1.0 (be conservative: only high confidence for clear, exploitable issues)

Return a JSON array of vulnerability objects. If no vulnerabilities found, return [].
"""

USER_TEMPLATE = """Analyze this file for security vulnerabilities:

File: {file_path}
Language: {language}

```
{code}
```

Return JSON array with this exact schema:
[
  {{
    "owasp_category": "A05:Injection",
    "severity": "high",
    "file_path": "{file_path}",
    "line_number": 42,
    "description": "SQL query built with f-string allows injection",
    "code_snippet": "query = f\\"SELECT * FROM users WHERE name = '{{username}}\\"",
    "recommendation": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE name = ?', (username,))",
    "confidence": 0.95
  }}
]"""

OWASP_MAP = {
    "A01:BrokenAccessControl": OwaspCategory.A01_BROKEN_ACCESS,
    "A02:SecurityMisconfiguration": OwaspCategory.A02_MISCONFIG,
    "A03:SoftwareSupplyChainFailures": OwaspCategory.A03_SUPPLY_CHAIN,
    "A04:CryptographicFailures": OwaspCategory.A04_CRYPTO,
    "A05:Injection": OwaspCategory.A05_INJECTION,
    "A06:InsecureDesign": OwaspCategory.A06_INSECURE_DESIGN,
    "A07:AuthenticationFailures": OwaspCategory.A07_AUTH_FAILURE,
    "A08:SoftwareDataIntegrityFailures": OwaspCategory.A08_INTEGRITY,
    "A09:SecurityLoggingFailures": OwaspCategory.A09_LOGGING,
    "A10:ExceptionalConditions": OwaspCategory.A10_EXCEPTIONAL,
    "HardcodedSecret": OwaspCategory.HARDCODED_SECRET,
}

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

EXT_TO_LANG = {
    ".py": "Python",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".jsx": "React/JSX",
    ".tsx": "React/TSX",
    ".java": "Java",
    ".go": "Go",
    ".rb": "Ruby",
    ".php": "PHP",
    ".cs": "C#",
}


def _parse_vulns(raw: dict | list, file_path: str) -> list[Vulnerability]:
    """LLM 응답 JSON → Vulnerability 객체 리스트 변환"""
    items = raw if isinstance(raw, list) else raw.get("vulnerabilities", [])
    result = []
    for item in items:
        if not isinstance(item, dict):
            continue
        try:
            owasp_raw = item.get("owasp_category", "Other")
            owasp = OWASP_MAP.get(owasp_raw, OwaspCategory.OTHER)
            severity = SEVERITY_MAP.get(
                item.get("severity", "medium").lower(), Severity.MEDIUM
            )
            result.append(
                Vulnerability(
                    owasp_category=owasp,
                    severity=severity,
                    file_path=item.get("file_path", file_path),
                    line_number=item.get("line_number"),
                    description=item.get("description", ""),
                    code_snippet=item.get("code_snippet"),
                    recommendation=item.get("recommendation", ""),
                    confidence=float(item.get("confidence", 0.5)),
                )
            )
        except Exception:
            continue
    return result


def analyze_file(file: ChangedFile) -> list[Vulnerability]:
    """단일 파일 분석. 500줄 초과 시 청크로 분할."""
    ext = "." + file.path.split(".")[-1].lower()
    lang = EXT_TO_LANG.get(ext, "Unknown")

    lines = file.content.splitlines()

    # 500줄 초과 시 청크 분할 (토큰 제한 대응)
    CHUNK_SIZE = 500
    all_vulns: list[Vulnerability] = []

    for start in range(0, max(len(lines), 1), CHUNK_SIZE):
        chunk = "\n".join(lines[start : start + CHUNK_SIZE])
        user_msg = USER_TEMPLATE.format(
            file_path=file.path,
            language=lang,
            code=chunk[:8000],  # 8000자 상한
        )
        raw = chat_json(SYSTEM_PROMPT, user_msg)
        all_vulns.extend(_parse_vulns(raw, file.path))

    return all_vulns


def analyze_files(files: list[ChangedFile]) -> list[Vulnerability]:
    """여러 파일 순차 분석"""
    all_vulns = []
    for file in files:
        vulns = analyze_file(file)
        all_vulns.extend(vulns)
    return all_vulns
