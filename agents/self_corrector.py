"""
agents/self_corrector.py — 4단계: 자기 수정 루프
포트폴리오 핵심 차별화 포인트.

동작:
  1. 3단계 결과를 검토 에이전트가 재평가
  2. 신뢰도 MIN_CONFIDENCE 미만 → is_false_positive = True
  3. 경계값(0.6~0.8) 항목 → LLM에 재질문 (최대 MAX_RETRIES회)
  4. 최종 신뢰도 점수 업데이트
"""
from __future__ import annotations
import os
from dotenv import load_dotenv
from models import Vulnerability, Severity
from llm_client import chat_json

load_dotenv()

MIN_CONFIDENCE = float(os.getenv("MIN_CONFIDENCE", 0.7))
MAX_RETRIES    = int(os.getenv("MAX_RETRIES", 2))
RETRY_THRESHOLD = 0.6   # 이 값 이상이면 재검토 대상


REVIEWER_SYSTEM = """You are a security code reviewer validating findings from another AI analyzer.
Your job: determine if each reported vulnerability is a TRUE POSITIVE or FALSE POSITIVE.

Be skeptical. Common false positives:
- MD5 used for non-security purposes (checksums, cache keys) → not a vulnerability
- Hardcoded values that are clearly not secrets (empty strings, placeholders like 'your_key_here')
- SQL queries that use parameterized inputs correctly despite complex structure
- subprocess calls with fully controlled, non-user-derived inputs
- Logging of non-sensitive data flagged as "insufficient logging"

Return JSON with updated confidence and false_positive verdict for each finding."""

REVIEWER_TEMPLATE = """Review this security finding and determine if it is a true vulnerability.

Finding:
- Category: {category}
- Severity: {severity}
- Description: {description}
- Code snippet: {snippet}
- Original confidence: {confidence}

Context (surrounding code):
```
{context}
```

Return JSON:
{{
  "is_false_positive": false,
  "confidence": 0.92,
  "reasoning": "This is a genuine SQL injection because user input flows directly into the query string"
}}"""


def _should_retry(vuln: Vulnerability) -> bool:
    """신뢰도가 경계값에 있는 항목만 재검토"""
    return RETRY_THRESHOLD <= vuln.confidence < MIN_CONFIDENCE


def _review_single(vuln: Vulnerability, context: str = "") -> Vulnerability:
    """단일 취약점 재검토"""
    user_msg = REVIEWER_TEMPLATE.format(
        category   = vuln.owasp_category.value,
        severity   = vuln.severity.value,
        description= vuln.description,
        snippet    = vuln.code_snippet or "(no snippet)",
        confidence = vuln.confidence,
        context    = context[:2000],
    )
    result = chat_json(REVIEWER_SYSTEM, user_msg)

    if result:
        vuln.confidence       = float(result.get("confidence", vuln.confidence))
        vuln.is_false_positive = bool(result.get("is_false_positive", False))

    return vuln


def run_self_correction(
    vulnerabilities: list[Vulnerability],
    file_contents: dict[str, str],   # {file_path: content}
) -> tuple[list[Vulnerability], int]:
    """
    자기 수정 루프 실행.
    반환: (수정된 취약점 리스트, 재검토 횟수)
    """
    correction_count = 0

    for vuln in vulnerabilities:
        # 즉시 필터링: 신뢰도가 너무 낮으면 재검토 없이 오탐 처리
        if vuln.confidence < RETRY_THRESHOLD:
            vuln.is_false_positive = True
            continue

        # 확실한 건 그대로 통과
        if vuln.confidence >= MIN_CONFIDENCE:
            continue

        # 경계값 항목 재검토 (최대 MAX_RETRIES회)
        for attempt in range(MAX_RETRIES):
            context = file_contents.get(vuln.file_path, "")
            vuln    = _review_single(vuln, context)
            correction_count += 1

            # 재검토 후 확정되면 루프 종료
            if vuln.confidence >= MIN_CONFIDENCE or vuln.is_false_positive:
                break

        # 재검토 후에도 불확실하면 보수적으로 오탐 처리
        if vuln.confidence < MIN_CONFIDENCE:
            vuln.is_false_positive = True

    # Critical/High는 신뢰도가 낮아도 한 번 더 확인 (놓치면 안 됨)
    critical_false_positives = [
        v for v in vulnerabilities
        if v.is_false_positive and v.severity in (Severity.CRITICAL, Severity.HIGH)
    ]
    for vuln in critical_false_positives:
        context = file_contents.get(vuln.file_path, "")
        reviewed = _review_single(vuln, context)
        correction_count += 1
        # 재검토에서 진짜라고 판정되면 오탐 해제
        if not reviewed.is_false_positive and reviewed.confidence >= MIN_CONFIDENCE:
            vuln.is_false_positive = False
            vuln.confidence = reviewed.confidence

    return vulnerabilities, correction_count
