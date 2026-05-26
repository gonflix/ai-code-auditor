"""
models.py — 파이프라인 전체에서 공유하는 데이터 모델
"""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class OwaspCategory(str, Enum):
    A01_BROKEN_ACCESS = "A01:BrokenAccessControl"
    A02_MISCONFIG = "A02:SecurityMisconfiguration"
    A03_SUPPLY_CHAIN = "A03:SoftwareSupplyChainFailures"
    A04_CRYPTO = "A04:CryptographicFailures"
    A05_INJECTION = "A05:Injection"
    A06_INSECURE_DESIGN = "A06:InsecureDesign"
    A07_AUTH_FAILURE = "A07:AuthenticationFailures"
    A08_INTEGRITY = "A08:SoftwareDataIntegrityFailures"
    A09_LOGGING = "A09:SecurityLoggingFailures"
    A10_EXCEPTIONAL = "A10:ExceptionalConditions"
    SLOPSQUATTING = "SlopsquattingRisk"
    HARDCODED_SECRET = "HardcodedSecret"
    OTHER = "Other"


class Vulnerability(BaseModel):
    """단일 취약점 항목"""

    owasp_category: OwaspCategory
    severity: Severity
    file_path: str
    line_number: Optional[int] = None
    description: str
    code_snippet: Optional[str] = None
    recommendation: str
    confidence: float = Field(ge=0.0, le=1.0, description="0~1 신뢰도")
    is_false_positive: bool = False


class DependencyRisk(BaseModel):
    """의존성 검증 결과"""

    package_name: str
    ecosystem: str  # "pypi" | "npm"
    exists: bool
    cve_ids: list[str] = []
    is_slopsquatting_risk: bool = False
    risk_reason: Optional[str] = None


class AuditResult(BaseModel):
    """파이프라인 최종 결과"""

    repo: str
    pr_number: Optional[int] = None
    commit_sha: str
    files_analyzed: int
    dependency_risks: list[DependencyRisk] = []
    vulnerabilities: list[Vulnerability] = []
    self_correction_count: int = 0

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.HIGH)

    @property
    def filtered_vulns(self) -> list[Vulnerability]:
        """오탐 제거된 최종 취약점 목록"""
        return [v for v in self.vulnerabilities if not v.is_false_positive]
