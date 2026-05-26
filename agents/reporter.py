"""
agents/reporter.py — 5단계: 리포트 생성 및 GitHub 등록
PR 코멘트 인라인 등록 / Critical은 별도 Issue 생성
"""
from __future__ import annotations
import os
from datetime import datetime
from github import Github
from dotenv import load_dotenv
from models import AuditResult, Severity, Vulnerability, DependencyRisk

load_dotenv()

SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH:     "🟠",
    Severity.MEDIUM:   "🟡",
    Severity.LOW:      "🔵",
    Severity.INFO:     "⚪",
}


# ── 마크다운 리포트 생성 ──────────────────────────────────────────────────────

def build_markdown_report(result: AuditResult) -> str:
    """PR 코멘트 또는 터미널 출력용 마크다운"""
    vulns   = result.filtered_vulns
    deps    = result.dependency_risks
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        "## 🛡️ AI 코드 보안 감사 리포트",
        f"**커밋:** `{result.commit_sha[:8]}`  |  **분석:** {now_str}",
        f"**파일:** {result.files_analyzed}개 분석  |  "
        f"**자기수정 루프:** {result.self_correction_count}회",
        "",
    ]

    # ── 요약 뱃지 ──
    critical = result.critical_count
    high     = result.high_count
    summary_parts = []
    if critical: summary_parts.append(f"🔴 Critical: **{critical}**")
    if high:     summary_parts.append(f"🟠 High: **{high}**")
    medium = sum(1 for v in vulns if v.severity == Severity.MEDIUM)
    if medium:   summary_parts.append(f"🟡 Medium: **{medium}**")

    if not vulns and not deps:
        lines.append("✅ **취약점이 발견되지 않았습니다.**")
        return "\n".join(lines)

    lines.append("### 요약")
    lines.append("  ".join(summary_parts) if summary_parts else "취약점 없음")
    lines.append("")

    # ── 의존성 위험 ──
    if deps:
        lines.append("### 📦 의존성 위험")
        lines.append("| 패키지 | 생태계 | 존재 여부 | CVE | 위험 이유 |")
        lines.append("|--------|--------|-----------|-----|-----------|")
        for d in deps:
            exists_icon = "✅" if d.exists else "❌"
            cves = ", ".join(d.cve_ids[:3]) if d.cve_ids else "-"
            reason = d.risk_reason or "-"
            lines.append(f"| `{d.package_name}` | {d.ecosystem} | {exists_icon} | {cves} | {reason} |")
        lines.append("")

    # ── 취약점 상세 ──
    if vulns:
        lines.append("### 🔍 취약점 상세")
        for i, v in enumerate(sorted(vulns, key=lambda x: list(Severity).index(x.severity)), 1):
            emoji = SEVERITY_EMOJI[v.severity]
            lines.append(f"#### {emoji} [{v.severity.value.upper()}] {v.owasp_category.value}")
            lines.append(f"**파일:** `{v.file_path}`" + (f" (라인 {v.line_number})" if v.line_number else ""))
            lines.append(f"**신뢰도:** {v.confidence:.0%}")
            lines.append(f"> {v.description}")
            if v.code_snippet:
                lines.append(f"\n```python\n{v.code_snippet}\n```")
            lines.append(f"**수정 방법:** {v.recommendation}")
            lines.append("")

    lines.append("---")
    lines.append("*AI 코드 보안 감사 에이전트 | Ollama/Claude 기반*")
    return "\n".join(lines)


# ── 터미널 출력 ───────────────────────────────────────────────────────────────

def print_terminal_report(result: AuditResult) -> None:
    """rich 라이브러리를 활용한 컬러 터미널 출력"""
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        from rich import box

        console = Console()
        md = build_markdown_report(result)
        console.print(Panel(md, title="보안 감사 결과", border_style="blue"))

    except ImportError:
        print(build_markdown_report(result))


# ── GitHub PR 코멘트 등록 ─────────────────────────────────────────────────────

def post_pr_comment(result: AuditResult) -> None:
    """PR에 전체 리포트를 코멘트로 등록"""
    if not result.pr_number:
        return
    g    = Github(os.getenv("GITHUB_TOKEN"))
    repo = g.get_repo(result.repo)
    pr   = repo.get_pull(result.pr_number)

    # 기존 봇 코멘트 업데이트 (중복 방지)
    bot_header = "## 🛡️ AI 코드 보안 감사 리포트"
    for comment in pr.get_issue_comments():
        if bot_header in comment.body:
            comment.edit(build_markdown_report(result))
            return

    pr.create_issue_comment(build_markdown_report(result))


def post_inline_comments(result: AuditResult) -> None:
    """파일 라인 단위 인라인 코멘트 등록 (Critical/High만)"""
    if not result.pr_number:
        return
    g    = Github(os.getenv("GITHUB_TOKEN"))
    repo = g.get_repo(result.repo)
    pr   = repo.get_pull(result.pr_number)
    commit = repo.get_commit(result.commit_sha)

    for v in result.filtered_vulns:
        if v.severity not in (Severity.CRITICAL, Severity.HIGH):
            continue
        if not v.line_number:
            continue
        try:
            emoji = SEVERITY_EMOJI[v.severity]
            body = (
                f"{emoji} **{v.severity.value.upper()}** — {v.owasp_category.value}\n\n"
                f"{v.description}\n\n"
                f"**수정:** {v.recommendation}"
            )
            pr.create_review_comment(
                body=body,
                commit=commit,
                path=v.file_path,
                line=v.line_number,
            )
        except Exception:
            pass   # 라인 번호 불일치 등 무시


def create_github_issues(result: AuditResult) -> None:
    """Critical 취약점은 별도 GitHub Issue로 생성"""
    g    = Github(os.getenv("GITHUB_TOKEN"))
    repo = g.get_repo(result.repo)

    for v in result.filtered_vulns:
        if v.severity != Severity.CRITICAL:
            continue
        title = f"[CRITICAL] {v.owasp_category.value} in {v.file_path}"
        body  = (
            f"## 🔴 Critical 보안 취약점\n\n"
            f"**파일:** `{v.file_path}`\n"
            f"**카테고리:** {v.owasp_category.value}\n"
            f"**신뢰도:** {v.confidence:.0%}\n\n"
            f"### 설명\n{v.description}\n\n"
            f"### 수정 방법\n{v.recommendation}\n\n"
            f"**자동 감지 — 커밋:** `{result.commit_sha[:8]}`"
        )
        repo.create_issue(
            title=title,
            body=body,
            labels=["security", "critical"],
        )
