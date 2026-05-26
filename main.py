"""
main.py — 파이프라인 오케스트레이터
5단계를 순서대로 실행하고 결과를 취합합니다.

사용법:
  # 로컬 샘플 파일로 빠른 테스트
  python main.py --mode sample

  # 로컬 Git 저장소 diff 분석
  python main.py --mode local --repo-path . --base-branch main

  # GitHub PR 분석
  python main.py --mode pr --repo owner/repo --pr 42
"""

import argparse
import sys
import os
from dotenv import load_dotenv
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

load_dotenv()
console = Console()


def run_pipeline(
    mode: str,
    local_repo_path: str = ".",
    repo_name: str = "",
    pr_number: int | None = None,
    base_branch: str = "main",
) -> None:

    from agents.collector import collect_from_pr, collect_from_local, create_sample_file
    from agents.dependency_validator import validate_dependencies
    from agents.security_analyzer import analyze_files
    from agents.self_corrector import run_self_correction
    from agents.reporter import (
        print_terminal_report,
        post_pr_comment,
        post_inline_comments,
        create_github_issues,
    )
    from models import AuditResult

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:

        # ── 1단계: 코드 수집 ─────────────────────────────────────────────────
        task = progress.add_task("1단계: 코드 수집 중...", total=None)

        if mode == "sample":
            collection = create_sample_file()
            console.print("[yellow]샘플 취약 파일로 테스트합니다[/yellow]")
        elif mode == "local":
            collection = collect_from_local(local_repo_path, base_branch)
        elif mode == "pr":
            collection = collect_from_pr(repo_name, pr_number)
        else:
            console.print(f"[red]알 수 없는 모드: {mode}[/red]")
            sys.exit(1)

        progress.update(
            task,
            description=f"✅ 1단계(코드 수집) 완료 — {len(collection.files)}개 파일 수집",
        )

        if not collection.files:
            console.print(
                "[yellow]분석할 파일이 없습니다. 지원 확장자: .py .js .ts .java .go[/yellow]"
            )
            return

        # ── 2단계: 의존성 검증 (LLM 불필요) ────────────────────────────────
        task2 = progress.add_task(
            "2단계: 의존성 검증 중 (OSV / PyPI / npm)...", total=None
        )
        dep_risks = validate_dependencies(collection.files)
        progress.update(
            task2,
            description=f"✅ 2단계(의존성 검증) 완료 — {len(dep_risks)}개 의존성 위험 발견",
        )

        # ── 3단계: LLM 보안 분석 ─────────────────────────────────────────────
        backend = os.getenv("LLM_BACKEND", "ollama")
        model = os.getenv(
            "OLLAMA_MODEL" if backend == "ollama" else "CLAUDE_MODEL", "gemma4:e4b"
        )
        task3 = progress.add_task(
            f"3단계: LLM 보안 분석 중 [{backend} / {model}]...", total=None
        )
        vulnerabilities = analyze_files(collection.files)
        progress.update(
            task3,
            description=f"✅ 3단계(LLM 보안 분석) 완료 — {len(vulnerabilities)}개 취약점 초안",
        )

        # ── 4단계: 자기 수정 루프 ────────────────────────────────────────────
        task4 = progress.add_task("4단계: 자기 수정 루프 실행 중...", total=None)
        file_contents = {f.path: f.content for f in collection.files}
        vulnerabilities, correction_count = run_self_correction(
            vulnerabilities, file_contents
        )
        final_count = sum(1 for v in vulnerabilities if not v.is_false_positive)
        progress.update(
            task4,
            description=f"✅ 4단계(자기 수정) 완료 — {correction_count}회 재검토, {final_count}개 최종 확정",
        )

        # ── 5단계: 리포트 생성 ───────────────────────────────────────────────
        task5 = progress.add_task("5단계: 리포트 생성 중...", total=None)

        result = AuditResult(
            repo=collection.repo,
            pr_number=collection.pr_number,
            commit_sha=collection.commit_sha,
            files_analyzed=len(collection.files),
            dependency_risks=dep_risks,
            vulnerabilities=vulnerabilities,
            self_correction_count=correction_count,
        )
        progress.update(task5, description="✅ 5단계(리포트 생성) 완료 — 리포트 생성")

    # ── 출력 ──────────────────────────────────────────────────────────────────
    print_terminal_report(result)

    report_mode = os.getenv("REPORT_MODE", "terminal")
    if report_mode in ("pr_comment", "both") and result.pr_number:
        console.print("[dim]GitHub PR 코멘트 등록 중...[/dim]")
        post_pr_comment(result)
        post_inline_comments(result)

    if report_mode in ("github_issue", "both") and result.critical_count > 0:
        console.print("[dim]Critical 이슈 GitHub에 등록 중...[/dim]")
        create_github_issues(result)

    # 종료 코드: CI에서 Critical 발견 시 빌드 실패 처리
    if result.critical_count > 0:
        console.print(
            f"\n[red bold]🔴 Critical 취약점 {result.critical_count}개 — CI 실패 처리[/red bold]"
        )
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="AI 생성 코드 보안 감사 에이전트")
    parser.add_argument("--mode", choices=["sample", "local", "pr"], default="sample")
    parser.add_argument("--local-repo-path", default=".", help="로컬 Git 저장소 경로")
    parser.add_argument("--base-branch", default="main")
    parser.add_argument("--repo", default="", help="GitHub 저장소 (owner/repo)")
    parser.add_argument("--pr", type=int, help="PR 번호")
    args = parser.parse_args()

    console.print("\n[bold blue]🛡️  AI 코드 보안 감사 에이전트[/bold blue]\n")
    run_pipeline(
        mode=args.mode,
        local_repo_path=args.local_repo_path,
        repo_name=args.repo,
        pr_number=args.pr,
        base_branch=args.base_branch,
    )


if __name__ == "__main__":
    main()
