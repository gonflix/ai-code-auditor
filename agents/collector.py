"""
agents/collector.py — 1단계: 코드 수집
GitHub PR diff 또는 로컬 Git diff에서 변경 파일을 추출합니다.
"""

from __future__ import annotations
import os
import tempfile

# import re
from dataclasses import dataclass, field
from github import Github
from dotenv import load_dotenv

load_dotenv()

SUPPORTED_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".java",
    ".go",
    ".rb",
    ".php",
    ".cs",
}


@dataclass
class ChangedFile:
    path: str
    content: str
    patch: str  # diff 텍스트
    additions: int = 0
    deletions: int = 0


@dataclass
class CollectionResult:
    repo: str
    pr_number: int | None
    commit_sha: str
    files: list[ChangedFile] = field(default_factory=list)


# ── GitHub PR에서 수집 ────────────────────────────────────────────────────────


def collect_from_pr(repo_name: str, pr_number: int) -> CollectionResult:
    """
    GitHub PR의 변경 파일만 추출.
    전체 코드베이스가 아닌 diff만 가져오므로 토큰 절약.
    """
    g = Github(os.getenv("GITHUB_TOKEN"))
    repo = g.get_repo(repo_name)
    pr = repo.get_pull(pr_number)

    result = CollectionResult(
        repo=repo_name,
        pr_number=pr_number,
        commit_sha=pr.head.sha,
    )

    for file in pr.get_files():
        ext = os.path.splitext(file.filename)[1].lower()
        if ext not in SUPPORTED_EXTENSIONS:
            continue
        if file.status == "removed":
            continue

        # 파일 전체 내용 가져오기 (분석용)
        try:
            content_obj = repo.get_contents(file.filename, ref=pr.head.sha)
            content = content_obj.decoded_content.decode("utf-8", errors="replace")
        except Exception:
            content = ""

        result.files.append(
            ChangedFile(
                path=file.filename,
                content=content,
                patch=file.patch or "",
                additions=file.additions,
                deletions=file.deletions,
            )
        )

    return result


# ── 로컬 Git diff에서 수집 (테스트용) ────────────────────────────────────────


def collect_from_local(
    repo_path: str = ".", base_branch: str = "main"
) -> CollectionResult:
    """
    로컬 git diff HEAD...<base_branch> 를 파싱.
    GitHub 연결 없이 테스트 가능.
    """
    import git

    repo = git.Repo(repo_path)
    diff = repo.git.diff(f"{base_branch}...HEAD", "--name-only")
    changed_files = [f for f in diff.splitlines() if f]

    files = []
    for path in changed_files:
        ext = os.path.splitext(path)[1].lower()
        if ext not in SUPPORTED_EXTENSIONS:
            continue
        full_path = os.path.join(repo_path, path)
        if not os.path.exists(full_path):
            continue
        with open(full_path, encoding="utf-8", errors="replace") as f:
            content = f.read()
        patch = repo.git.diff(f"{base_branch}...HEAD", "--", path)
        files.append(ChangedFile(path=path, content=content, patch=patch))

    return CollectionResult(
        repo=repo_path,
        pr_number=None,
        commit_sha=repo.head.commit.hexsha,
        files=files,
    )


# ── 테스트용: 취약한 샘플 파일 생성 ──────────────────────────────────────────

SAMPLE_VULNERABLE_CODE = """
import sqlite3
import requests
import subprocess
import hashlib

def get_user(username):
    conn = sqlite3.connect("users.db")
    query = f"SELECT * FROM users WHERE name = '{username}'"
    return conn.execute(query).fetchall()

SECRET_KEY = "super_secret_password_123"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

def run_report(report_name):
    subprocess.call(f"python reports/{report_name}.py", shell=True)

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest() 

import torchvison   
import langchaiin    
"""


def create_sample_file(path: str = "") -> CollectionResult:
    """파이프라인 전체 테스트용 샘플 생성"""
    if not path:
        path = os.path.join(tempfile.gettempdir(), "sample_vulnerable.py")
    with open(path, "w", encoding="utf-8") as f:
        f.write(SAMPLE_VULNERABLE_CODE)
    return CollectionResult(
        repo="local/test",
        pr_number=None,
        commit_sha="abc1234",
        files=[
            ChangedFile(
                path=path,
                content=SAMPLE_VULNERABLE_CODE,
                patch=SAMPLE_VULNERABLE_CODE,
            )
        ],
    )
