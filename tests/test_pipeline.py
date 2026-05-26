"""
tests/test_pipeline.py — 파이프라인 단계별 단위 테스트
Ollama 없이도 실행 가능한 mock 테스트 포함
"""

import sys, os
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import unittest
from unittest.mock import patch, MagicMock
from models import Vulnerability, Severity, OwaspCategory, DependencyRisk
from agents.collector import ChangedFile, create_sample_file, SAMPLE_VULNERABLE_CODE
from agents.dependency_validator import (
    extract_python_imports,
    extract_npm_imports,
    TYPOSQUAT_MAP,
)


class TestCollector(unittest.TestCase):

    def test_sample_file_creation(self):
        result = create_sample_file(os.path.join(tempfile.gettempdir(), "test_vuln.py"))
        self.assertEqual(len(result.files), 1)
        self.assertIn("sqlite3", result.files[0].content)

    def test_supported_extensions(self):
        from agents.collector import SUPPORTED_EXTENSIONS

        self.assertIn(".py", SUPPORTED_EXTENSIONS)
        self.assertIn(".ts", SUPPORTED_EXTENSIONS)
        self.assertNotIn(".html", SUPPORTED_EXTENSIONS)


class TestDependencyValidator(unittest.TestCase):

    def test_python_import_extraction(self):
        code = """
import requests
from flask import Flask
import os
import numpy as np
"""
        pkgs = extract_python_imports(code)
        self.assertIn("requests", pkgs)
        self.assertIn("flask", pkgs)
        self.assertIn("numpy", pkgs)
        self.assertNotIn("os", pkgs)  # 표준 라이브러리 제외

    def test_npm_import_extraction(self):
        code = """
const express = require('express')
import React from 'react'
import { useState } from 'react'
import axios from 'axios'
"""
        pkgs = extract_npm_imports(code)
        self.assertIn("express", pkgs)
        self.assertIn("axios", pkgs)

    def test_typosquat_detection(self):
        self.assertIn("langchian", TYPOSQUAT_MAP)
        self.assertIn("torchvison", TYPOSQUAT_MAP)
        self.assertEqual(TYPOSQUAT_MAP["langchian"], "langchain")

    def test_sample_has_slopsquat_risks(self):
        """샘플 코드에 슬롭스쿼팅 위험 패키지가 포함되어 있는지"""
        pkgs = extract_python_imports(SAMPLE_VULNERABLE_CODE)
        risky = [p for p in pkgs if p in TYPOSQUAT_MAP]
        self.assertGreater(len(risky), 0, "샘플에 슬롭스쿼팅 패키지가 있어야 함")


class TestSecurityAnalyzerMock(unittest.TestCase):
    """LLM 없이 파서 로직만 테스트"""

    def test_parse_vulns(self):
        from agents.security_analyzer import _parse_vulns

        raw = [
            {
                "owasp_category": "A05:Injection",
                "severity": "high",
                "file_path": "app.py",
                "line_number": 10,
                "description": "SQL Injection via f-string",
                "code_snippet": "query = f\"SELECT * FROM users WHERE name = '{username}'\"",
                "recommendation": "Use parameterized queries",
                "confidence": 0.95,
            }
        ]
        vulns = _parse_vulns(raw, "app.py")
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0].severity, Severity.HIGH)
        self.assertEqual(vulns[0].owasp_category, OwaspCategory.A05_INJECTION)
        self.assertAlmostEqual(vulns[0].confidence, 0.95)


class TestSelfCorrectorLogic(unittest.TestCase):
    """자기 수정 루프 필터링 로직 테스트 (LLM mock)"""

    def _make_vuln(self, confidence: float, severity=Severity.MEDIUM) -> Vulnerability:
        return Vulnerability(
            owasp_category=OwaspCategory.A05_INJECTION,
            severity=severity,
            file_path="app.py",
            description="Test",
            recommendation="Fix it",
            confidence=confidence,
        )

    def test_low_confidence_filtered(self):
        from agents.self_corrector import run_self_correction

        vuln = self._make_vuln(confidence=0.3)
        result, _ = run_self_correction([vuln], {})
        self.assertTrue(result[0].is_false_positive)

    def test_high_confidence_passes(self):
        from agents.self_corrector import run_self_correction

        vuln = self._make_vuln(confidence=0.95)
        # 신뢰도가 높으면 LLM 재검토 없이 통과
        result, count = run_self_correction([vuln], {})
        self.assertFalse(result[0].is_false_positive)
        self.assertEqual(count, 0)


class TestReporter(unittest.TestCase):

    def test_markdown_report_no_vulns(self):
        from agents.reporter import build_markdown_report
        from models import AuditResult

        result = AuditResult(
            repo="test/repo",
            commit_sha="abc1234",
            files_analyzed=3,
        )
        md = build_markdown_report(result)
        self.assertIn("취약점이 발견되지 않았습니다", md)

    def test_markdown_report_with_vulns(self):
        from agents.reporter import build_markdown_report
        from models import AuditResult

        vuln = Vulnerability(
            owasp_category=OwaspCategory.A05_INJECTION,
            severity=Severity.CRITICAL,
            file_path="app.py",
            line_number=42,
            description="SQL Injection",
            recommendation="Use parameterized queries",
            confidence=0.95,
        )
        result = AuditResult(
            repo="test/repo",
            commit_sha="abc1234",
            files_analyzed=1,
            vulnerabilities=[vuln],
        )
        md = build_markdown_report(result)
        self.assertIn("CRITICAL", md)
        self.assertIn("SQL Injection", md)
        self.assertIn("app.py", md)


if __name__ == "__main__":
    unittest.main(verbosity=2)
