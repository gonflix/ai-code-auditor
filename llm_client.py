"""
llm_client.py — Ollama(로컬) / Claude API 전환 래퍼
환경변수 LLM_BACKEND 값 하나로 전환됩니다.
"""

from __future__ import annotations
import os
import json
from dotenv import load_dotenv

load_dotenv()

BACKEND = os.getenv("LLM_BACKEND", "ollama")


def _build_ollama_client():
    from openai import OpenAI

    return OpenAI(
        base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1"),
        api_key="ollama",  # Ollama는 키 불필요 — 아무 문자열
    )


def _build_claude_client():
    import anthropic

    return anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))


def chat(system: str, user: str, temperature: float = 0.1) -> str:
    """
    단일 진입점. BACKEND에 따라 Ollama 또는 Claude를 투명하게 호출.
    항상 str 반환.
    """
    if BACKEND == "claude":
        client = _build_claude_client()
        model = os.getenv("CLAUDE_MODEL", "claude-haiku-4-5-20251001")
        msg = client.messages.create(
            model=model,
            max_tokens=2048,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return msg.content[0].text

    else:  # ollama (default)
        client = _build_ollama_client()
        model = os.getenv("OLLAMA_MODEL", "gemma4:e4b")
        resp = client.chat.completions.create(
            model=model,
            temperature=temperature,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        return resp.choices[0].message.content


def chat_json(system: str, user: str) -> dict:
    """JSON 응답이 필요한 단계에서 사용. 파싱 실패 시 빈 dict 반환."""
    raw = chat(system, user + "\n\nRespond ONLY with valid JSON, no markdown fences.")
    # ```json ... ``` 펜스 제거
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("```")[1]
        if cleaned.startswith("json"):
            cleaned = cleaned[4:]
    try:
        return json.loads(cleaned.strip())
    except json.JSONDecodeError:
        return {}
