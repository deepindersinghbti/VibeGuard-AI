"""AI explanation layer for scanner findings."""
import asyncio
import hashlib
import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict

from app.models import ExplainFinding, ExplainResponse


GEMINI_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"
REQUEST_TIMEOUT_SECONDS = 12

FALLBACK_RESPONSE = ExplainResponse(
    explanation="AI explanation is currently unavailable. Refer to the recommendation above.",
    attack_scenario="No AI-generated attack scenario is available right now.",
    fix_details="Use the recommendation shown with this finding and review the flagged line.",
)

_EXPLANATION_CACHE: Dict[str, ExplainResponse] = {}


def _get_env_value(name: str) -> str:
    """Read an environment value, falling back to backend/.env for local dev."""
    value = os.getenv(name)
    if value:
        return value

    env_path = Path(__file__).resolve().parents[2] / ".env"
    if not env_path.exists():
        return ""

    try:
        for line in env_path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, raw_value = stripped.split("=", 1)
            if key.strip() == name:
                return raw_value.strip().strip('"').strip("'")
    except OSError:
        return ""

    return ""


def _cache_key(finding: ExplainFinding) -> str:
    """Build a stable cache key for equivalent findings."""
    raw_key = f"{finding.rule_id}|{finding.evidence}|{finding.severity.value}"
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def _build_prompt(finding: ExplainFinding) -> str:
    """Build the strict prompt sent to the AI model."""
    return f"""Explain this security issue to a beginner developer.

Rule: {finding.title}
Severity: {finding.severity.value}
Code: {finding.evidence}

Give:
1. Why this is dangerous
2. A simple attack scenario
3. How to fix it step-by-step

Keep it simple and practical.
Do not repeat the input.
Return valid JSON only with these string keys: explanation, attack_scenario, fix_details."""


def _parse_gemini_response(payload: dict) -> ExplainResponse:
    """Parse Gemini's response text into the explanation shape."""
    text = (
        payload.get("candidates", [{}])[0]
        .get("content", {})
        .get("parts", [{}])[0]
        .get("text", "")
    )
    if not text:
        raise ValueError("Gemini response did not include text")

    cleaned_text = text.strip()
    if cleaned_text.startswith("```json"):
        cleaned_text = cleaned_text.removeprefix("```json").removesuffix("```").strip()
    elif cleaned_text.startswith("```"):
        cleaned_text = cleaned_text.removeprefix("```").removesuffix("```").strip()

    parsed = json.loads(cleaned_text)
    return ExplainResponse(
        explanation=parsed["explanation"],
        attack_scenario=parsed.get("attack_scenario", ""),
        fix_details=parsed.get("fix_details", ""),
    )


def _call_gemini(prompt: str) -> ExplainResponse:
    """Call Gemini and return a structured explanation."""
    api_key = _get_env_value("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY is not configured")

    model = _get_env_value("GEMINI_MODEL") or DEFAULT_GEMINI_MODEL
    url = GEMINI_ENDPOINT.format(model=model)
    body = {
        "contents": [
            {
                "parts": [
                    {
                        "text": prompt,
                    }
                ]
            }
        ],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 512,
            "responseMimeType": "application/json",
        },
    }

    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "x-goog-api-key": api_key,
        },
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        response_body = response.read().decode("utf-8")

    return _parse_gemini_response(json.loads(response_body))


async def explain_finding(finding: ExplainFinding) -> ExplainResponse:
    """Explain a finding, using an in-memory cache to avoid duplicate AI calls."""
    cache_key = _cache_key(finding)
    if cache_key in _EXPLANATION_CACHE:
        return _EXPLANATION_CACHE[cache_key]

    prompt = _build_prompt(finding)
    try:
        explanation = await asyncio.to_thread(_call_gemini, prompt)
    except (RuntimeError, ValueError, KeyError, json.JSONDecodeError, urllib.error.URLError):
        return FALLBACK_RESPONSE

    _EXPLANATION_CACHE[cache_key] = explanation
    return explanation


def clear_explanation_cache() -> None:
    """Clear the in-memory explanation cache. Intended for tests."""
    _EXPLANATION_CACHE.clear()
