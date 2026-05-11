"""AI explanation layer for scanner findings."""
import asyncio
import hashlib
import json
import logging
import os
import re
import socket
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict

from app.models import ExplainFinding, ExplainResponse


GEMINI_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"
REQUEST_TIMEOUT_SECONDS = 12
LOGGER = logging.getLogger(__name__)

GENERIC_FALLBACK_RESPONSE = ExplainResponse(
    explanation="AI explanation is currently unavailable. Refer to the recommendation above.",
    attack_scenario="No AI-generated attack scenario is available right now.",
    fix_details="Use the recommendation shown with this finding and review the flagged line.",
)
MISSING_KEY_FALLBACK_RESPONSE = ExplainResponse(
    explanation="AI explanations are not configured yet. Add GEMINI_API_KEY to the backend environment to enable them.",
    attack_scenario="No AI-generated attack scenario is available right now.",
    fix_details="Use the recommendation shown with this finding, then configure the backend Gemini key when you want AI help.",
)
INVALID_KEY_FALLBACK_RESPONSE = ExplainResponse(
    explanation="AI explanations could not be generated because the configured Gemini API key was rejected.",
    attack_scenario="No AI-generated attack scenario is available right now.",
    fix_details="Check backend/.env or the server environment and replace GEMINI_API_KEY with a valid Google AI Studio key.",
)
TIMEOUT_FALLBACK_RESPONSE = ExplainResponse(
    explanation="AI explanation took too long to generate. Refer to the recommendation above.",
    attack_scenario="No AI-generated attack scenario is available right now.",
    fix_details="Try again in a moment, or use the recommendation shown with this finding.",
)

_EXPLANATION_CACHE: Dict[str, ExplainResponse] = {}


class MissingAPIKeyError(RuntimeError):
    """Raised when Gemini is not configured."""


class InvalidAPIKeyError(RuntimeError):
    """Raised when Gemini rejects the configured API key."""


class ExplanationTimeoutError(RuntimeError):
    """Raised when Gemini does not respond in time."""


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
    """Build a stable cache key without storing evidence or secrets in the key."""
    evidence_digest = hashlib.sha256(finding.evidence.encode("utf-8")).hexdigest()
    raw_key = f"{finding.rule_id}|{evidence_digest}|{finding.severity.value}"
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def _sanitize_evidence_for_ai(evidence: str) -> str:
    """Mask likely secret values before sending evidence to AI."""
    sanitized = evidence[:500]
    sanitized = re.sub(r"(sk-(?:proj-)?)[A-Za-z0-9_-]{8,}", r"\1***", sanitized)
    sanitized = re.sub(r"(sk_test_)[A-Za-z0-9_-]{3,}", r"\1***", sanitized)
    sanitized = re.sub(r"(ghp_)[A-Za-z0-9]{8,}", r"\1***", sanitized)
    sanitized = re.sub(r"(github_pat_)[A-Za-z0-9_]{8,}", r"\1***", sanitized)
    sanitized = re.sub(r"(AIza)[0-9A-Za-z_-]{8,}", r"\1***", sanitized)
    sanitized = re.sub(r"\b((?:AKIA|ASIA)[0-9A-Z]{8,})\b", "***", sanitized)
    sanitized = re.sub(
        r"(=\s*[\"']?)([^\"'\s]{16,})([\"']?)",
        r"\1***\3",
        sanitized,
    )
    return sanitized


def _build_prompt(finding: ExplainFinding) -> str:
    """Build the strict prompt sent to the AI model."""
    evidence = _sanitize_evidence_for_ai(finding.evidence)
    return f"""Explain this security issue to a beginner developer.

Rule: {finding.title}
Severity: {finding.severity.value}
Code: {evidence}

Give:
1. Why this is dangerous
2. A simple attack scenario
3. How to fix it step-by-step

CRITICAL FORMATTING RULES:
- Do NOT put multiple numbered list items on the same line.
- Each numbered step MUST start on a new line.
- Do NOT return "1. item 2. item 3. item" in one paragraph.
- If returning a numbered list, use format:
  1. First step here.
  2. Second step here.
  3. Third step here.
- Each item in a numbered list MUST have its own line.

Keep it simple and practical.
Do not repeat the input.
Return valid JSON only with these string keys: explanation, attack_scenario, fix_details.
Keep each value under 80 words."""


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
        raise MissingAPIKeyError("GEMINI_API_KEY is not configured")

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
            "maxOutputTokens": 2048,
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

    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            response_body = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        if exc.code in {400, 401, 403}:
            raise InvalidAPIKeyError("Gemini rejected the configured API key") from exc
        raise
    except (TimeoutError, socket.timeout) as exc:
        raise ExplanationTimeoutError("Gemini request timed out") from exc

    return _parse_gemini_response(json.loads(response_body))


def _fallback_for_error(error: Exception) -> ExplainResponse:
    """Return a friendly fallback for a known AI failure."""
    if isinstance(error, MissingAPIKeyError):
        return MISSING_KEY_FALLBACK_RESPONSE
    if isinstance(error, InvalidAPIKeyError):
        return INVALID_KEY_FALLBACK_RESPONSE
    if isinstance(error, ExplanationTimeoutError):
        return TIMEOUT_FALLBACK_RESPONSE
    return GENERIC_FALLBACK_RESPONSE


async def explain_finding(finding: ExplainFinding) -> ExplainResponse:
    """Explain a finding, using an in-memory cache to avoid duplicate AI calls."""
    cache_key = _cache_key(finding)
    if cache_key in _EXPLANATION_CACHE:
        return _EXPLANATION_CACHE[cache_key]

    prompt = _build_prompt(finding)
    try:
        explanation = await asyncio.to_thread(_call_gemini, prompt)
    except (
        MissingAPIKeyError,
        InvalidAPIKeyError,
        ExplanationTimeoutError,
        RuntimeError,
        ValueError,
        KeyError,
        json.JSONDecodeError,
        urllib.error.URLError,
    ) as error:
        LOGGER.warning("AI explanation unavailable: %s", error.__class__.__name__)
        return _fallback_for_error(error)

    _EXPLANATION_CACHE[cache_key] = explanation
    return explanation


def clear_explanation_cache() -> None:
    """Clear the in-memory explanation cache. Intended for tests."""
    _EXPLANATION_CACHE.clear()
