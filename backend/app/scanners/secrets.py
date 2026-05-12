"""Secrets and hardcoded credentials detection."""
import re
from typing import List, Optional, Tuple
from app.models import Finding, Severity, Category


# Patterns for secret keys that should not be in code
SECRET_PATTERNS = {
    "openai_api_key": (r"OPENAI_API_KEY\s*=\s*['\"]([^'\"]+)['\"]", "OPENAI API Key"),
    "gemini_api_key": (r"GEMINI_API_KEY\s*=\s*['\"]([^'\"]+)['\"]", "Gemini API Key"),
    "google_api_key": (r"GOOGLE_API_KEY\s*=\s*['\"]([^'\"]+)['\"]", "Google API Key"),
    "aws_access_key": (r"AWS_ACCESS_KEY_ID\s*=\s*['\"]([^'\"]+)['\"]", "AWS Access Key ID"),
    "aws_secret_key": (r"AWS_SECRET_ACCESS_KEY\s*=\s*['\"]([^'\"]+)['\"]", "AWS Secret Access Key"),
    "mongodb_uri": (r"MONGODB_URI\s*=\s*['\"]([^'\"]+)['\"]", "MongoDB URI"),
    "database_url": (r"DATABASE_URL\s*=\s*['\"]([^'\"]+)['\"]", "Database URL"),
    "jwt_secret": (r"JWT_SECRET\s*=\s*['\"]([^'\"]+)['\"]", "JWT Secret"),
    "secret_key": (r"SECRET_KEY\s*=\s*['\"]([^'\"]+)['\"]", "Secret Key"),
    "private_key": (r"PRIVATE_KEY\s*=\s*['\"]([^'\"]+)['\"]", "Private Key"),
    "api_key": (r"API_KEY\s*=\s*['\"]([^'\"]+)['\"]", "API Key"),
    "access_token": (r"ACCESS_TOKEN\s*=\s*['\"]([^'\"]+)['\"]", "Access Token"),
}

# Value-based secret patterns that do not depend on variable names.
VALUE_PATTERNS: Tuple[Tuple[str, str, str], ...] = (
    (r"\b((?:sk-(?:proj-)?[A-Za-z0-9_-]{8,}|sk_test_[A-Za-z0-9_-]{3,}))\b", "openai_value", "OpenAI-style key"),
    (r"\b(ghp_[A-Za-z0-9]{20,})\b", "github_ghp", "GitHub token"),
    (r"\b(github_pat_[A-Za-z0-9_]{20,})\b", "github_pat", "GitHub fine-grained token"),
    (r"\b(AIza[0-9A-Za-z_-]{20,})\b", "google_api_key", "Google API key"),
    (r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b", "aws_access_key_id", "AWS access key ID"),
    (r"-----BEGIN PRIVATE KEY-----", "private_key_block", "Private key block"),
)

# False positive avoidance: common placeholder values
PLACEHOLDER_VALUES = {
    "secret123",
    "your_key_here",
    "your_api_key",
    "test",
    "dummy",
    "example",
    "fake",
    "abc",
    "xyz",
    "token",
    "jwt_secret",
    "changeme",
    "change_me",
    "placeholder",
    "replace_me",
}

FALSE_POSITIVE_MARKERS = {
    "your_", "example", "dummy", "test", "placeholder", "changeme",
    "change_me", "replace_me", "xxxx", "your_key", "your_token",
    "your_api", "your_secret", "fake", "sample", "demo",
}


SPECIFIC_NAME_MARKERS = (
    "OPENAI_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "MONGODB_URI",
    "DATABASE_URL",
    "JWT_SECRET",
    "SECRET_KEY",
    "PRIVATE_KEY",
    "ACCESS_TOKEN",
)


def _is_false_positive(value: str) -> bool:
    """Check if a value looks like a placeholder/example."""
    value_lower = value.strip().strip("'\"").lower()

    if value_lower in PLACEHOLDER_VALUES:
        return True
    
    # Check for common false positive markers
    for marker in FALSE_POSITIVE_MARKERS:
        if marker in value_lower:
            return True
    
    # Check for angle bracket templates like <YOUR_API_KEY>
    if value.startswith("<") and value.endswith(">"):
        return True
    
    # Check for extremely short values (likely placeholder)
    if len(value_lower) < 5:
        return True
    
    return False


def _looks_like_real_secret(value: str) -> bool:
    """Check whether a value has a provider format or enough entropy to be high confidence."""
    normalized = value.strip().strip("'\"")
    if _is_false_positive(normalized) and not normalized.lower().startswith(("sk-proj-", "ghp_", "github_pat_", "aiza", "akia", "asia")):
        return False

    if _find_value_match(normalized):
        return True

    if len(normalized) < 20:
        return False

    char_classes = sum([
        bool(re.search(r"[a-z]", normalized)),
        bool(re.search(r"[A-Z]", normalized)),
        bool(re.search(r"\d", normalized)),
        bool(re.search(r"[^A-Za-z0-9]", normalized)),
    ])
    unique_ratio = len(set(normalized)) / max(len(normalized), 1)
    return char_classes >= 3 and unique_ratio >= 0.45


def _mask_secret(value: str, show_chars: int = 3) -> str:
    """Mask a secret value for display."""
    if len(value) <= show_chars * 2:
        return "***"
    return f"{value[:show_chars]}...{value[-show_chars:]}"


def _is_demo_or_test_value(value: str) -> bool:
    """Check if a value looks like a demo/test placeholder secret."""
    value_lower = value.lower()
    if value_lower.startswith(("sk_test_", "sk-demo", "sk_demo")):
        return True
    return any(marker in value_lower for marker in ("demo", "test", "fake", "sample"))


def _severity_for_value(value: str) -> Severity:
    """Assign a severity for value-based detections."""
    if _is_demo_or_test_value(value):
        return Severity.LOW
    return Severity.CRITICAL


def _severity_for_named_secret(value: str) -> Severity:
    """Assign severity for name-based secret detections."""
    if _is_false_positive(value):
        return Severity.LOW
    if _looks_like_real_secret(value):
        return Severity.CRITICAL
    return Severity.MEDIUM


def _find_value_match(line: str) -> Optional[Tuple[str, str, str]]:
    """Return the first value-pattern match on a line, if any."""
    for pattern, rule_id_suffix, title in VALUE_PATTERNS:
        match = re.search(pattern, line)
        if match:
            if rule_id_suffix == "private_key_block" and re.search(r"\br['\"]", line):
                continue
            return rule_id_suffix, title, match.group(1) if match.groups() else match.group(0)
    return None


def _line_has_more_specific_name(line: str) -> bool:
    """Check whether a line already matched a more specific secret name."""
    return any(marker in line.upper() for marker in SPECIFIC_NAME_MARKERS)


def scan(file_path: str) -> List[Finding]:
    """
    Scan a file for hardcoded secrets and API keys.
    
    Uses regex patterns to detect common secret assignment patterns.
    Avoids obvious false positives (examples, placeholders, etc.).
    """
    findings = []
    
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            lines = content.split("\n")
    except Exception:
        return findings

    specific_lines = set()
    
    # Scan for each pattern
    for pattern_key, (pattern, secret_name) in SECRET_PATTERNS.items():
        try:
            for line_num, line in enumerate(lines, 1):
                if pattern_key == "api_key" and _line_has_more_specific_name(line):
                    continue
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    value = match.group(1) if match.groups() else match.group(0)
                    
                    severity = _severity_for_named_secret(value)
                    
                    # Create finding
                    findings.append(Finding(
                        rule_id=f"SECRETS_{pattern_key.upper()}",
                        title=f"Hardcoded {secret_name} ({pattern_key.upper()})",
                        severity=severity,
                        category=Category.SECRETS,
                        file=file_path,
                        line=line_num,
                        evidence=f"{secret_name} = {_mask_secret(value)}",
                        recommendation=f"Remove {secret_name} from code. Use environment variables instead."
                    ))
                    specific_lines.add(line_num)
        except Exception:
            continue

    for line_num, line in enumerate(lines, 1):
        if line_num in specific_lines:
            continue

        value_match = _find_value_match(line)
        if not value_match:
            continue

        rule_suffix, title_name, matched_value = value_match

        if _is_false_positive(matched_value) and not _is_demo_or_test_value(matched_value):
            continue

        severity = _severity_for_value(matched_value)
        evidence_value = _mask_secret(matched_value)

        findings.append(Finding(
            rule_id=f"SECRETS_VALUE_{rule_suffix.upper()}",
            title=f"Hardcoded {title_name}",
            severity=severity,
            category=Category.SECRETS,
            file=file_path,
            line=line_num,
            evidence=evidence_value,
            recommendation="Remove the secret from code. Use environment variables or a secret manager instead.",
        ))
    
    return findings
