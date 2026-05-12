"""Configuration and CORS misconfigurations detection."""
import re
from pathlib import Path
from typing import List
from app.models import Finding, Severity, Category


EXAMPLE_ENV_FILENAMES = {
    ".env.example",
    ".env.sample",
    ".env.template",
    ".env.example.local",
    "example.env",
    "sample.env",
    "template.env",
}

PLACEHOLDER_VALUES = {
    "",
    "your_key_here",
    "your_api_key",
    "changeme",
    "change_me",
    "placeholder",
    "example",
    "demo",
    "test",
    "dummy",
    "xxx",
    "replace_me",
}

SECRET_NAME_PATTERN = re.compile(
    r"(API[_-]?KEY|TOKEN|SECRET|PRIVATE[_-]?KEY|PASSWORD)",
    re.IGNORECASE,
)

ENV_ASSIGNMENT_PATTERN = re.compile(
    r"^\s*(?:export\s+)?(?P<name>[A-Z0-9_]*?(?:API_KEY|TOKEN|SECRET|PRIVATE_KEY|PASSWORD)[A-Z0-9_]*)\s*=\s*(?P<value>.*)\s*$",
    re.IGNORECASE,
)

EXAMPLE_ENV_RECOMMENDATION = (
    "`.env.example` files are usually safe to commit, but values should be obvious placeholders. "
    "Avoid putting real-looking tokens or secret-like values in example files. Also avoid exposing "
    "private API keys through `NEXT_PUBLIC_` variables because they are bundled into the browser."
)


def is_example_env_file(file_path: str) -> bool:
    """Return true for known environment template/example filenames."""
    return Path(file_path).name.lower() in EXAMPLE_ENV_FILENAMES


def is_env_file(file_path: str) -> bool:
    """Return true for real or example environment filenames."""
    name = Path(file_path).name.lower()
    return name == ".env" or name.startswith(".env.") or name in EXAMPLE_ENV_FILENAMES


def is_real_env_file(file_path: str) -> bool:
    """Return true for env files that should be treated as sensitive."""
    return is_env_file(file_path) and not is_example_env_file(file_path)


def _strip_env_value(value: str) -> str:
    """Normalize a dotenv value for placeholder checks."""
    value = value.split("#", 1)[0].strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1].strip()
    return value


def is_placeholder_value(value: str) -> bool:
    """Return true when an env value is clearly a template placeholder."""
    normalized = _strip_env_value(value)
    lowered = normalized.lower()

    if lowered in PLACEHOLDER_VALUES:
        return True
    if lowered.startswith("<") and lowered.endswith(">"):
        return True
    if lowered in {"<your-key-here>", "<your_api_key>", "<replace_me>"}:
        return True
    if re.fullmatch(r"x+", lowered):
        return True
    if re.fullmatch(r"your[_-]?[a-z0-9_-]*(key|token|secret|password)[a-z0-9_-]*", lowered):
        return True

    return False


def _masked_env_value(value: str) -> str:
    normalized = _strip_env_value(value)
    if not normalized:
        return "<empty>"
    if len(normalized) <= 8:
        return "***"
    return f"{normalized[:3]}...{normalized[-3:]}"


def scan(file_path: str) -> List[Finding]:
    """
    Scan a file for configuration issues:
    - CORS misconfiguration (allow_origins=["*"])
    - .env file exposure
    - NEXT_PUBLIC_ variables with secrets
    """
    findings = []
    
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            lines = content.split("\n")
    except Exception:
        return findings
    
    example_env = is_example_env_file(file_path)
    real_env = is_real_env_file(file_path)

    # Check if it's a real .env file. Template/example files are handled more softly below.
    if real_env:
        findings.append(Finding(
            rule_id="CONFIG_ENV_FILE",
            title=".env file found",
            severity=Severity.HIGH,
            category=Category.EXPOSURE,
            file=file_path,
            line=1,
            evidence=".env files should not be committed to version control",
            recommendation="Add .env to .gitignore. Use environment-specific configuration and secrets management."
        ))
    
    # CORS wildcard patterns
    cors_patterns = [
        (r"allow_origins\s*=\s*\[\s*['\"]?\*['\"]?\s*\]", "Python FastAPI"),
        (r"origin\s*:\s*['\"]?\*['\"]?", "Config file"),
        (r"Access-Control-Allow-Origin\s*:\s*\*", "HTTP header"),
    ]
    
    for pattern, context in cors_patterns:
        try:
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        rule_id="CONFIG_CORS_WILDCARD",
                        title="CORS allow_origins set to wildcard (*)",
                        severity=Severity.MEDIUM,
                        category=Category.CORS,
                        file=file_path,
                        line=line_num,
                        evidence=line.strip()[:80] + ("..." if len(line.strip()) > 80 else ""),
                        recommendation=f"Restrict CORS to specific trusted origins. Currently allows all ({context})."
                    ))
        except Exception:
            continue
    
    for line_num, line in enumerate(lines, 1):
        match = ENV_ASSIGNMENT_PATTERN.search(line)
        if not match:
            continue

        name = match.group("name")
        value = match.group("value")
        placeholder = is_placeholder_value(value)
        is_next_public = name.upper().startswith("NEXT_PUBLIC_")

        if not SECRET_NAME_PATTERN.search(name):
            continue

        if example_env and placeholder:
            if is_next_public:
                findings.append(Finding(
                    rule_id="CONFIG_EXAMPLE_NEXT_PUBLIC_PLACEHOLDER",
                    title="NEXT_PUBLIC variable uses secret-like name",
                    severity=Severity.LOW,
                    category=Category.EXPOSURE,
                    file=file_path,
                    line=line_num,
                    evidence=line.strip()[:80] + ("..." if len(line.strip()) > 80 else ""),
                    recommendation=EXAMPLE_ENV_RECOMMENDATION,
                ))
            continue

        if is_next_public:
            if example_env:
                rule_id = "CONFIG_EXAMPLE_NEXT_PUBLIC_SECRET_LIKE"
                title = "Example environment file contains public secret-like variable"
                severity = Severity.MEDIUM
                recommendation = EXAMPLE_ENV_RECOMMENDATION
            else:
                secret_type_match = SECRET_NAME_PATTERN.search(name)
                secret_type = secret_type_match.group(1).lower() if secret_type_match else "secret"
                rule_id = f"CONFIG_NEXT_PUBLIC_{secret_type.upper().replace('-', '_')}"
                title = f"NEXT_PUBLIC_ variable with {secret_type}"
                severity = Severity.CRITICAL
                recommendation = (
                    "NEXT_PUBLIC_ variables are exposed to the browser. Never expose secrets, "
                    "keys, or tokens this way."
                )

            findings.append(Finding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                category=Category.EXPOSURE,
                file=file_path,
                line=line_num,
                evidence=line.strip()[:80] + ("..." if len(line.strip()) > 80 else ""),
                recommendation=recommendation,
            ))
            continue

        if example_env:
            findings.append(Finding(
                rule_id="CONFIG_EXAMPLE_ENV_SECRET_LIKE_VALUE",
                title="Example env file should use clear placeholder values",
                severity=Severity.LOW,
                category=Category.EXPOSURE,
                file=file_path,
                line=line_num,
                evidence=f"{name}={_masked_env_value(value)}",
                recommendation=EXAMPLE_ENV_RECOMMENDATION,
            ))
        elif real_env and not placeholder:
            findings.append(Finding(
                rule_id="CONFIG_ENV_SECRET_LIKE_VALUE",
                title="Environment file contains secret-like variable",
                severity=Severity.HIGH,
                category=Category.SECRETS,
                file=file_path,
                line=line_num,
                evidence=f"{name}={_masked_env_value(value)}",
                recommendation="Remove secrets from committed .env files. Use a secret manager or runtime environment variables.",
            ))
    
    return findings
