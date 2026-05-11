"""Configuration and CORS misconfigurations detection."""
import re
from pathlib import Path
from typing import List
from app.models import Finding, Severity, Category


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
    
    # Check if it's a .env file
    if Path(file_path).name.endswith(".env") or Path(file_path).name.startswith(".env."):
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
    
    # NEXT_PUBLIC_ variables that look like secrets
    next_public_secret_patterns = {
        "api_key": r"NEXT_PUBLIC_.*API_KEY\s*=",
        "secret": r"NEXT_PUBLIC_.*SECRET\s*=",
        "token": r"NEXT_PUBLIC_.*TOKEN\s*=",
        "password": r"NEXT_PUBLIC_.*PASSWORD\s*=",
    }
    
    for secret_type, pattern in next_public_secret_patterns.items():
        try:
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        rule_id=f"CONFIG_NEXT_PUBLIC_{secret_type.upper()}",
                        title=f"NEXT_PUBLIC_ variable with {secret_type}",
                        severity=Severity.CRITICAL,
                        category=Category.EXPOSURE,
                        file=file_path,
                        line=line_num,
                        evidence=line.strip()[:80] + ("..." if len(line.strip()) > 80 else ""),
                        recommendation="NEXT_PUBLIC_ variables are exposed to the browser. Never expose secrets, keys, or tokens this way."
                    ))
        except Exception:
            continue
    
    return findings
