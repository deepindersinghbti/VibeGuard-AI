"""Dangerous JavaScript/TypeScript patterns detection."""
import re
from typing import List
from app.models import Finding, Severity, Category


# Dangerous JavaScript/TypeScript patterns
DANGEROUS_PATTERNS = {
    "eval": {
        "pattern": r"\beval\s*\(",
        "title": "eval() usage detected",
        "severity": Severity.HIGH,
        "recommendation": "Replace eval() with safer alternatives like Function() with restricted scope or JSON.parse()."
    },
    "new_function": {
        "pattern": r"\bnew\s+Function\s*\(",
        "title": "new Function() detected",
        "severity": Severity.HIGH,
        "recommendation": "Avoid dynamic code execution. Use safer alternatives or pre-compiled functions."
    },
    "child_process_exec": {
        "pattern": r"(?:child_process|require\(['\"]child_process['\"])\s*\.\s*exec\s*\(",
        "title": "child_process.exec() with shell execution detected",
        "severity": Severity.CRITICAL,
        "recommendation": "Use child_process.execFile() instead, which doesn't spawn a shell. Or use safer alternatives."
    },
    "dangerous_inner_html": {
        "pattern": r"dangerouslySetInnerHTML\s*=\s*\{",
        "title": "dangerouslySetInnerHTML usage",
        "severity": Severity.HIGH,
        "recommendation": "Sanitize HTML with libraries like DOMPurify before using dangerouslySetInnerHTML, or use safer alternatives."
    },
    "localstorage_token": {
        "pattern": r"localStorage\.setItem\s*\(\s*['\"](?:token|jwt|auth|session|access_token)['\"]",
        "title": "Token stored in localStorage",
        "severity": Severity.HIGH,
        "recommendation": "Tokens should not be stored in localStorage. Use httpOnly cookies or secure session storage."
    },
}


def scan(file_path: str) -> List[Finding]:
    """
    Scan a JavaScript/TypeScript file for dangerous patterns.
    
    Uses regex to detect unsafe patterns that could lead to security issues.
    """
    findings = []
    
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            lines = content.split("\n")
    except Exception:
        return findings
    
    for pattern_key, pattern_info in DANGEROUS_PATTERNS.items():
        try:
            pattern = pattern_info["pattern"]
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    # Extract context (up to 80 chars)
                    evidence = line.strip()[:80]
                    if len(line.strip()) > 80:
                        evidence += "..."
                    
                    findings.append(Finding(
                        rule_id=f"JS_{pattern_key.upper()}",
                        title=pattern_info["title"],
                        severity=pattern_info["severity"],
                        category=Category.DANGEROUS_CODE,
                        file=file_path,
                        line=line_num,
                        evidence=evidence,
                        recommendation=pattern_info["recommendation"]
                    ))
        except Exception:
            continue
    
    return findings
