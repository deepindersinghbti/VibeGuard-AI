"""Scanner orchestrator - coordinates all scanners."""
import os
from pathlib import Path
from typing import List
from app.models import Finding, ScanSummary, Severity
from app.services.zip_handler import should_skip_file
from app.scanners import secrets, javascript, python, config


# Map file extensions to scanner functions
SCANNER_MAP = {
    ".py": python.scan,
    ".js": javascript.scan,
    ".jsx": javascript.scan,
    ".ts": javascript.scan,
    ".tsx": javascript.scan,
    ".json": config.scan,
    ".env": config.scan,
    ".yml": config.scan,
    ".yaml": config.scan,
    ".toml": config.scan,
    ".ini": config.scan,
}

RISK_WEIGHTS = {
    Severity.CRITICAL: 24,
    Severity.HIGH: 11,
    Severity.MEDIUM: 6,
    Severity.LOW: 1,
}

LOW_SEVERITY_PENALTY_CAP = 5
SINGLE_DIGIT_SCORE_FLOOR = 10

EXAMPLE_FINDING_RULE_PREFIXES = (
    "CONFIG_EXAMPLE_",
)

EXAMPLE_ENV_FILENAMES = {
    ".env.example",
    ".env.sample",
    ".env.template",
    ".env.example.local",
    "example.env",
    "sample.env",
    "template.env",
}

CATASTROPHIC_RULE_KEYWORDS = (
    "PRIVATE_KEY",
    "AUTH_BYPASS",
    "ADMIN_CREDENTIAL",
    "SQL_INJECTION",
    "COMMAND_INJECTION",
    "DESTRUCTIVE",
    "MALWARE",
)

CODE_EXECUTION_RULE_KEYWORDS = (
    "SUBPROCESS_SHELL",
    "CHILD_PROCESS_EXEC",
    "EXEC",
    "RCE",
)


def _scanner_key(filename: str) -> str:
    """Return the scanner map key for a file name."""
    name = Path(filename).name.lower()
    if name == ".env" or name.startswith(".env."):
        return ".env"
    return Path(filename).suffix.lower()


def generate_summary(findings: List[Finding]) -> ScanSummary:
    """Generate severity counts and score for scan findings."""
    counts = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 0,
        Severity.MEDIUM: 0,
        Severity.LOW: 0,
    }

    for finding in findings:
        severity = Severity(finding.severity)
        counts[severity] += 1

    rule_counts = {}
    severity_counts = {}
    category_counts = {}
    deduction = 0.0
    low_deduction = 0.0
    real_critical_findings = []

    for finding in findings:
        severity = Severity(finding.severity)
        rule_id = finding.rule_id
        rule_seen_count = rule_counts.get(rule_id, 0)
        rule_counts[rule_id] = rule_seen_count + 1
        severity_seen_count = severity_counts.get(severity, 0)
        severity_counts[severity] = severity_seen_count + 1
        category_seen_count = category_counts.get(finding.category, 0)
        category_counts[finding.category] = category_seen_count + 1

        duplicate_multiplier = _duplicate_multiplier(rule_seen_count)
        severity_multiplier = _repeat_multiplier(severity_seen_count)
        category_multiplier = _category_multiplier(category_seen_count)
        example_multiplier = 0.25 if _is_example_or_template_finding(finding) else 1.0
        penalty = (
            RISK_WEIGHTS[severity]
            * min(duplicate_multiplier, severity_multiplier, category_multiplier)
            * example_multiplier
        )

        if severity == Severity.LOW:
            low_deduction += penalty
        else:
            deduction += penalty

        if severity == Severity.CRITICAL and not _is_example_or_template_finding(finding):
            real_critical_findings.append(finding)

    deduction += min(low_deduction, LOW_SEVERITY_PENALTY_CAP)
    catastrophic_risk = _has_catastrophic_risk(real_critical_findings)
    if catastrophic_risk and deduction >= 60:
        deduction += 30
    score = max(0, min(100, round(100 - deduction)))
    if score < SINGLE_DIGIT_SCORE_FLOOR and not catastrophic_risk:
        score = SINGLE_DIGIT_SCORE_FLOOR

    return ScanSummary(
        total=len(findings),
        critical=counts[Severity.CRITICAL],
        high=counts[Severity.HIGH],
        medium=counts[Severity.MEDIUM],
        low=counts[Severity.LOW],
        score=score,
    )


def _repeat_multiplier(previous_count: int) -> float:
    """Diminish repeated findings with the same broad risk dimension."""
    if previous_count == 0:
        return 1.0
    if previous_count == 1:
        return 0.75
    if previous_count == 2:
        return 0.55
    return 0.35


def _duplicate_multiplier(previous_count: int) -> float:
    """Diminish duplicate/same-rule findings more aggressively."""
    if previous_count == 0:
        return 1.0
    if previous_count == 1:
        return 0.5
    return 0.25


def _category_multiplier(previous_count: int) -> float:
    """Keep repeated findings in one category from overwhelming the score."""
    if previous_count == 0:
        return 1.0
    if previous_count == 1:
        return 0.85
    if previous_count == 2:
        return 0.65
    return 0.45


def _has_catastrophic_risk(real_critical_findings: List[Finding]) -> bool:
    """Return true when single-digit scores are justified by confirmed severe patterns."""
    if len(real_critical_findings) >= 4:
        categories = {finding.category for finding in real_critical_findings}
        if len(categories) >= 2:
            return True

    rule_ids = [finding.rule_id.upper() for finding in real_critical_findings]
    if any(any(keyword in rule_id for keyword in CATASTROPHIC_RULE_KEYWORDS) for rule_id in rule_ids):
        return True

    code_execution_count = sum(
        any(keyword in rule_id for keyword in CODE_EXECUTION_RULE_KEYWORDS)
        for rule_id in rule_ids
    )
    return code_execution_count >= 2


def _is_example_or_template_finding(finding: Finding) -> bool:
    """Identify findings from example/template config files for reduced scoring impact."""
    filename = Path(finding.file).name.lower()
    return (
        filename in EXAMPLE_ENV_FILENAMES
        or any(finding.rule_id.startswith(prefix) for prefix in EXAMPLE_FINDING_RULE_PREFIXES)
    )


def _severity_sort_key(finding: Finding) -> tuple:
    """Create a sort key for findings (severity, file, line)."""
    severity_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
    }
    
    return (
        severity_order.get(finding.severity, 99),
        finding.file,
        finding.line,
    )


def scan_directory(extract_dir: str) -> List[Finding]:
    """
    Scan an extracted directory for security issues.
    
    Walks the directory tree:
    - Skips excluded directories (node_modules, .git, etc.)
    - Filters to allowed file types
    - Calls appropriate scanner for each file
    - Aggregates and deduplicates findings
    - Returns findings sorted by severity, then file, then line
    
    Args:
        extract_dir: Path to the extracted directory
    
    Returns:
        List of Finding objects sorted by severity (critical → low), file, line
    """
    findings = []
    seen_findings = set()  # For deduplication
    
    # Walk the directory tree
    for root, dirs, files in os.walk(extract_dir):
        # Filter out excluded directories
        dirs[:] = [d for d in dirs if d not in {
            "node_modules", ".git", "dist", "build", ".next",
            "venv", "__pycache__", ".cache"
        }]
        
        for filename in files:
            file_path = os.path.join(root, filename)
            
            # Get relative path for reporting
            rel_path = os.path.relpath(file_path, extract_dir)
            
            # Skip if file should be skipped
            if should_skip_file(rel_path):
                continue
            
            # Check file size (skip files > 1MB)
            try:
                if os.path.getsize(file_path) > 1 * 1024 * 1024:
                    continue
            except Exception:
                continue
            
            # Get scanner key
            scanner_key = _scanner_key(filename)
            
            # Run all applicable scanners
            try:
                # Run extension-specific scanner
                if scanner_key in SCANNER_MAP:
                    scanner_func = SCANNER_MAP[scanner_key]
                    file_findings = scanner_func(file_path)
                    
                    # Normalize file paths to use forward slashes and relative paths
                    for finding in file_findings:
                        finding.file = rel_path.replace("\\", "/")
                        
                        # Create dedup key
                        dedup_key = (
                            finding.rule_id,
                            finding.file,
                            finding.line,
                        )
                        
                        # Only add if not already seen
                        if dedup_key not in seen_findings:
                            findings.append(finding)
                            seen_findings.add(dedup_key)
                
                # Always run secrets scanner for supported text files
                if scanner_key in {".js", ".jsx", ".ts", ".tsx", ".py", ".json", ".yml", ".yaml", ".toml", ".ini", ".env"}:
                    secret_findings = secrets.scan(file_path)
                    for finding in secret_findings:
                        finding.file = rel_path.replace("\\", "/")
                        dedup_key = (finding.rule_id, finding.file, finding.line)
                        if dedup_key not in seen_findings:
                            findings.append(finding)
                            seen_findings.add(dedup_key)
            
            except Exception:
                # Skip files that can't be scanned
                continue
    
    # Sort findings: critical → high → medium → low, then by file and line
    findings.sort(key=_severity_sort_key)
    
    return findings
