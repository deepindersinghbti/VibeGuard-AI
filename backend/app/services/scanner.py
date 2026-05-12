"""Scanner orchestrator - coordinates all scanners."""
import os
import math
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional
from app.models import Category, FileContext, Finding, ScanSummary, Severity
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

EXAMPLE_FINDING_RULE_PREFIXES = ("CONFIG_EXAMPLE_",)

EXAMPLE_ENV_FILENAMES = {
    ".env.example",
    ".env.sample",
    ".env.template",
    ".env.example.local",
    "example.env",
    "sample.env",
    "template.env",
}

GENERATED_DEPENDENCY_DIRS = {
    "node_modules",
    ".next",
    "dist",
    "build",
    "coverage",
    ".git",
    "venv",
    "__pycache__",
}

TEST_DEMO_PARTS = {
    "test",
    "tests",
    "__tests__",
    "spec",
    "specs",
    "fixture",
    "fixtures",
    "demo",
    "demos",
    "vulnerable",
    "vuln",
    "dvwa",
    "juice-shop",
    "sample-vulnerable-app",
    "badrepo",
    "conftest.py",
    "debug",
}

DEMO_FIXTURE_PARTS = {
    "fixture",
    "fixtures",
    "demo",
    "demos",
    "vulnerable",
    "vuln",
    "dvwa",
    "juice-shop",
    "sample-vulnerable-app",
    "badrepo",
    "conftest.py",
    "debug",
}

ENV_TEMPLATE_FILENAMES = EXAMPLE_ENV_FILENAMES

EXAMPLE_TEMPLATE_PARTS = {
    "doc",
    "docs",
    "documentation",
    "example",
    "examples",
    "sample",
    "samples",
    "template",
    "templates",
}

README_FILENAMES = {"readme", "readme.md", "readme.txt", "readme.rst"}

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

SECRET_SCAN_KEYS = {
    ".js", ".jsx", ".ts", ".tsx", ".py", ".json", ".yml", ".yaml",
    ".toml", ".ini", ".env", ".md", ".mdx",
}


@dataclass
class ScanStats:
    """File-level scan counters."""
    scanned_files: int = 0
    ignored_files: int = 0
    skipped_generated_dependency_files: int = 0


def _scanner_key(filename: str) -> str:
    """Return the scanner map key for a file name."""
    name = Path(filename).name.lower()
    if name == ".env" or name.startswith(".env."):
        return ".env"
    return Path(filename).suffix.lower()


def generate_summary(findings: List[Finding], stats: Optional[ScanStats] = None) -> ScanSummary:
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
    production_gate_critical_count = 0
    non_production_critical_count = 0
    production_critical_count = 0
    env_critical_count = 0
    test_demo_critical_count = 0
    docs_template_critical_count = 0
    generated_dependency_critical_count = 0
    production_env_high_count = 0
    production_penalty = 0.0
    env_config_penalty = 0.0
    test_demo_penalty = 0.0
    documentation_template_penalty = 0.0
    duplicate_caps_applied = False
    score_ceiling = 100

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
        repeat_multiplier = min(duplicate_multiplier, severity_multiplier, category_multiplier)
        if repeat_multiplier < 1.0:
            duplicate_caps_applied = True

        penalty = (
            RISK_WEIGHTS[severity]
            * repeat_multiplier
            * _context_score_multiplier(finding)
        )
        finding.score_penalty = round(penalty, 2)

        bucket = _score_bucket(finding)
        if bucket == "production":
            production_penalty += penalty
        elif bucket == "env_config":
            env_config_penalty += penalty
        elif bucket == "test_demo":
            test_demo_penalty += penalty
        else:
            documentation_template_penalty += penalty

        if severity == Severity.LOW:
            low_deduction += penalty
        else:
            deduction += penalty

        if severity == Severity.CRITICAL and not _is_example_or_template_finding(finding):
            real_critical_findings.append(finding)
        if severity == Severity.CRITICAL and _is_confirmed_production_finding(finding):
            production_gate_critical_count += 1
        elif severity == Severity.CRITICAL:
            non_production_critical_count += 1

        if severity == Severity.CRITICAL:
            critical_bucket = _critical_count_bucket(finding)
            if critical_bucket == "production":
                production_critical_count += 1
            elif critical_bucket == "env_config":
                env_critical_count += 1
            elif critical_bucket == "test_demo":
                test_demo_critical_count += 1
            elif critical_bucket == "docs_template":
                docs_template_critical_count += 1
            elif critical_bucket == "generated_dependency":
                generated_dependency_critical_count += 1
        if severity == Severity.HIGH and _score_bucket(finding) in {"production", "env_config"}:
            production_env_high_count += 1

        score_ceiling = min(score_ceiling, _score_ceiling_for_finding(finding))

    low_cap = min(low_deduction, LOW_SEVERITY_PENALTY_CAP)
    if low_deduction > LOW_SEVERITY_PENALTY_CAP:
        duplicate_caps_applied = True
    deduction += low_cap
    catastrophic_risk = _has_catastrophic_risk(real_critical_findings)
    if catastrophic_risk and deduction >= 60:
        deduction += 30
    score = max(0, min(100, round(100 - deduction)))
    if production_env_high_count >= 4:
        score_ceiling = min(score_ceiling, 65)
    elif production_env_high_count >= 2:
        score_ceiling = min(score_ceiling, 75)
    score = min(score, score_ceiling)
    if score < SINGLE_DIGIT_SCORE_FLOOR and not catastrophic_risk:
        score = SINGLE_DIGIT_SCORE_FLOOR
    production_env_critical_count = production_critical_count + env_critical_count
    if production_env_critical_count < 3 and score < 20:
        score = 20
    if non_production_critical_count > production_gate_critical_count and score < 40:
        score = 40
    if production_env_critical_count == 0 and production_penalty + env_config_penalty == 0 and score < 50:
        score = 50
    risk_label = _risk_label_for_summary(
        score=score,
        production_critical_count=production_critical_count,
        env_critical_count=env_critical_count,
        production_env_high_count=production_env_high_count,
        total=len(findings),
    )
    warning_message = _warning_message_for_summary(
        total=len(findings),
        risk_label=risk_label,
        production_critical_count=production_critical_count,
        env_critical_count=env_critical_count,
        test_demo_critical_count=test_demo_critical_count,
        docs_template_critical_count=docs_template_critical_count,
        generated_dependency_critical_count=generated_dependency_critical_count,
        test_demo_penalty=test_demo_penalty,
        production_penalty=production_penalty,
        env_config_penalty=env_config_penalty,
    )

    return ScanSummary(
        total=len(findings),
        critical=counts[Severity.CRITICAL],
        high=counts[Severity.HIGH],
        medium=counts[Severity.MEDIUM],
        low=counts[Severity.LOW],
        score=score,
        risk_label=risk_label,
        warning_message=warning_message,
        scanned_files=stats.scanned_files if stats else 0,
        ignored_files=stats.ignored_files if stats else 0,
        skipped_generated_dependency_files=(
            stats.skipped_generated_dependency_files if stats else 0
        ),
        production_penalty=_display_penalty(production_penalty),
        real_env_config_penalty=_display_penalty(env_config_penalty),
        test_demo_penalty=_display_penalty(test_demo_penalty),
        documentation_template_penalty=_display_penalty(documentation_template_penalty),
        duplicate_caps_applied=duplicate_caps_applied,
        production_critical_count=production_critical_count,
        env_critical_count=env_critical_count,
        test_demo_critical_count=test_demo_critical_count,
        docs_template_critical_count=docs_template_critical_count,
        generated_dependency_critical_count=generated_dependency_critical_count,
    )


def _display_penalty(value: float) -> int:
    """Round score breakdown penalties without hiding tiny nonzero discounts."""
    if 0 < value < 1:
        return 1
    return math.ceil(value)


def _critical_count_bucket(finding: Finding) -> str:
    """Choose the critical-count bucket for a finding."""
    context = FileContext(finding.file_context)
    if context == FileContext.GENERATED_DEPENDENCY:
        return "generated_dependency"
    if _is_real_env_or_config_finding(finding):
        return "env_config"
    if context == FileContext.PRODUCTION:
        return "production"
    if context == FileContext.TEST_DEMO:
        return "test_demo"
    return "docs_template"


def _baseline_risk_label(score: int, total: int) -> str:
    """Return the score-only risk label."""
    if total == 0 or score >= 90:
        return "Healthy"
    if score >= 71:
        return "Low Risk"
    if score >= 46:
        return "Moderate Risk"
    if score >= 21:
        return "High Risk"
    return "Critical Risk"


def _risk_label_for_summary(
    score: int,
    production_critical_count: int,
    env_critical_count: int,
    production_env_high_count: int = 0,
    total: Optional[int] = None,
) -> str:
    """Calculate the context-aware risk label."""
    risk_label = _baseline_risk_label(score, total if total is not None else 1)
    production_env_critical_count = production_critical_count + env_critical_count

    if production_env_critical_count >= 2:
        return "Critical Risk"
    if production_env_critical_count == 1 and risk_label in {"Healthy", "Low Risk", "Moderate Risk"}:
        return "High Risk"
    if production_env_high_count > 0 and risk_label == "Healthy":
        return "Low Risk"
    return risk_label


def _warning_message_for_summary(
    total: int,
    risk_label: str,
    production_critical_count: int,
    env_critical_count: int,
    test_demo_critical_count: int,
    docs_template_critical_count: int,
    generated_dependency_critical_count: int,
    test_demo_penalty: float,
    production_penalty: float,
    env_config_penalty: float,
) -> str:
    """Build a context-aware warning message for the score summary."""
    if total == 0:
        return "No security issues found in scanned application files."

    production_env_critical_count = production_critical_count + env_critical_count
    non_production_critical_count = (
        test_demo_critical_count
        + docs_template_critical_count
        + generated_dependency_critical_count
    )

    if production_env_critical_count >= 2:
        return "Critical production/env issues found. Fix immediately before deploying."
    if production_env_critical_count == 1:
        return "1 critical production/env issue found. Fix before deploying."
    if non_production_critical_count > 0:
        return "Critical-severity patterns found in non-production files. Review if these are intentional test/demo examples."
    if test_demo_penalty > production_penalty + env_config_penalty and test_demo_penalty > 0:
        return "Many findings are from test/demo files. Review production findings first."
    if risk_label in {"High Risk", "Critical Risk"}:
        return "Security issues found. Prioritize high-impact production findings before deploying."
    return "Security issues found. Review the findings before deploying."


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


def _context_score_multiplier(finding: Finding) -> float:
    """Reduce score impact for lower-confidence file contexts."""
    if _is_real_env_or_config_finding(finding):
        return 1.0
    context = FileContext(finding.file_context)
    if context == FileContext.EXAMPLE_TEMPLATE:
        return 0.15 if _is_documentation_path(finding.file) else 0.3
    if context == FileContext.TEST_DEMO:
        return 0.25 if _is_demo_fixture_path(finding.file) else 0.5
    if context == FileContext.GENERATED_DEPENDENCY:
        return 0.2
    return 1.0


def _score_bucket(finding: Finding) -> str:
    """Choose the score breakdown bucket for a finding."""
    if _is_real_env_or_config_finding(finding):
        return "env_config"
    context = FileContext(finding.file_context)
    if context == FileContext.TEST_DEMO:
        return "test_demo"
    if context in {FileContext.EXAMPLE_TEMPLATE, FileContext.GENERATED_DEPENDENCY}:
        return "documentation_template"
    return "production"


def _is_real_env_or_config_finding(finding: Finding) -> bool:
    """Return true for real env/config findings that should carry full weight."""
    filename = _filename(finding.file)
    if filename in EXAMPLE_ENV_FILENAMES:
        return False
    if _is_demo_fixture_path(finding.file):
        return False
    return (
        filename == ".env"
        or (filename.startswith(".env.") and filename not in EXAMPLE_ENV_FILENAMES)
        or finding.rule_id.startswith(("CONFIG_ENV_", "CONFIG_NEXT_PUBLIC_"))
    )


def _is_confirmed_production_finding(finding: Finding) -> bool:
    """Return true for findings that should count toward production-critical floors."""
    return (
        FileContext(finding.file_context) == FileContext.PRODUCTION
        and not _is_example_or_template_finding(finding)
    )


def _score_ceiling_for_finding(finding: Finding) -> int:
    """Apply maximum scores for high-confidence production/env anti-patterns."""
    if _is_real_env_or_config_finding(finding):
        if finding.rule_id == "CONFIG_ENV_FILE":
            return 85
        if Severity(finding.severity) in {Severity.HIGH, Severity.CRITICAL}:
            return 80

    if FileContext(finding.file_context) != FileContext.PRODUCTION:
        return 100

    rule_id = finding.rule_id.upper()
    if rule_id in {"JS_EVAL", "PY_EVAL", "PY_SUBPROCESS_SHELL"}:
        return 80
    if rule_id in {"JS_LOCALSTORAGE_TOKEN"}:
        return 85
    severity = Severity(finding.severity)
    if severity == Severity.HIGH:
        return 85
    if severity == Severity.CRITICAL:
        return 75
    return 100


def _downgrade_severity(severity: Severity, steps: int = 1) -> Severity:
    """Downgrade a severity by the requested number of levels."""
    order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    index = order.index(Severity(severity))
    return order[max(0, index - steps)]


def _is_high_confidence_secret(finding: Finding) -> bool:
    """Identify real-looking secrets that should resist context downgrades."""
    rule_id = finding.rule_id.upper()
    if "PRIVATE_KEY" in rule_id:
        return True
    return rule_id.startswith("SECRETS_VALUE_") and any(
        marker in rule_id
        for marker in ("OPENAI", "GITHUB", "GOOGLE", "AWS", "PRIVATE_KEY")
    )


def _normalize_finding_for_context(finding: Finding) -> Optional[Finding]:
    """Apply context-aware severity adjustments before scoring and display."""
    original_severity = Severity(finding.severity)
    finding.original_severity = original_severity
    context = FileContext(finding.file_context)
    if context == FileContext.GENERATED_DEPENDENCY:
        finding.adjusted_severity_reason = "ignored generated/dependency file"
        return None

    severity = Severity(finding.severity)
    if _is_real_env_or_config_finding(finding):
        finding.adjusted_severity_reason = "real env/config files keep full severity"
        return finding

    if context == FileContext.PRODUCTION:
        finding.adjusted_severity_reason = "production/application code keeps full severity"
        return finding

    if context == FileContext.TEST_DEMO:
        steps = 2 if _is_demo_fixture_path(finding.file) else 1
        if _is_high_confidence_secret(finding):
            steps = 0 if not _is_demo_fixture_path(finding.file) else 1
        finding.severity = _downgrade_severity(severity, steps)
        finding.adjusted_severity_reason = f"test/demo context downgraded severity by {steps} level(s)"
        return finding

    if context == FileContext.EXAMPLE_TEMPLATE:
        if _is_high_confidence_secret(finding):
            finding.severity = _downgrade_severity(severity, 1)
            finding.adjusted_severity_reason = "example/template high-confidence secret downgraded by 1 level"
        elif _is_documentation_path(finding.file):
            finding.severity = Severity.LOW
            finding.adjusted_severity_reason = "documentation examples are capped at low severity"
        else:
            finding.severity = _downgrade_severity(severity, 2)
            finding.adjusted_severity_reason = "example/template context downgraded severity by 2 levels"
        return finding

    finding.adjusted_severity_reason = "no context adjustment applied"
    return finding


def _is_example_or_template_finding(finding: Finding) -> bool:
    """Identify findings from example/template config files for reduced scoring impact."""
    filename = Path(finding.file).name.lower()
    return (
        filename in EXAMPLE_ENV_FILENAMES
        or FileContext(finding.file_context) == FileContext.EXAMPLE_TEMPLATE
        or any(finding.rule_id.startswith(prefix) for prefix in EXAMPLE_FINDING_RULE_PREFIXES)
    )


def classify_file_context(file_path: str) -> FileContext:
    """Classify a relative file path for scoring and display."""
    path_parts = _path_parts(file_path)
    parts = {part.lower() for part in path_parts}
    filename = path_parts[-1].lower() if path_parts else ""
    stem = Path(filename).stem.lower()

    if parts & GENERATED_DEPENDENCY_DIRS:
        return FileContext.GENERATED_DEPENDENCY
    if _is_real_env_filename(filename):
        return FileContext.PRODUCTION
    if filename in EXAMPLE_ENV_FILENAMES or filename in README_FILENAMES:
        return FileContext.EXAMPLE_TEMPLATE
    if parts & TEST_DEMO_PARTS or stem.endswith((".test", ".spec")) or stem.startswith("debug"):
        return FileContext.TEST_DEMO
    if parts & EXAMPLE_TEMPLATE_PARTS or filename.endswith((".example", ".sample", ".template")):
        return FileContext.EXAMPLE_TEMPLATE

    return FileContext.PRODUCTION


def _is_demo_fixture_path(file_path: str) -> bool:
    path_parts = _path_parts(file_path)
    parts = {part.lower() for part in path_parts}
    filename = path_parts[-1].lower() if path_parts else ""
    return filename in DEMO_FIXTURE_PARTS or bool(parts & DEMO_FIXTURE_PARTS)


def _is_documentation_path(file_path: str) -> bool:
    path_parts = _path_parts(file_path)
    parts = {part.lower() for part in path_parts}
    filename = path_parts[-1].lower() if path_parts else ""
    return filename in README_FILENAMES or bool(parts & {"doc", "docs", "documentation"})


def _path_parts(file_path: str) -> List[str]:
    """Split paths consistently across ZIP-style and OS-native separators."""
    return [part for part in file_path.replace("\\", "/").split("/") if part]


def _filename(file_path: str) -> str:
    parts = _path_parts(file_path)
    return parts[-1].lower() if parts else ""


def _is_real_env_filename(filename: str) -> bool:
    return (
        filename not in ENV_TEMPLATE_FILENAMES
        and (filename == ".env" or filename.startswith(".env."))
    )


def _count_files_under(root: str, dirs: List[str]) -> int:
    """Count files below directories that are about to be skipped."""
    total = 0
    for dirname in dirs:
        dir_path = os.path.join(root, dirname)
        for _, _, files in os.walk(dir_path):
            total += len(files)
    return total


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


def scan_directory(extract_dir: str, stats: Optional[ScanStats] = None) -> List[Finding]:
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
        skipped_dirs = [
            d for d in dirs
            if d.lower() in GENERATED_DEPENDENCY_DIRS or d.lower() == ".cache"
        ]
        if stats and skipped_dirs:
            skipped_files = _count_files_under(root, skipped_dirs)
            stats.ignored_files += skipped_files
            stats.skipped_generated_dependency_files += skipped_files

        # Filter out excluded directories
        dirs[:] = [d for d in dirs if d not in skipped_dirs]
        
        for filename in files:
            file_path = os.path.join(root, filename)
            
            # Get relative path for reporting
            rel_path = os.path.relpath(file_path, extract_dir)
            
            # Skip if file should be skipped
            if should_skip_file(rel_path):
                if stats:
                    stats.ignored_files += 1
                    if classify_file_context(rel_path) == FileContext.GENERATED_DEPENDENCY:
                        stats.skipped_generated_dependency_files += 1
                continue
            
            # Check file size (skip files > 1MB)
            try:
                if os.path.getsize(file_path) > 1 * 1024 * 1024:
                    if stats:
                        stats.ignored_files += 1
                    continue
            except Exception:
                if stats:
                    stats.ignored_files += 1
                continue
            
            # Get scanner key
            scanner_key = _scanner_key(filename)
            file_context = classify_file_context(rel_path)
            if stats:
                stats.scanned_files += 1
            
            # Run all applicable scanners
            try:
                # Run extension-specific scanner
                if scanner_key in SCANNER_MAP:
                    scanner_func = SCANNER_MAP[scanner_key]
                    file_findings = scanner_func(file_path)
                    
                    # Normalize file paths to use forward slashes and relative paths
                    for finding in file_findings:
                        finding.file = rel_path.replace("\\", "/")
                        finding.file_context = file_context
                        finding = _normalize_finding_for_context(finding)
                        if finding is None:
                            continue
                        
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
                if scanner_key in SECRET_SCAN_KEYS:
                    secret_findings = secrets.scan(file_path)
                    for finding in secret_findings:
                        finding.file = rel_path.replace("\\", "/")
                        finding.file_context = file_context
                        finding = _normalize_finding_for_context(finding)
                        if finding is None:
                            continue
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
