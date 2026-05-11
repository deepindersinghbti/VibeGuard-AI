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
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 10,
    Severity.LOW: 5,
}


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

    deduction = sum(counts[severity] * weight for severity, weight in RISK_WEIGHTS.items())
    score = max(0, min(100, 100 - deduction))

    return ScanSummary(
        total=len(findings),
        critical=counts[Severity.CRITICAL],
        high=counts[Severity.HIGH],
        medium=counts[Severity.MEDIUM],
        low=counts[Severity.LOW],
        score=score,
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
