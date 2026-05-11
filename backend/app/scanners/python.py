"""Dangerous Python patterns detection."""
import ast
import re
from typing import List
from app.models import Finding, Severity, Category


class DangerousCallVisitor(ast.NodeVisitor):
    """AST visitor to find dangerous function calls."""
    
    def __init__(self, lines: List[str], file_path: str):
        self.findings = []
        self.lines = lines
        self.file_path = file_path
    
    def visit_Call(self, node):
        """Visit function call nodes."""
        # Check for eval()
        if isinstance(node.func, ast.Name) and node.func.id == "eval":
            self.findings.append(Finding(
                rule_id="PY_EVAL",
                title="eval() usage detected",
                severity=Severity.HIGH,
                category=Category.DANGEROUS_CODE,
                file=self.file_path,
                line=node.lineno,
                evidence=self._get_line_text(node.lineno),
                recommendation="Replace eval() with safer alternatives like ast.literal_eval() for data parsing."
            ))
        
        # Check for exec()
        if isinstance(node.func, ast.Name) and node.func.id == "exec":
            self.findings.append(Finding(
                rule_id="PY_EXEC",
                title="exec() usage detected",
                severity=Severity.CRITICAL,
                category=Category.DANGEROUS_CODE,
                file=self.file_path,
                line=node.lineno,
                evidence=self._get_line_text(node.lineno),
                recommendation="Avoid exec(). Use safer alternatives or pre-compiled code."
            ))
        
        # Check for subprocess with shell=True
        if self._is_subprocess_shell_true(node):
            self.findings.append(Finding(
                rule_id="PY_SUBPROCESS_SHELL",
                title="subprocess call with shell=True",
                severity=Severity.CRITICAL,
                category=Category.DANGEROUS_CODE,
                file=self.file_path,
                line=node.lineno,
                evidence=self._get_line_text(node.lineno),
                recommendation="Use subprocess without shell=True. Pass list of arguments instead of shell string."
            ))
        
        self.generic_visit(node)
    
    def _is_subprocess_shell_true(self, node):
        """Check if a call is subprocess with shell=True."""
        # Check for subprocess.run/call/Popen with shell=True
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ("run", "call", "Popen", "check_call", "check_output"):
                # Check if subprocess module
                if isinstance(node.func.value, ast.Name):
                    if node.func.value.id in ("subprocess",):
                        # Check for shell=True keyword argument
                        for keyword in node.keywords:
                            if keyword.arg == "shell":
                                if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                                    return True
                                if isinstance(keyword.value, ast.NameConstant) and keyword.value.value is True:
                                    return True
        return False
    
    def _get_line_text(self, line_num):
        """Get the line text for evidence."""
        if line_num <= len(self.lines):
            text = self.lines[line_num - 1].strip()[:80]
            if len(self.lines[line_num - 1].strip()) > 80:
                text += "..."
            return text
        return "Code line"


def scan(file_path: str) -> List[Finding]:
    """
    Scan a Python file for dangerous patterns.
    
    Uses AST parsing for eval(), exec(), and subprocess(shell=True).
    Uses regex for pickle.loads() and yaml.load() without SafeLoader.
    """
    findings = []
    
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            lines = content.split("\n")
    except Exception:
        return findings
    
    # AST-based detection
    try:
        tree = ast.parse(content)
        visitor = DangerousCallVisitor(lines, file_path)
        visitor.visit(tree)
        findings.extend(visitor.findings)
    except SyntaxError:
        # If AST parsing fails, fall back to regex
        pass
    
    # Regex-based detection for pickle and yaml
    
    # pickle.loads pattern
    pickle_pattern = r"pickle\.loads\s*\("
    for line_num, line in enumerate(lines, 1):
        if re.search(pickle_pattern, line):
            findings.append(Finding(
                rule_id="PY_PICKLE",
                title="pickle.loads() usage detected",
                severity=Severity.HIGH,
                category=Category.DANGEROUS_CODE,
                file=file_path,
                line=line_num,
                evidence=line.strip()[:80] + ("..." if len(line.strip()) > 80 else ""),
                recommendation="pickle.loads() can execute arbitrary code. Use safer serialization formats like JSON."
            ))
    
    # yaml.load without SafeLoader pattern
    yaml_unsafe_pattern = r"yaml\.load\s*\(\s*([^,)]*)\s*(?:[,)])"
    for line_num, line in enumerate(lines, 1):
        match = re.search(yaml_unsafe_pattern, line)
        if match:
            # Check if SafeLoader is specified
            if "SafeLoader" not in line and "safe_load" not in line:
                findings.append(Finding(
                    rule_id="PY_YAML_LOAD",
                    title="yaml.load() without SafeLoader",
                    severity=Severity.HIGH,
                    category=Category.DANGEROUS_CODE,
                    file=file_path,
                    line=line_num,
                    evidence=line.strip()[:80] + ("..." if len(line.strip()) > 80 else ""),
                    recommendation="Use yaml.safe_load() or specify Loader=yaml.SafeLoader explicitly."
                ))
    
    return findings
