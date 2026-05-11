"""Tests for scanner modules."""
import pytest
import tempfile
import os
from app.scanners import secrets, javascript, python, config
from app.models import Finding, Severity, Category
from app.services.scanner import generate_summary, scan_directory


class TestSecretsScanner:
    """Tests for secrets detection."""
    
    def test_detect_openai_key(self, sample_api_key_file):
        """Test detection of hardcoded OpenAI API key."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(sample_api_key_file)
            f.flush()
            temp_name = f.name
        
        try:
            findings = secrets.scan(temp_name)
            assert any("OPENAI_API_KEY" in f.title for f in findings)
            assert any(f.severity == Severity.CRITICAL for f in findings)
        finally:
            os.unlink(temp_name)
    
    def test_detect_generic_api_key(self, sample_api_key_file):
        """Test detection of generic API_KEY."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(sample_api_key_file)
            f.flush()
            temp_name = f.name
        
        try:
            findings = secrets.scan(temp_name)
            assert any("API Key" in f.title for f in findings)
        finally:
            os.unlink(temp_name)
    
    def test_false_positive_avoidance(self):
        """Test that false positives are avoided."""
        content = """
OPENAI_API_KEY = "your_api_key_here"
API_KEY = "example_key"
JWT_SECRET = "placeholder"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(content)
            f.flush()
            temp_name = f.name
        
        try:
            findings = secrets.scan(temp_name)
            # Should have no findings due to false positive avoidance
            assert len(findings) == 0
        finally:
            os.unlink(temp_name)

    def test_detect_openai_value_pattern(self, sample_openai_value_file):
        """Test detection of OpenAI-style value-based keys."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(sample_openai_value_file)
            f.flush()
            temp_name = f.name

        try:
            findings = secrets.scan(temp_name)
            assert any("OpenAI-style key" in finding.title for finding in findings)
            assert any(finding.severity == Severity.CRITICAL for finding in findings)
        finally:
            os.unlink(temp_name)

    def test_detect_github_token_value(self, sample_github_token_file):
        """Test detection of GitHub token values."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(sample_github_token_file)
            f.flush()
            temp_name = f.name

        try:
            findings = secrets.scan(temp_name)
            assert any("GitHub token" in finding.title for finding in findings)
            assert any("GitHub fine-grained token" in finding.title for finding in findings)
            assert any(finding.severity == Severity.CRITICAL for finding in findings)
        finally:
            os.unlink(temp_name)

    def test_detect_google_api_key_value(self, sample_google_api_value_file):
        """Test detection of Google API key values."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(sample_google_api_value_file)
            f.flush()
            temp_name = f.name

        try:
            findings = secrets.scan(temp_name)
            assert any("Google API key" in finding.title for finding in findings)
            assert any(finding.severity == Severity.CRITICAL for finding in findings)
        finally:
            os.unlink(temp_name)

    def test_detect_aws_access_key_value(self, sample_aws_access_key_value_file):
        """Test detection of AWS access key ID values."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(sample_aws_access_key_value_file)
            f.flush()
            temp_name = f.name

        try:
            findings = secrets.scan(temp_name)
            assert any("AWS access key ID" in finding.title for finding in findings)
            assert any(finding.severity == Severity.CRITICAL for finding in findings)
        finally:
            os.unlink(temp_name)

    def test_detect_private_key_block(self, sample_private_key_block_file):
        """Test detection of private key blocks."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as f:
            f.write(sample_private_key_block_file)
            f.flush()
            temp_name = f.name

        try:
            findings = secrets.scan(temp_name)
            assert any("Private key block" in finding.title for finding in findings)
            assert any(finding.severity == Severity.CRITICAL for finding in findings)
        finally:
            os.unlink(temp_name)

    def test_downgrade_test_openai_value(self, sample_openai_test_value_file):
        """Test that OpenAI-style test/demo values are not critical."""
        content = """
key = "sk_test_abc12345"
demo_key = "sk-demo-realLookingValue123"
sample_key = "sk-proj-sampleSecretValue123"
fake_key = "sk-proj-fakeSecretValue123"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(content)
            f.flush()
            temp_name = f.name

        try:
            findings = secrets.scan(temp_name)
            assert any("OpenAI-style key" in finding.title for finding in findings)
            assert all(finding.severity in {Severity.MEDIUM, Severity.LOW} for finding in findings)
            assert not any(finding.severity == Severity.CRITICAL for finding in findings)
        finally:
            os.unlink(temp_name)

    def test_detect_short_sk_test_value_as_non_critical(self):
        """Test that short sk_test_ values are detected but downgraded."""
        content = 'key = "sk_test_abc"\n'
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(content)
            f.flush()
            temp_name = f.name

        try:
            findings = secrets.scan(temp_name)
            assert any("OpenAI-style key" in finding.title for finding in findings)
            assert any(finding.severity in {Severity.MEDIUM, Severity.LOW} for finding in findings)
            assert not any(finding.severity == Severity.CRITICAL for finding in findings)
        finally:
            os.unlink(temp_name)

    def test_prefer_specific_name_over_value(self):
        """Test that a specific named secret suppresses the generic value-based duplicate."""
        content = 'OPENAI_API_KEY = "sk-proj-realLookingValue123456"\n'
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(content)
            f.flush()
            temp_name = f.name

        try:
            findings = secrets.scan(temp_name)
            assert len(findings) == 1
            assert any("OPENAI_API_KEY" in finding.title for finding in findings)
            assert not any("OpenAI-style key" in finding.title for finding in findings)
        finally:
            os.unlink(temp_name)


class TestJavaScriptScanner:
    """Tests for JavaScript/TypeScript dangerous patterns."""
    
    def test_detect_eval(self, sample_js_eval_file):
        """Test detection of eval()."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
            f.write(sample_js_eval_file)
            f.flush()
            temp_name = f.name
        
        try:
            findings = javascript.scan(temp_name)
            assert any("eval" in f.title.lower() for f in findings)
            assert any(f.severity == Severity.HIGH for f in findings)
        finally:
            os.unlink(temp_name)
    
    def test_detect_new_function(self, sample_js_function_file):
        """Test detection of new Function()."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
            f.write(sample_js_function_file)
            f.flush()
            temp_name = f.name
        
        try:
            findings = javascript.scan(temp_name)
            assert any("Function" in f.title for f in findings)
        finally:
            os.unlink(temp_name)
    
    def test_detect_dangerous_innerhtml(self, sample_js_dangerous_html_file):
        """Test detection of dangerouslySetInnerHTML."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".tsx", delete=False) as f:
            f.write(sample_js_dangerous_html_file)
            f.flush()
            temp_name = f.name
        
        try:
            findings = javascript.scan(temp_name)
            assert any("dangerouslySetInnerHTML" in f.title for f in findings)
        finally:
            os.unlink(temp_name)
    
    def test_detect_localstorage_token(self, sample_js_localstorage_file):
        """Test detection of token in localStorage."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
            f.write(sample_js_localstorage_file)
            f.flush()
            temp_name = f.name
        
        try:
            findings = javascript.scan(temp_name)
            assert any("localStorage" in f.title for f in findings)
        finally:
            os.unlink(temp_name)


class TestPythonScanner:
    """Tests for Python dangerous patterns."""
    
    def test_detect_eval(self, sample_eval_file):
        """Test AST-based detection of eval()."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(sample_eval_file)
            f.flush()
            temp_name = f.name
        
        try:
            findings = python.scan(temp_name)
            assert any("eval" in f.title.lower() for f in findings)
            assert any(f.severity == Severity.HIGH for f in findings)
        finally:
            os.unlink(temp_name)
    
    def test_detect_exec(self, sample_exec_file):
        """Test AST-based detection of exec()."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(sample_exec_file)
            f.flush()
            temp_name = f.name
        
        try:
            findings = python.scan(temp_name)
            assert any("exec" in f.title.lower() for f in findings)
            assert any(f.severity == Severity.CRITICAL for f in findings)
        finally:
            os.unlink(temp_name)
    
    def test_detect_pickle_loads(self, sample_pickle_file):
        """Test regex detection of pickle.loads()."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(sample_pickle_file)
            f.flush()
            temp_name = f.name
        
        try:
            findings = python.scan(temp_name)
            assert any("pickle" in f.title.lower() for f in findings)
        finally:
            os.unlink(temp_name)
    
    def test_detect_subprocess_shell_true(self, sample_subprocess_shell_file):
        """Test AST-based detection of subprocess(shell=True)."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(sample_subprocess_shell_file)
            f.flush()
            temp_name = f.name
        
        try:
            findings = python.scan(temp_name)
            assert any("subprocess" in f.title.lower() for f in findings)
            assert any(f.severity == Severity.CRITICAL for f in findings)
        finally:
            os.unlink(temp_name)
    
    def test_detect_yaml_unsafe_load(self, sample_yaml_unsafe_file):
        """Test detection of yaml.load without SafeLoader."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(sample_yaml_unsafe_file)
            f.flush()
            temp_name = f.name
        
        try:
            findings = python.scan(temp_name)
            assert any("yaml" in f.title.lower() for f in findings)
        finally:
            os.unlink(temp_name)


class TestConfigScanner:
    """Tests for configuration issues."""
    
    def test_detect_env_file(self):
        """Test detection of .env file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_name = os.path.join(temp_dir, ".env")
            with open(temp_name, "w", encoding="utf-8") as f:
                f.write("DATABASE_URL=postgres://user:pass@localhost/db\n")

            findings = config.scan(temp_name)
            assert any(".env" in f.title for f in findings)
            assert any(f.category == Category.EXPOSURE for f in findings)
    
    def test_detect_cors_wildcard(self, sample_cors_wildcard_file):
        """Test detection of CORS allow_origins=["*"]."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(sample_cors_wildcard_file)
            f.flush()
            temp_name = f.name
        
        try:
            findings = config.scan(temp_name)
            assert any("CORS" in f.title for f in findings)
            assert any(f.category == Category.CORS for f in findings)
        finally:
            os.unlink(temp_name)
    
    def test_detect_next_public_secret(self, sample_next_public_secret_file):
        """Test detection of NEXT_PUBLIC_ secrets."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_name = os.path.join(temp_dir, ".env")
            with open(temp_name, "w", encoding="utf-8") as f:
                f.write(sample_next_public_secret_file)

            findings = config.scan(temp_name)
            assert any("NEXT_PUBLIC_" in f.evidence for f in findings)
            assert any(f.category == Category.EXPOSURE for f in findings)


class TestScannerOrchestrator:
    """Tests for scanner orchestration across real project files."""

    def test_scan_directory_includes_root_env_file(self):
        """Test that root .env files are not skipped as extensionless files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            env_path = os.path.join(temp_dir, ".env")
            with open(env_path, "w", encoding="utf-8") as f:
                f.write("NEXT_PUBLIC_GEMINI_API_KEY=secret123\n")

            findings = scan_directory(temp_dir)

            assert any(finding.rule_id == "CONFIG_ENV_FILE" for finding in findings)
            assert any(finding.rule_id == "CONFIG_NEXT_PUBLIC_API_KEY" for finding in findings)

    def test_scan_directory_detects_sk_test_value(self):
        """Test that value-based scanning runs and downgrades sk_test_ values."""
        with tempfile.TemporaryDirectory() as temp_dir:
            py_path = os.path.join(temp_dir, "config.py")
            with open(py_path, "w", encoding="utf-8") as f:
                f.write('key = "sk_test_abc"\n')

            findings = scan_directory(temp_dir)

            value_findings = [
                finding for finding in findings
                if finding.rule_id == "SECRETS_VALUE_OPENAI_VALUE"
            ]
            assert value_findings
            assert all(finding.severity in {Severity.MEDIUM, Severity.LOW} for finding in value_findings)


class TestScanSummary:
    """Tests for scan summary and risk scoring."""

    def _finding(self, severity: Severity) -> Finding:
        return Finding(
            rule_id=f"TEST_{severity.value.upper()}",
            title="Test finding",
            severity=severity,
            category=Category.SECRETS,
            file="test.py",
            line=1,
            evidence="test",
            recommendation="fix it",
        )

    def test_summary_counts_match_findings(self):
        """Test summary counts by severity."""
        findings = [
            self._finding(Severity.CRITICAL),
            self._finding(Severity.CRITICAL),
            self._finding(Severity.HIGH),
            self._finding(Severity.MEDIUM),
            self._finding(Severity.LOW),
        ]

        summary = generate_summary(findings)

        assert summary.total == 5
        assert summary.critical == 2
        assert summary.high == 1
        assert summary.medium == 1
        assert summary.low == 1

    def test_summary_score_calculation(self):
        """Test weighted score calculation."""
        findings = [
            self._finding(Severity.CRITICAL),
            self._finding(Severity.HIGH),
            self._finding(Severity.MEDIUM),
            self._finding(Severity.LOW),
        ]

        summary = generate_summary(findings)

        assert summary.score == 25

    def test_summary_no_findings_score_is_100(self):
        """Test empty scans keep a perfect score."""
        summary = generate_summary([])

        assert summary.total == 0
        assert summary.score == 100

    def test_summary_only_low_findings_small_deduction(self):
        """Test low findings have a small score impact."""
        findings = [
            self._finding(Severity.LOW),
            self._finding(Severity.LOW),
        ]

        summary = generate_summary(findings)

        assert summary.low == 2
        assert summary.score == 90

    def test_summary_many_critical_clamps_to_zero(self):
        """Test score cannot go below zero."""
        findings = [
            self._finding(Severity.CRITICAL),
            self._finding(Severity.CRITICAL),
            self._finding(Severity.CRITICAL),
        ]

        summary = generate_summary(findings)

        assert summary.critical == 3
        assert summary.score == 0
