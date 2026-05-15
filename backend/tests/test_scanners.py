"""Tests for scanner modules."""
import pytest
import tempfile
import os
from app.scanners import secrets, javascript, python, config
from app.models import FileContext, Finding, Severity, Category
from app.services.scanner import ScanStats, classify_file_context, generate_summary, scan_directory


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
            # Placeholder values are tracked as low-confidence poor practice, not critical leaks.
            assert findings
            assert all(finding.severity == Severity.LOW for finding in findings)
            assert not any(finding.severity == Severity.CRITICAL for finding in findings)
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

    def test_static_subprocess_shell_true_is_high_not_critical(self):
        """Test static shell=True commands are serious but not automatically critical."""
        content = 'import subprocess\nsubprocess.run("ls", shell=True)\n'
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(content)
            f.flush()
            temp_name = f.name

        try:
            findings = python.scan(temp_name)
            shell_findings = [
                finding for finding in findings
                if finding.rule_id == "PY_SUBPROCESS_SHELL"
            ]
            assert shell_findings
            assert all(finding.severity == Severity.HIGH for finding in shell_findings)
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

    def test_detect_env_local_file(self):
        """Test detection of .env.local as a real environment file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_name = os.path.join(temp_dir, ".env.local")
            with open(temp_name, "w", encoding="utf-8") as f:
                f.write("DATABASE_URL=postgres://user:pass@localhost/db\n")

            findings = config.scan(temp_name)
            assert any(f.rule_id == "CONFIG_ENV_FILE" for f in findings)

    @pytest.mark.parametrize("filename", [".env.example", ".env.sample"])
    def test_example_env_files_do_not_trigger_env_file_found(self, filename):
        """Test that template env files are not treated as real .env files."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_name = os.path.join(temp_dir, filename)
            with open(temp_name, "w", encoding="utf-8") as f:
                f.write("GEMINI_API_KEY=YOUR_KEY_HERE\n")

            findings = config.scan(temp_name)
            assert not any(f.rule_id == "CONFIG_ENV_FILE" for f in findings)

    def test_example_env_placeholder_secret_is_ignored(self):
        """Test clear placeholders in example env files are not treated as real secrets."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_name = os.path.join(temp_dir, ".env.example")
            with open(temp_name, "w", encoding="utf-8") as f:
                f.write("GEMINI_API_KEY=YOUR_KEY_HERE\n")

            findings = config.scan(temp_name)
            assert not findings

    def test_example_env_next_public_placeholder_is_low_or_ignored(self):
        """Test NEXT_PUBLIC placeholders in example env files are not critical."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_name = os.path.join(temp_dir, ".env.example")
            with open(temp_name, "w", encoding="utf-8") as f:
                f.write("NEXT_PUBLIC_GEMINI_API_KEY=YOUR_KEY_HERE\n")

            findings = config.scan(temp_name)
            assert not any(f.severity in {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM} for f in findings)

    def test_example_env_next_public_suspicious_value_is_medium(self):
        """Test suspicious example NEXT_PUBLIC secret-like values are medium, not critical."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_name = os.path.join(temp_dir, ".env.example")
            with open(temp_name, "w", encoding="utf-8") as f:
                f.write("NEXT_PUBLIC_GEMINI_API_KEY=secret123\n")

            findings = config.scan(temp_name)
            next_public_findings = [
                finding for finding in findings
                if finding.rule_id == "CONFIG_EXAMPLE_NEXT_PUBLIC_SECRET_LIKE"
            ]
            assert next_public_findings
            assert all(finding.severity == Severity.MEDIUM for finding in next_public_findings)
            assert not any(f.severity == Severity.CRITICAL for f in findings)
    
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

    def test_scan_directory_records_file_context_and_stats(self):
        """Test scan stats and file context classification."""
        with tempfile.TemporaryDirectory() as temp_dir:
            os.makedirs(os.path.join(temp_dir, "tests"), exist_ok=True)
            os.makedirs(os.path.join(temp_dir, "node_modules", "pkg"), exist_ok=True)
            with open(os.path.join(temp_dir, "tests", "bad.py"), "w", encoding="utf-8") as f:
                f.write("def run(user_input):\n    return eval(user_input)\n")
            with open(os.path.join(temp_dir, "README.md"), "w", encoding="utf-8") as f:
                f.write("OPENAI_API_KEY = \"sk-proj-realLookingValue123456\"\n")
            with open(os.path.join(temp_dir, "node_modules", "pkg", "bad.js"), "w", encoding="utf-8") as f:
                f.write("eval(code)\n")
            with open(os.path.join(temp_dir, "notes.txt"), "w", encoding="utf-8") as f:
                f.write("plain text\n")

            stats = ScanStats()
            findings = scan_directory(temp_dir, stats)

            assert stats.scanned_files == 2
            assert stats.ignored_files == 2
            assert stats.skipped_generated_dependency_files == 1
            assert any(f.file_context == FileContext.TEST_DEMO for f in findings)

    def test_classify_file_contexts(self):
        """Test important file context classifications."""
        assert classify_file_context("src/app.py") == FileContext.PRODUCTION
        assert classify_file_context("tests/test_app.py") == FileContext.TEST_DEMO
        assert classify_file_context("docs/README.md") == FileContext.EXAMPLE_TEMPLATE
        assert classify_file_context(".env.example") == FileContext.EXAMPLE_TEMPLATE
        assert classify_file_context("BadRepo/fixtures/bad.py") == FileContext.TEST_DEMO
        assert classify_file_context("node_modules/pkg/index.js") == FileContext.GENERATED_DEPENDENCY

    @pytest.mark.parametrize(
        "dirname",
        ["node_modules", ".next", "dist", "build", "coverage", ".git", "venv", "__pycache__"],
    )
    def test_default_generated_dependency_folders_are_classified(self, dirname):
        """Test default ignored folders are generated/dependency context."""
        assert classify_file_context(f"{dirname}/file.js") == FileContext.GENERATED_DEPENDENCY

    def test_scan_directory_example_env_placeholder_keeps_high_score(self):
        """Test example env placeholder findings do not collapse the score."""
        with tempfile.TemporaryDirectory() as temp_dir:
            env_path = os.path.join(temp_dir, ".env.example")
            with open(env_path, "w", encoding="utf-8") as f:
                f.write("NEXT_PUBLIC_GEMINI_API_KEY=YOUR_KEY_HERE\n")

            stats = ScanStats()
            findings = scan_directory(temp_dir, stats)
            summary = generate_summary(findings, stats)

            assert not any(finding.rule_id == "CONFIG_ENV_FILE" for finding in findings)
            assert all(finding.file_context == FileContext.EXAMPLE_TEMPLATE for finding in findings)
            assert summary.score >= 90

    def test_scan_directory_example_env_suspicious_value_does_not_score_zero(self):
        """Test suspicious example env values are reduced-impact findings."""
        with tempfile.TemporaryDirectory() as temp_dir:
            env_path = os.path.join(temp_dir, ".env.example")
            with open(env_path, "w", encoding="utf-8") as f:
                f.write("NEXT_PUBLIC_GEMINI_API_KEY=secret123\n")

            findings = scan_directory(temp_dir)
            summary = generate_summary(findings)

            assert any(finding.severity == Severity.LOW for finding in findings)
            assert not any(finding.severity == Severity.CRITICAL for finding in findings)
            assert summary.score >= 98

    def test_fixture_demo_docs_only_repo_does_not_become_critical_risk(self):
        """Test intentionally bad fixtures/docs do not dominate repo risk."""
        with tempfile.TemporaryDirectory() as temp_dir:
            os.makedirs(os.path.join(temp_dir, "src"), exist_ok=True)
            os.makedirs(os.path.join(temp_dir, "BadRepo", "fixtures"), exist_ok=True)
            os.makedirs(os.path.join(temp_dir, "tests"), exist_ok=True)

            with open(os.path.join(temp_dir, "src", "app.py"), "w", encoding="utf-8") as f:
                f.write("def add(a, b):\n    return a + b\n")
            with open(os.path.join(temp_dir, "BadRepo", "fixtures", "bad.py"), "w", encoding="utf-8") as f:
                f.write("def run(user_input):\n    eval(user_input)\n    exec(user_input)\n")
            with open(os.path.join(temp_dir, "README.md"), "w", encoding="utf-8") as f:
                f.write('API_KEY = "secret123"\n')
            with open(os.path.join(temp_dir, ".env.example"), "w", encoding="utf-8") as f:
                f.write("GEMINI_API_KEY=YOUR_KEY_HERE\n")
            with open(os.path.join(temp_dir, "tests", "test_config.py"), "w", encoding="utf-8") as f:
                f.write('JWT_SECRET = "dummy"\n')

            stats = ScanStats()
            findings = scan_directory(temp_dir, stats)
            summary = generate_summary(findings, stats)

            assert findings
            assert not any(
                finding.file_context == FileContext.PRODUCTION
                and finding.severity == Severity.CRITICAL
                for finding in findings
            )
            assert summary.score >= 50
            assert summary.test_demo_penalty > 0
            assert summary.documentation_template_penalty > 0

    def test_real_production_critical_repo_can_score_very_low(self):
        """Test production critical issues can still drive a very low score."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with open(os.path.join(temp_dir, ".env"), "w", encoding="utf-8") as f:
                f.write("OPENAI_API_KEY=sk-proj-realLookingValue123456789\n")
            with open(os.path.join(temp_dir, "app.py"), "w", encoding="utf-8") as f:
                f.write(
                    'import subprocess\n'
                    'token = "ghp_1234567890abcdef1234567890abcdef1234"\n'
                    'def run(user_input):\n'
                    '    eval(user_input)\n'
                    '    subprocess.run(user_input, shell=True)\n'
                )

            stats = ScanStats()
            findings = scan_directory(temp_dir, stats)
            summary = generate_summary(findings, stats)

            production_critical = [
                finding for finding in findings
                if finding.file_context == FileContext.PRODUCTION
                and finding.severity == Severity.CRITICAL
            ]
            assert len(production_critical) >= 3
            assert summary.score <= 25
            assert summary.production_penalty + summary.real_env_config_penalty > 0

    def test_small_zip_with_real_env_and_root_app_code_is_not_healthy(self):
        """Regression test for real env/root app files being over-discounted."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with open(os.path.join(temp_dir, ".env"), "w", encoding="utf-8") as f:
                f.write("NEXT_PUBLIC_GEMINI_API_KEY=secret123\n")
            with open(os.path.join(temp_dir, ".env.example"), "w", encoding="utf-8") as f:
                f.write("NEXT_PUBLIC_GEMINI_API_KEY=YOUR_KEY_HERE\n")
            with open(os.path.join(temp_dir, "app.js"), "w", encoding="utf-8") as f:
                f.write(
                    "function run(userInput, token) {\n"
                    "  eval(userInput);\n"
                    "  localStorage.setItem(\"jwt\", token);\n"
                    "}\n"
                )
            with open(os.path.join(temp_dir, "config.py"), "w", encoding="utf-8") as f:
                f.write(
                    "import subprocess\n"
                    "OPENAI_API_KEY = \"YOUR_API_KEY_HERE\"\n"
                    "subprocess.run(\"ls\", shell=True)\n"
                    "key = \"sk_test_abc\"\n"
                )

            stats = ScanStats()
            findings = scan_directory(temp_dir, stats)
            summary = generate_summary(findings, stats)

            env_findings = [finding for finding in findings if finding.file == ".env"]
            example_findings = [finding for finding in findings if finding.file == ".env.example"]
            app_findings = [finding for finding in findings if finding.file == "app.js"]
            config_findings = [finding for finding in findings if finding.file == "config.py"]

            assert env_findings
            assert all(finding.file_context == FileContext.PRODUCTION for finding in env_findings)
            assert any(finding.rule_id == "CONFIG_ENV_FILE" for finding in env_findings)
            assert any(finding.rule_id == "CONFIG_NEXT_PUBLIC_API_KEY" for finding in env_findings)
            assert all(finding.file_context == FileContext.EXAMPLE_TEMPLATE for finding in example_findings)
            assert all(finding.file_context == FileContext.PRODUCTION for finding in app_findings)
            assert all(finding.file_context == FileContext.PRODUCTION for finding in config_findings)
            assert any(finding.rule_id == "JS_EVAL" for finding in app_findings)
            assert any(finding.rule_id == "JS_LOCALSTORAGE_TOKEN" for finding in app_findings)
            assert any(finding.rule_id == "PY_SUBPROCESS_SHELL" for finding in config_findings)
            assert any(
                finding.rule_id == "SECRETS_OPENAI_API_KEY"
                and finding.severity in {Severity.LOW, Severity.MEDIUM}
                for finding in config_findings
            )
            assert summary.production_penalty > 0
            assert summary.real_env_config_penalty > 0
            assert summary.test_demo_penalty == 0
            assert summary.documentation_template_penalty <= 1
            assert 35 <= summary.score <= 65
            assert summary.risk_label != "Healthy"

            for finding in findings:
                assert finding.original_severity is not None
                assert finding.adjusted_severity_reason
                assert finding.score_penalty >= 0

    def test_real_env_and_env_example_use_separate_score_buckets(self):
        """Test real env findings explain under env/config, not production/templates."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with open(os.path.join(temp_dir, ".env"), "w", encoding="utf-8") as f:
                f.write("NEXT_PUBLIC_GEMINI_API_KEY=secret123\n")
            with open(os.path.join(temp_dir, ".env.example"), "w", encoding="utf-8") as f:
                f.write("NEXT_PUBLIC_GEMINI_API_KEY=YOUR_KEY_HERE\n")

            stats = ScanStats()
            findings = scan_directory(temp_dir, stats)
            summary = generate_summary(findings, stats)

            real_env_findings = [finding for finding in findings if finding.file == ".env"]
            template_findings = [finding for finding in findings if finding.file == ".env.example"]

            assert real_env_findings
            assert template_findings
            assert summary.real_env_config_penalty > 0
            assert summary.production_penalty == 0
            assert summary.documentation_template_penalty > 0
            assert summary.score < 90
            assert summary.score > 20
            assert all(
                "real env/config" in finding.adjusted_severity_reason
                for finding in real_env_findings
            )
            assert all(
                finding.file_context == FileContext.EXAMPLE_TEMPLATE
                for finding in template_findings
            )

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

    def _finding(
        self,
        severity: Severity,
        category: Category = Category.SECRETS,
        file_context: FileContext = FileContext.PRODUCTION,
    ) -> Finding:
        return Finding(
            rule_id=f"TEST_{severity.value.upper()}",
            title="Test finding",
            severity=severity,
            category=category,
            file="test.py",
            line=1,
            evidence="test",
            recommendation="fix it",
            file_context=file_context,
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

        assert summary.score == 62

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
        assert summary.score == 98

    def test_summary_many_critical_clamps_to_zero(self):
        """Test repeated critical findings have diminishing impact."""
        findings = [
            self._finding(Severity.CRITICAL),
            self._finding(Severity.CRITICAL),
            self._finding(Severity.CRITICAL),
        ]

        summary = generate_summary(findings)

        assert summary.critical == 3
        assert summary.score > 0

    def test_summary_serious_mix_stays_critical_but_not_single_digit(self):
        """Test several serious findings have gradation above catastrophic scores."""
        findings = [
            self._finding(Severity.CRITICAL, Category.DANGEROUS_CODE),
            self._finding(Severity.CRITICAL, Category.SECRETS),
            self._finding(Severity.HIGH, Category.EXPOSURE),
            self._finding(Severity.HIGH, Category.DANGEROUS_CODE),
            self._finding(Severity.HIGH, Category.SECRETS),
            self._finding(Severity.MEDIUM, Category.CORS),
            self._finding(Severity.LOW, Category.EXPOSURE),
        ]

        summary = generate_summary(findings)

        assert summary.critical == 2
        assert 25 <= summary.score <= 40

    def test_summary_test_and_example_context_have_reduced_impact(self):
        """Test demo/example findings are discounted compared with production code."""
        production = generate_summary([self._finding(Severity.CRITICAL)]).score
        demo = generate_summary([
            self._finding(Severity.CRITICAL, file_context=FileContext.TEST_DEMO)
        ]).score
        example = generate_summary([
            self._finding(Severity.CRITICAL, file_context=FileContext.EXAMPLE_TEMPLATE)
        ]).score

        assert production < demo < example

    def test_summary_example_template_findings_have_reduced_impact(self):
        """Test example/template env findings do not over-penalize the score."""
        finding = self._finding(Severity.MEDIUM)
        finding.rule_id = "CONFIG_EXAMPLE_NEXT_PUBLIC_SECRET_LIKE"
        finding.file = ".env.example"
        finding.file_context = FileContext.EXAMPLE_TEMPLATE

        summary = generate_summary([finding])

        assert summary.score >= 98

    def test_summary_multiple_distinct_catastrophic_findings_can_score_single_digit(self):
        """Test catastrophic confirmed findings can still produce a near-zero score."""
        categories = [
            Category.SECRETS,
            Category.DANGEROUS_CODE,
            Category.CONFIG,
            Category.EXPOSURE,
        ]
        findings = []
        for index, category in enumerate(categories):
            finding = self._finding(Severity.CRITICAL, category)
            finding.rule_id = f"TEST_PRIVATE_KEY_CRITICAL_{index}"
            findings.append(finding)

        summary = generate_summary(findings)

        assert summary.critical == 4
        assert summary.score <= 10

    def test_risk_moderate_with_critical_only_in_demo_files(self):
        """Test demo-only critical findings do not force high/critical risk."""
        findings = [
            self._finding(Severity.CRITICAL, file_context=FileContext.TEST_DEMO),
            self._finding(Severity.HIGH, Category.EXPOSURE),
            self._finding(Severity.HIGH, Category.CORS),
            self._finding(Severity.MEDIUM, Category.CONFIG),
        ]
        for index, finding in enumerate(findings):
            finding.rule_id = f"TEST_RISK_DEMO_{index}"

        summary = generate_summary(findings)

        assert summary.risk_label == "Moderate Risk"
        assert "non-production files" in summary.warning_message
        assert "Fix immediately" not in summary.warning_message
        assert summary.test_demo_critical_count == 1
        assert summary.production_critical_count == 0

    def test_risk_high_with_one_production_critical(self):
        """Test one production critical issue raises moderate scores to high risk."""
        findings = [
            self._finding(Severity.CRITICAL, Category.SECRETS),
            self._finding(Severity.HIGH, Category.CORS),
            self._finding(Severity.MEDIUM, Category.CONFIG),
        ]
        for index, finding in enumerate(findings):
            finding.rule_id = f"TEST_RISK_PROD_{index}"

        summary = generate_summary(findings)

        assert summary.score >= 46
        assert summary.risk_label == "High Risk"
        assert summary.warning_message == "1 critical production/env issue found. Fix before deploying."
        assert summary.production_critical_count == 1

    def test_risk_critical_with_multiple_production_env_critical(self):
        """Test multiple production/env critical issues force critical risk."""
        prod = self._finding(Severity.CRITICAL, Category.DANGEROUS_CODE)
        env = self._finding(Severity.CRITICAL, Category.SECRETS)
        env.file = ".env"
        env.rule_id = "CONFIG_NEXT_PUBLIC_API_KEY"

        summary = generate_summary([prod, env])

        assert summary.risk_label == "Critical Risk"
        assert summary.warning_message == "Critical production/env issues found. Fix immediately before deploying."
        assert summary.production_critical_count == 1
        assert summary.env_critical_count == 1

    def test_risk_clean_scan_message(self):
        """Test no findings use a clean message."""
        summary = generate_summary([])

        assert summary.risk_label == "Healthy"
        assert summary.warning_message == "No security issues found in scanned application files."

    def test_many_demo_findings_do_not_use_deploy_blocker_wording(self):
        """Test many demo/test findings do not get deploy-blocker wording."""
        findings = []
        for index in range(10):
            finding = self._finding(
                Severity.HIGH,
                Category.DANGEROUS_CODE,
                file_context=FileContext.TEST_DEMO,
            )
            finding.rule_id = f"TEST_DEMO_HIGH_{index}"
            findings.append(finding)

        summary = generate_summary(findings)

        assert "test/demo" in summary.warning_message
        assert "Fix immediately" not in summary.warning_message
        assert summary.production_critical_count == 0

    def test_high_production_issue_prevents_healthy_label(self):
        """Test production/env high findings keep an otherwise high score from looking healthy."""
        finding = self._finding(Severity.HIGH, Category.DANGEROUS_CODE)

        summary = generate_summary([finding])

        assert summary.score >= 80
        assert summary.risk_label == "Low Risk"
