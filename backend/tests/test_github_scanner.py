"""Tests for GitHub repository scanning."""
import os
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services import github_scanner


@pytest.fixture
def client():
    """Create a test client."""
    return TestClient(app)


class TestGitHubUrlValidation:
    """Tests for GitHub repository URL validation."""

    def test_accepts_valid_github_url(self):
        """Test valid GitHub URL normalization."""
        url = github_scanner.validate_github_repo_url("https://github.com/owner/repo")

        assert url == "https://github.com/owner/repo.git"

    def test_accepts_valid_github_git_url(self):
        """Test valid .git GitHub URL normalization."""
        url = github_scanner.validate_github_repo_url("https://github.com/owner/repo.git")

        assert url == "https://github.com/owner/repo.git"

    @pytest.mark.parametrize(
        "repo_url",
        [
            "http://github.com/owner/repo",
            "https://evil.com/owner/repo",
            "git@github.com:owner/repo.git",
            "ssh://github.com/owner/repo",
            "file:///tmp/repo",
            "/tmp/repo",
            "https://github.com/owner",
            "https://github.com/owner/repo/issues",
            "https://github.com/owner/repo?tab=readme",
            "https://github.com/owner/re po",
        ],
    )
    def test_rejects_invalid_urls(self, repo_url):
        """Test invalid and non-GitHub URLs are rejected."""
        with pytest.raises(github_scanner.GitHubScanError):
            github_scanner.validate_github_repo_url(repo_url)

    def test_rejects_repo_with_too_many_files(self, tmp_path, monkeypatch):
        """Test cloned repository file count limit is enforced."""
        monkeypatch.setattr(github_scanner, "MAX_FILE_COUNT", 1)
        (tmp_path / "one.py").write_text("print('one')", encoding="utf-8")
        (tmp_path / "two.py").write_text("print('two')", encoding="utf-8")

        with pytest.raises(github_scanner.GitHubScanError):
            github_scanner._validate_repo_file_count(tmp_path)


class TestGitHubScanEndpoint:
    """Tests for the /api/v1/scan/github endpoint."""

    def test_rejects_non_github_url(self, client):
        """Test endpoint rejects non-GitHub URLs."""
        response = client.post(
            "/api/v1/scan/github",
            json={"repo_url": "https://example.com/owner/repo"},
        )

        assert response.status_code == 400
        assert "github.com" in response.json()["detail"]

    def test_scan_github_response_shape_with_mocked_clone(self, client, monkeypatch):
        """Test mocked GitHub clone is scanned and response shape matches ZIP scans."""
        def fake_clone(repo_url, destination):
            os.makedirs(destination, exist_ok=True)
            with open(os.path.join(destination, "app.py"), "w", encoding="utf-8") as f:
                f.write('eval("1 + 1")\n')

        monkeypatch.setattr(github_scanner, "_clone_repository", fake_clone)

        response = client.post(
            "/api/v1/scan/github",
            json={"repo_url": "https://github.com/owner/repo"},
        )

        assert response.status_code == 200
        payload = response.json()
        assert "summary" in payload
        assert "findings" in payload
        assert payload["summary"]["total"] == len(payload["findings"])
        assert any(finding["rule_id"] == "PY_EVAL" for finding in payload["findings"])

    def test_clone_timeout_returns_error(self, client, monkeypatch):
        """Test clone timeout is surfaced as a friendly client error."""
        def fake_clone(repo_url, destination):
            raise github_scanner.GitHubScanError("GitHub clone timed out")

        monkeypatch.setattr(github_scanner, "_clone_repository", fake_clone)

        response = client.post(
            "/api/v1/scan/github",
            json={"repo_url": "https://github.com/owner/repo"},
        )

        assert response.status_code == 400
        assert "timed out" in response.json()["detail"]
