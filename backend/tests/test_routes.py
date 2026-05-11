"""Tests for the API routes."""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.models import ExplainResponse
from app.services import explainer


@pytest.fixture
def client():
    """Create a test client."""
    return TestClient(app)


class TestScanEndpoint:
    """Tests for the /api/v1/scan/zip endpoint."""
    
    def test_health_check(self, client):
        """Test health check endpoint."""
        response = client.get("/")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"
    
    def test_upload_valid_zip(self, client, safe_project_zip):
        """Test uploading a valid ZIP file."""
        response = client.post(
            "/api/v1/scan/zip",
            files={"file": ("test.zip", safe_project_zip, "application/zip")}
        )
        
        assert response.status_code == 200
        payload = response.json()
        findings = payload["findings"]
        summary = payload["summary"]
        assert isinstance(findings, list)
        # Safe project should have no findings
        assert len(findings) == 0
        assert summary["total"] == 0
        assert summary["score"] == 100
    
    def test_upload_zip_with_issues(self, client, api_key_zip):
        """Test uploading a ZIP with security issues."""
        response = client.post(
            "/api/v1/scan/zip",
            files={"file": ("test.zip", api_key_zip, "application/zip")}
        )
        
        assert response.status_code == 200
        payload = response.json()
        findings = payload["findings"]
        summary = payload["summary"]
        assert isinstance(findings, list)
        # Should have API key findings
        assert len(findings) > 0
        assert any("API" in f["title"] for f in findings)
        assert summary["total"] == len(findings)
        assert summary["critical"] > 0
    
    def test_reject_non_zip_file(self, client):
        """Test rejection of non-ZIP files."""
        response = client.post(
            "/api/v1/scan/zip",
            files={"file": ("test.txt", b"not a zip", "text/plain")}
        )
        
        assert response.status_code == 400
        assert "must be a .zip file" in response.json()["detail"]
    
    def test_reject_oversized_file(self, client):
        """Test rejection of files exceeding 25MB."""
        import io
        
        # Create a large file (30MB)
        large_content = b"x" * (30 * 1024 * 1024)
        
        response = client.post(
            "/api/v1/scan/zip",
            files={"file": ("test.zip", large_content, "application/zip")}
        )
        
        assert response.status_code == 413
        assert "exceeds 25MB" in response.json()["detail"]
    
    def test_findings_sorted_by_severity(self, client, comprehensive_zip):
        """Test that findings are sorted by severity."""
        response = client.post(
            "/api/v1/scan/zip",
            files={"file": ("test.zip", comprehensive_zip, "application/zip")}
        )
        
        assert response.status_code == 200
        findings = response.json()["findings"]
        
        # Verify findings are sorted by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        
        for i in range(len(findings) - 1):
            current_severity = severity_order[findings[i]["severity"]]
            next_severity = severity_order[findings[i + 1]["severity"]]
            # Current should be <= next (or same severity, sorted by file/line)
            assert current_severity <= next_severity


class TestExplainEndpoint:
    """Tests for the /api/v1/explain endpoint."""

    @pytest.fixture(autouse=True)
    def clear_cache(self):
        """Clear explanation cache between tests."""
        explainer.clear_explanation_cache()
        yield
        explainer.clear_explanation_cache()

    def _payload(self):
        return {
            "finding": {
                "rule_id": "JS_EVAL",
                "title": "eval() usage detected",
                "severity": "high",
                "file": "app.js",
                "line": 1,
                "evidence": "eval(userInput)",
                "recommendation": "Avoid eval(). Use safer parsing or explicit logic.",
            }
        }

    def test_explain_endpoint_returns_valid_structure(self, client, monkeypatch):
        """Test explanation endpoint response shape."""
        def fake_call(prompt):
            return ExplainResponse(
                explanation="This can run untrusted code.",
                attack_scenario="An attacker submits JavaScript that steals data.",
                fix_details="Replace eval with explicit parsing or safe control flow.",
            )

        monkeypatch.setattr(explainer, "_call_gemini", fake_call)

        response = client.post("/api/v1/explain", json=self._payload())

        assert response.status_code == 200
        payload = response.json()
        assert payload["explanation"]
        assert payload["attack_scenario"]
        assert payload["fix_details"]

    def test_explain_endpoint_uses_cache(self, client, monkeypatch):
        """Test the same finding does not trigger duplicate AI calls."""
        calls = {"count": 0}

        def fake_call(prompt):
            calls["count"] += 1
            return ExplainResponse(
                explanation="Cached explanation.",
                attack_scenario="Cached attack scenario.",
                fix_details="Cached fix details.",
            )

        monkeypatch.setattr(explainer, "_call_gemini", fake_call)

        first = client.post("/api/v1/explain", json=self._payload())
        second = client.post("/api/v1/explain", json=self._payload())

        assert first.status_code == 200
        assert second.status_code == 200
        assert calls["count"] == 1
        assert first.json() == second.json()

    def test_explain_endpoint_fallback_on_failure(self, client, monkeypatch):
        """Test fallback response when AI generation fails."""
        def fake_call(prompt):
            raise RuntimeError("AI unavailable")

        monkeypatch.setattr(explainer, "_call_gemini", fake_call)

        response = client.post("/api/v1/explain", json=self._payload())

        assert response.status_code == 200
        payload = response.json()
        assert "AI explanation is currently unavailable" in payload["explanation"]
