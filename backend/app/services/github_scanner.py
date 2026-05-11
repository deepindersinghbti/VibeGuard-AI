"""Public GitHub repository clone helpers for scanning."""
import os
import re
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlparse

from app.services.zip_handler import MAX_FILE_COUNT, SKIP_DIRS


CLONE_TIMEOUT_SECONDS = 60
GITHUB_PATH_SEGMENT_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")


class GitHubScanError(Exception):
    """Raised when a GitHub repository cannot be prepared for scanning."""


def validate_github_repo_url(repo_url: str) -> str:
    """Validate and normalize a public GitHub repository URL."""
    parsed = urlparse(repo_url.strip())

    if parsed.scheme != "https":
        raise GitHubScanError("Repository URL must use https://github.com/owner/repo")

    if parsed.netloc.lower() != "github.com":
        raise GitHubScanError("Only public github.com repository URLs are supported")

    if parsed.query or parsed.fragment:
        raise GitHubScanError("Repository URL must not include query strings or fragments")

    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) != 2:
        raise GitHubScanError("Repository URL must look like https://github.com/owner/repo")

    owner, repo = parts
    if repo.endswith(".git"):
        repo = repo[:-4]

    if not owner or not repo:
        raise GitHubScanError("Repository URL must include an owner and repository name")

    if not GITHUB_PATH_SEGMENT_PATTERN.fullmatch(owner) or not GITHUB_PATH_SEGMENT_PATTERN.fullmatch(repo):
        raise GitHubScanError("Repository URL contains invalid owner or repository characters")

    return f"https://github.com/{owner}/{repo}.git"


def _clone_repository(repo_url: str, destination: Path) -> None:
    """Clone a public GitHub repository with a shallow clone."""
    try:
        result = subprocess.run(
            [
                "git",
                "clone",
                "--depth",
                "1",
                "--single-branch",
                repo_url,
                str(destination),
            ],
            capture_output=True,
            text=True,
            timeout=CLONE_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError as exc:
        raise GitHubScanError("git is not installed or is not available on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitHubScanError("GitHub clone timed out") from exc

    if result.returncode != 0:
        raise GitHubScanError("Unable to clone public GitHub repository")


def _validate_repo_file_count(repo_dir: Path) -> None:
    """Reject cloned repositories that exceed the existing file count limit."""
    file_count = 0
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [directory for directory in dirs if directory not in SKIP_DIRS]
        file_count += len(files)
        if file_count > MAX_FILE_COUNT:
            raise GitHubScanError(f"Repository file count exceeds {MAX_FILE_COUNT} limit")


@contextmanager
def clone_github_repo_temp(repo_url: str):
    """Clone a validated GitHub repository into a temporary directory."""
    normalized_url = validate_github_repo_url(repo_url)
    temp_dir = Path(tempfile.mkdtemp(prefix="vibeguard_github_"))
    repo_dir = temp_dir / "repo"

    try:
        _clone_repository(normalized_url, repo_dir)
        _validate_repo_file_count(repo_dir)
        yield str(repo_dir)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
