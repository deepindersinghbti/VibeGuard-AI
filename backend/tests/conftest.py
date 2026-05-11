"""Fixtures for pytest."""
import pytest
import zipfile
import io
from pathlib import Path


@pytest.fixture
def sample_api_key_file():
    """Sample Python file with hardcoded API key."""
    return """
import os

# Configuration
OPENAI_API_KEY = "sk-proj-abc123xyz789def456ghi"
API_KEY = "real-secret-key-12345"
"""


@pytest.fixture
def sample_openai_value_file():
    """Sample file with an OpenAI-style key used as a value."""
    return 'token = "sk-proj-realLookingValue123456"\n'


@pytest.fixture
def sample_github_token_file():
    """Sample file with a GitHub token value."""
    return """
key = "ghp_1234567890abcdef1234567890abcdef1234"
fine_grained = "github_pat_11AAbBccDD1122EEffGGHHiiJJkkLLmmNN"
"""


@pytest.fixture
def sample_google_api_value_file():
    """Sample file with a Google API key value."""
    return 'api = "AIzaSyA1234567890123456789012345678901234"\n'


@pytest.fixture
def sample_aws_access_key_value_file():
    """Sample file with an AWS access key ID value."""
    return 'aws = "AKIA1234567890ABCD12"\n'


@pytest.fixture
def sample_openai_test_value_file():
    """Sample file with a test/demo OpenAI-style key value."""
    return 'key = "sk_test_abc"\n'


@pytest.fixture
def sample_private_key_block_file():
    """Sample file with a private key block."""
    return """
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASC...
-----END PRIVATE KEY-----
"""


@pytest.fixture
def sample_eval_file():
    """Sample Python file with eval usage."""
    return """
def evaluate_user_input(user_input):
    result = eval(user_input)
    return result
"""


@pytest.fixture
def sample_exec_file():
    """Sample Python file with exec usage."""
    return """
def execute_code(code_string):
    exec(code_string)
"""


@pytest.fixture
def sample_pickle_file():
    """Sample Python file with pickle.loads."""
    return """
import pickle

def deserialize(data):
    return pickle.loads(data)
"""


@pytest.fixture
def sample_subprocess_shell_file():
    """Sample Python file with subprocess shell=True."""
    return """
import subprocess

def run_command(cmd):
    subprocess.run(cmd, shell=True)
"""


@pytest.fixture
def sample_yaml_unsafe_file():
    """Sample Python file with yaml.load without SafeLoader."""
    return """
import yaml

def parse_yaml(content):
    return yaml.load(content)
"""


@pytest.fixture
def sample_js_eval_file():
    """Sample JavaScript file with eval."""
    return """
function executeCode(code) {
  eval(code);
}
"""


@pytest.fixture
def sample_js_function_file():
    """Sample JavaScript file with new Function."""
    return """
const fn = new Function('a', 'b', 'return a + b');
"""


@pytest.fixture
def sample_js_dangerous_html_file():
    """Sample React file with dangerouslySetInnerHTML."""
    return """
export function Component() {
  return <div dangerouslySetInnerHTML={{ __html: '<b>test</b>' }} />;
}
"""


@pytest.fixture
def sample_js_localstorage_file():
    """Sample JavaScript file storing token in localStorage."""
    return """
function saveToken(token) {
  localStorage.setItem("token", token);
  localStorage.setItem("jwt", token);
}
"""


@pytest.fixture
def sample_cors_wildcard_file():
    """Sample Python FastAPI file with CORS wildcard."""
    return """
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
)
"""


@pytest.fixture
def sample_next_public_secret_file():
    """Sample .env file with NEXT_PUBLIC_ secret."""
    return """
NEXT_PUBLIC_API_KEY=sk-real-secret-key
NEXT_PUBLIC_GEMINI_API_KEY=gemini-key-12345
NEXT_PUBLIC_SECRET=very-secret-value
"""


@pytest.fixture
def sample_env_file():
    """.env file content."""
    return """
DATABASE_URL=postgresql://user:password@localhost/db
OPENAI_API_KEY=sk-proj-secret
JWT_SECRET=super-secret-jwt-key
"""


@pytest.fixture
def sample_clean_python_file():
    """Sample clean Python file with no issues."""
    return """
def add(a, b):
    return a + b

def multiply(a, b):
    return a * b
"""


@pytest.fixture
def sample_clean_js_file():
    """Sample clean JavaScript file with no issues."""
    return """
export function greet(name) {
  return `Hello, ${name}!`;
}
"""


def create_test_zip(files_dict: dict) -> bytes:
    """
    Create a ZIP file from a dictionary of {filename: content}.
    
    Args:
        files_dict: Dictionary mapping file paths to file contents
    
    Returns:
        ZIP file as bytes
    """
    zip_buffer = io.BytesIO()
    
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        for file_path, content in files_dict.items():
            zip_file.writestr(file_path, content)
    
    zip_buffer.seek(0)
    return zip_buffer.getvalue()


@pytest.fixture
def api_key_zip(sample_api_key_file):
    """ZIP file containing hardcoded API keys."""
    return create_test_zip({
        "src/config.py": sample_api_key_file,
    })


@pytest.fixture
def eval_usage_zip(sample_eval_file):
    """ZIP file containing eval() usage."""
    return create_test_zip({
        "src/eval_bad.py": sample_eval_file,
    })


@pytest.fixture
def env_file_zip(sample_env_file):
    """ZIP file containing .env file."""
    return create_test_zip({
        ".env": sample_env_file,
    })


@pytest.fixture
def cors_wildcard_zip(sample_cors_wildcard_file):
    """ZIP file containing CORS wildcard configuration."""
    return create_test_zip({
        "app.py": sample_cors_wildcard_file,
    })


@pytest.fixture
def dangerous_pickle_zip(sample_pickle_file):
    """ZIP file containing pickle.loads."""
    return create_test_zip({
        "serializer.py": sample_pickle_file,
    })


@pytest.fixture
def safe_project_zip(sample_clean_python_file, sample_clean_js_file):
    """ZIP file containing a safe project."""
    return create_test_zip({
        "utils.py": sample_clean_python_file,
        "lib.js": sample_clean_js_file,
    })


@pytest.fixture
def comprehensive_zip(
    sample_api_key_file,
    sample_eval_file,
    sample_js_dangerous_html_file,
    sample_env_file,
):
    """ZIP file containing multiple security issues."""
    return create_test_zip({
        "src/config.py": sample_api_key_file,
        "src/processor.py": sample_eval_file,
        "frontend/Component.tsx": sample_js_dangerous_html_file,
        ".env": sample_env_file,
    })
