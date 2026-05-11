"""Debug the secrets scanner."""
import tempfile
import os
from app.scanners import secrets

content = """
import os

# Configuration
OPENAI_API_KEY = "sk-proj-abc123xyz789def456ghi"
API_KEY = "real-secret-key-12345"
"""

with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
    f.write(content)
    f.flush()
    temp_name = f.name

try:
    findings = secrets.scan(temp_name)
    print(f'Found {len(findings)} findings')
    for finding in findings:
        print(f'  - {finding.title}')
        print(f'    Evidence: {finding.evidence}')
finally:
    os.unlink(temp_name)
