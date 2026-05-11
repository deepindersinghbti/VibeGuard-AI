# VibeGuard AI

A static security scanner for source code that detects hardcoded secrets, dangerous code patterns, CORS misconfigurations, and environment file exposure.

**Phase 1 MVP**: Deterministic security scanning with ZIP upload support, no AI models or advanced features yet.

## Features (Phase 1)

✅ **Hardcoded Secrets Detection**
- API keys (OpenAI, Gemini, Google, AWS, etc.)
- Database credentials (MongoDB, PostgreSQL, etc.)
- Tokens (JWT, access tokens)
- Private keys
- Prevents false positives (ignores `example`, `placeholder`, `test`, etc.)

✅ **Dangerous Code Patterns**
- **Python**: eval(), exec(), subprocess with shell=True, pickle.loads(), yaml.load() without SafeLoader (AST-based detection)
- **JavaScript/TypeScript**: eval(), new Function(), child_process.exec(), dangerouslySetInnerHTML, localStorage token storage

✅ **Configuration Issues**
- CORS misconfiguration (allow_origins=["*"])
- .env file exposure
- NEXT_PUBLIC_ variables with secrets

✅ **Safe ZIP Handling**
- Zip Slip prevention (../../ paths)
- Absolute path rejection
- File size limits (1MB per file)
- Total extracted size limit (100MB)
- File count limit (1000 files)
- Automatic cleanup of temporary files

✅ **Frontend UI**
- Simple ZIP upload interface
- Real-time scan progress
- Results grouped by file and severity
- Clear recommendations for each finding

## Tech Stack

- **Backend**: FastAPI + Python 3.9+
- **Frontend**: Next.js 14 + React + TypeScript + Tailwind CSS
- **Testing**: pytest with fixtures
- **Detection**: Regex + AST parsing (deterministic, no ML)

## Quick Start

### Prerequisites

- Python 3.9+
- Node.js 18+
- pip and npm

### Backend Setup

1. **Install dependencies**:
   ```bash
   cd backend
   pip install -e .
   # Or with dev dependencies:
   pip install -e ".[dev]"
   ```

2. **Configure Gemini for AI explanations**:
   ```bash
   copy .env.example .env
   ```

   Add your real key to `backend/.env`:
   ```env
   GEMINI_API_KEY=your_real_gemini_api_key
   GEMINI_MODEL=gemini-2.5-flash
   ```

   You can also set the key in your shell before starting the backend:
   ```bash
   $env:GEMINI_API_KEY="your_real_gemini_api_key"
   ```

   Optional:
   ```bash
   $env:GEMINI_MODEL="gemini-2.5-flash"
   ```

   Do not put this key in `frontend/.env.example` or any `NEXT_PUBLIC_*` variable.

3. **Run the backend** (development server on port 8000):
   ```bash
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```

   Backend will be available at `http://localhost:8000`

### Frontend Setup

1. **Install dependencies**:
   ```bash
   cd frontend
   npm install
   ```

2. **Run the frontend** (development server on port 3000):
   ```bash
   npm run dev
   ```

   Frontend will be available at `http://localhost:3000`

### Access the Application

Open `http://localhost:3000` in your browser to use VibeGuard AI.

## Usage

1. **Prepare a ZIP file** of your project:
   ```bash
   zip -r myproject.zip src/ config/ .env
   ```

2. **Upload and scan** via the web interface:
   - Select ZIP file
   - Click "Scan ZIP File"
   - View results grouped by file and severity

3. **Review findings**:
   - Each finding shows file, line number, issue type, code snippet, and fix recommendation
   - Results sorted by severity (critical → high → medium → low)

## Testing

### Run all tests:

```bash
cd backend
pytest -v
```

### Run specific test file:

```bash
pytest tests/test_scanners.py -v
```

### Run with coverage:

```bash
pytest --cov=app tests/
```

### Test fixtures:

The test suite includes sample files for:
- Hardcoded API keys
- eval() and exec() usage
- Dangerous subprocess calls
- CORS misconfigurations
- .env file exposure
- pickle and yaml usage
- Safe projects (negative tests)

## Project Structure

```
VibeGuard-AI/
├── backend/
│   ├── app/
│   │   ├── main.py                  # FastAPI app
│   │   ├── models/
│   │   │   └── finding.py          # Finding dataclass
│   │   ├── routes/
│   │   │   └── scan.py             # /api/v1/scan/zip endpoint
│   │   ├── services/
│   │   │   ├── zip_handler.py      # Safe ZIP extraction
│   │   │   └── scanner.py          # Orchestrator
│   │   └── scanners/
│   │       ├── secrets.py          # Secrets detection
│   │       ├── javascript.py       # JS/TS patterns
│   │       ├── python.py           # Python patterns (AST + regex)
│   │       └── config.py           # Config issues
│   ├── tests/
│   │   ├── conftest.py             # Fixtures
│   │   ├── test_zip_handler.py     # ZIP tests
│   │   ├── test_scanners.py        # Scanner tests
│   │   └── test_routes.py          # API tests
│   └── pyproject.toml
├── frontend/
│   ├── app/
│   │   ├── page.tsx                # Main upload UI
│   │   ├── layout.tsx              # Layout
│   │   └── globals.css             # Base styles
│   ├── components/
│   │   └── ScanResults.tsx         # Results display
│   ├── lib/
│   │   └── api.ts                  # API client
│   ├── types.ts                    # TypeScript types
│   ├── package.json
│   ├── tsconfig.json
│   ├── tailwind.config.ts
│   └── next.config.js
├── README.md
├── ARCHITECTURE.md
└── .gitignore
```

## API Reference

### Health Check

```http
GET /
```

Returns: `{"status": "ok", "service": "VibeGuard AI Backend"}`

### Scan ZIP

```http
POST /api/v1/scan/zip
Content-Type: multipart/form-data

file: <binary ZIP file>
```

**Response** (200 OK):
```json
[
  {
    "rule_id": "SECRETS_OPENAI_API_KEY",
    "title": "Hardcoded OpenAI API Key",
    "severity": "critical",
    "category": "secrets",
    "file": "src/config.py",
    "line": 42,
    "evidence": "OPENAI_API_KEY = sk-abc...xyz",
    "recommendation": "Remove API key from code. Use environment variables instead."
  }
]
```

**Error** (400 Bad Request):
```json
{"detail": "File must be a .zip file"}
```

**Error** (413 Payload Too Large):
```json
{"detail": "File exceeds 25MB limit"}
```

## Limits & Configuration

| Setting | Value | Description |
|---------|-------|-------------|
| Max ZIP size | 25 MB | Upload file size limit |
| Max extracted size | 100 MB | Total size after extraction |
| Max file count | 1000 | Files in ZIP |
| Max single file | 1 MB | Individual file size |
| Timeout | N/A | Scanning is synchronous |

## What's NOT Included (Phase 1)

❌ AI/ML model integration (Gemini, GPT, etc.)
❌ GitHub repository scanning
❌ User authentication or accounts
❌ Database or scan history
❌ PDF/report export
❌ Dashboard or analytics
❌ Webhook support
❌ Batch scanning
❌ Rate limiting or production hardening
❌ Advanced UI polish

These are intentionally deferred to later phases to keep Phase 1 focused and reliable.

## Future Phases

**Phase 2**: GitHub repo scanning, user accounts, scan history
**Phase 3**: AI-powered analysis with Gemini API
**Phase 4**: Dashboard, reports, team collaboration
**Phase 5**: Production deployment, scaling, advanced features

## Development

### Adding New Scanner Rules

1. Create a scanner function in `backend/app/scanners/<category>.py`:
   ```python
   def scan(file_path: str) -> List[Finding]:
       # Detect patterns
       # Return list of Finding objects
   ```

2. Register in `backend/app/services/scanner.py` SCANNER_MAP

3. Add tests in `backend/tests/test_scanners.py`

### Debugging

**Backend logs**:
```bash
uvicorn app.main:app --reload --log-level debug
```

**Frontend logs**: Check browser console

**Test debugging**:
```bash
pytest -vv --tb=short tests/
```

## Security Notes

- All temporary files are automatically cleaned up
- No secrets are exposed in logs or responses
- Secret values are masked in findings evidence
- ZIP extraction uses secure path validation
- No external API calls in Phase 1
- CORS restricted to localhost in development

## License

MIT License - See LICENSE file

## Contributing

This is Phase 1 of VibeGuard AI. Bug reports and feature requests welcome!

---

**Built with ❤️ - 2026 Deepinder Singh**
