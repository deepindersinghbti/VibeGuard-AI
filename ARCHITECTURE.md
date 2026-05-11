# VibeGuard AI - Architecture

## Overview

VibeGuard AI Phase 1 is a deterministic static security scanner MVP. It safely extracts user-uploaded ZIP files, scans source code using explicit rules (regex + AST), and returns structured findings sorted by severity.

**Core Design Principle**: Explicit, testable, maintainable detection rules. No AI/ML in Phase 1.

## System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Frontend (Next.js)                   │
│  - File upload interface                                 │
│  - Results display (grouped by file & severity)          │
│  - Responsive Tailwind UI                                │
└────────────────────────┬────────────────────────────────┘
                         │ HTTP/JSON
                         ▼
┌─────────────────────────────────────────────────────────┐
│                  Backend (FastAPI)                       │
│                                                           │
│  POST /api/v1/scan/zip                                   │
│    ├─ Validate ZIP file format & size                    │
│    ├─ Extract safely (Zip Slip prevention)               │
│    ├─ Run all scanners (modular, parallel)               │
│    ├─ Sort findings (severity → file → line)             │
│    └─ Return JSON response                               │
│                                                           │
│  Services:                                                │
│    ├─ zip_handler.py      → Safe extraction              │
│    ├─ scanner.py          → Orchestration                │
│    └─ Finding model       → Standardized output          │
│                                                           │
│  Scanners (independent modules):                         │
│    ├─ secrets.py          → API keys, tokens             │
│    ├─ javascript.py       → JS/TS dangerous patterns     │
│    ├─ python.py           → Python dangerous patterns    │
│    └─ config.py           → CORS, .env, NEXT_PUBLIC_     │
└────────────────────────────────────────────────────────┘
```

## Request Flow

```
1. User uploads ZIP via web UI
                    ▼
2. Frontend validates file type (.zip)
                    ▼
3. POST to /api/v1/scan/zip with FormData
                    ▼
4. Backend validates:
   - File is valid ZIP
   - Size ≤ 25MB
                    ▼
5. extract_zip_temp context manager:
   a) Extract to temp directory with validation:
      - Prevent Zip Slip (../../ paths)
      - Prevent absolute paths
      - Enforce file size limits (1MB per file)
      - Enforce total size limit (100MB)
      - Enforce file count limit (1000)
   b) Execute scanning
   c) Auto-cleanup temp directory
                    ▼
6. scan_directory orchestrator:
   - Walk extracted files
   - Skip excluded directories (node_modules, .git, etc.)
   - Filter to allowed extensions
   - Call appropriate scanners for each file
                    ▼
7. Scanners (parallel execution):
   - secrets.scan() → regex patterns for keys/tokens
   - javascript.scan() → regex for dangerous patterns
   - python.scan() → AST + regex for dangerous patterns
   - config.scan() → regex for config issues
                    ▼
8. Aggregate & deduplicate findings
                    ▼
9. Sort findings:
   - Primary: Severity (critical → high → medium → low)
   - Secondary: File path (alphabetical)
   - Tertiary: Line number (ascending)
                    ▼
10. Return JSON array of Finding objects
                    ▼
11. Frontend displays results:
    - Group by file
    - Color-code by severity
    - Show evidence & recommendations
```

## Component Details

### ZIP Handler (`zip_handler.py`)

**Responsibilities**:
- Safely extract ZIP files with multiple security checks
- Prevent Zip Slip attacks (path traversal)
- Enforce size and file count limits
- Clean up temporary files

**Key Functions**:
- `extract_zip(content: bytes) -> str` — Extract ZIP, validate, return temp path
- `extract_zip_temp(content: bytes)` — Context manager for automatic cleanup
- `should_skip_file(file_path: str) -> bool` — Check if file should be scanned

**Security Guarantees**:
- ✓ Zip Slip prevention via path resolution & validation
- ✓ Absolute path rejection
- ✓ Max 1MB per file (prevents memory exhaustion)
- ✓ Max 100MB total extracted (prevents disk exhaustion)
- ✓ Max 1000 files (prevents directory bombs)
- ✓ Automatic cleanup via context manager

**Excluded Directories** (skipped during scan):
- `node_modules` (dependencies)
- `.git` (version control)
- `dist`, `build` (compiled output)
- `.next` (Next.js build)
- `venv`, `.cache` (Python env/cache)
- `__pycache__` (Python bytecode)

**Allowed Extensions**:
- `.js`, `.jsx`, `.ts`, `.tsx` (JavaScript/TypeScript)
- `.py` (Python)
- `.json` (JSON config)
- `.yml`, `.yaml` (YAML)
- `.toml`, `.ini` (Config formats)
- `.env` (Environment files)

### Scanner Orchestrator (`scanner.py`)

**Responsibilities**:
- Walk extracted file tree
- Route each file to appropriate scanners
- Aggregate and deduplicate findings
- Sort results by severity, file, line

**Key Function**:
- `scan_directory(extract_dir: str) -> List[Finding]` — Scan all files, return sorted findings

**Design**:
- Modular: Each scanner is independent
- Extensible: Add new scanners without changing orchestrator
- Deduplicated: Same finding not reported twice
- Sorted: Findings in deterministic order for frontend

### Scanners

#### Secrets Scanner (`secrets.py`)

**Detection Method**: Regex patterns + string matching

**Detects**:
- OPENAI_API_KEY, GEMINI_API_KEY, GOOGLE_API_KEY
- AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
- MONGODB_URI, DATABASE_URL
- JWT_SECRET, SECRET_KEY, PRIVATE_KEY
- API_KEY, ACCESS_TOKEN

**False Positive Avoidance**:
- Ignores values containing: "example", "placeholder", "test", "dummy", "changeme", "xxxx"
- Ignores values in angle brackets like `<YOUR_API_KEY>`
- Ignores values shorter than 5 characters

**Output**: Finding with masked secret (show first/last 3 chars only)

#### JavaScript Scanner (`javascript.py`)

**Detection Method**: Regex patterns

**Detects**:
- `eval(...)` — Dynamic code execution
- `new Function(...)` — Dynamic function creation
- `child_process.exec(...)` — Shell execution
- `dangerouslySetInnerHTML={...}` — DOM injection
- `localStorage.setItem("token", ...)` — Token storage

**Severity**: HIGH (except child_process.exec = CRITICAL)

**Output**: Finding with code context (up to 80 chars)

#### Python Scanner (`python.py`)

**Detection Method**: Hybrid (AST + regex)

**AST-Based Detection** (deterministic, no parsing errors):
- `eval(...)` — Dynamic code execution
- `exec(...)` — Dynamic code execution
- `subprocess.run/call/Popen(..., shell=True)` — Shell execution

**Regex-Based Detection** (fallback if AST parsing fails):
- `pickle.loads(...)` — Unsafe deserialization
- `yaml.load(...)` without SafeLoader — Unsafe YAML parsing

**Severity**:
- eval() = HIGH
- exec() = CRITICAL
- subprocess(shell=True) = CRITICAL
- pickle.loads() = HIGH
- yaml.load() = HIGH

**Output**: Finding with code context

#### Config Scanner (`config.py`)

**Detection Method**: Regex patterns + special handling

**Detects**:
1. **Environment Files**: Any `.env*` file → EXPOSURE (HIGH)
2. **CORS Misconfigurations**: 
   - `allow_origins=["*"]` (Python)
   - `origin: "*"` (JSON)
   - `Access-Control-Allow-Origin: *` (Headers)
   → CORS (MEDIUM)
3. **NEXT_PUBLIC_ Secrets**:
   - `NEXT_PUBLIC_API_KEY`, `NEXT_PUBLIC_SECRET`, `NEXT_PUBLIC_TOKEN`, `NEXT_PUBLIC_PASSWORD`
   → EXPOSURE (CRITICAL)

**Output**: Finding with config context

## Finding Model

```python
class Finding(BaseModel):
    rule_id: str                    # e.g., "SECRETS_OPENAI_API_KEY"
    title: str                      # "Hardcoded OpenAI API Key"
    severity: Severity              # critical | high | medium | low
    category: Category              # secrets | dangerous-code | config | cors | exposure
    file: str                       # Relative path (forward slashes)
    line: int                       # 1-indexed line number
    evidence: str                   # Sanitized code snippet (max 80 chars)
    recommendation: str             # Actionable fix suggestion
```

**JSON Example**:
```json
{
  "rule_id": "SECRETS_OPENAI_API_KEY",
  "title": "Hardcoded OpenAI API Key",
  "severity": "critical",
  "category": "secrets",
  "file": "src/config.py",
  "line": 42,
  "evidence": "OPENAI_API_KEY = sk-abc...xyz",
  "recommendation": "Remove from code. Use environment variables."
}
```

## API Endpoints

### POST /api/v1/scan/zip

**Request**:
- Content-Type: multipart/form-data
- Body: file (ZIP binary)

**Response** (200 OK):
```json
[
  { Finding object },
  { Finding object }
]
```

**Sorted by**: severity (critical first) → file path → line number

**Errors**:
- 400: Non-ZIP file, malicious paths, invalid ZIP format
- 413: File exceeds 25MB
- 500: Unexpected error (generic message, no stack trace)

## Testing Strategy

### Unit Tests

**ZIP Handler** (`test_zip_handler.py`):
- ✓ Valid ZIP extraction
- ✓ Temporary file cleanup (context manager)
- ✓ Zip Slip prevention (../../ paths)
- ✓ Absolute path rejection
- ✓ File size limit enforcement
- ✓ Total size limit enforcement
- ✓ File count limit enforcement

**Scanners** (`test_scanners.py`):
- ✓ Each scanner detects its target patterns
- ✓ False positives are avoided
- ✓ Evidence is properly sanitized
- ✓ Severity levels are correct

**API Routes** (`test_routes.py`):
- ✓ Health check works
- ✓ Valid ZIP returns findings
- ✓ Safe project returns empty findings
- ✓ Non-ZIP rejected (400)
- ✓ Oversized file rejected (413)
- ✓ Findings sorted by severity

### Test Fixtures

**Conftest.py** provides reusable fixtures:
- Sample code files with security issues (secrets, eval, exec, etc.)
- ZIP file fixtures combining multiple issues
- Safe project fixture (negative test)

**Fixtures**:
- `api_key_zip` — Hardcoded API key
- `eval_usage_zip` — eval() usage
- `env_file_zip` — .env file exposure
- `cors_wildcard_zip` — CORS wildcard
- `dangerous_pickle_zip` — pickle.loads()
- `safe_project_zip` — No issues
- `comprehensive_zip` — Multiple issues

## Extensibility

### Adding a New Scanner Rule

1. **Create detector function** in appropriate module:
   ```python
   # In backend/app/scanners/secrets.py (or new module)
   def scan(file_path: str) -> List[Finding]:
       findings = []
       # Implement detection logic
       return findings
   ```

2. **Register in orchestrator** if new module:
   ```python
   # backend/app/services/scanner.py
   SCANNER_MAP = {
       ".py": python.scan,
       # ... other modules
       ".rs": rust.scan,  # NEW
   }
   ```

3. **Write tests**:
   ```python
   # backend/tests/test_scanners.py
   def test_detect_new_pattern(sample_code_with_issue):
       findings = scanner.scan(sample_code_file)
       assert len(findings) > 0
       assert findings[0].rule_id == "RULE_ID"
   ```

4. **Add test fixtures** for positive and negative cases

### Adding a New File Type

1. Add extension to `ALLOWED_EXTENSIONS` in `zip_handler.py`
2. Add scanner mapping to `SCANNER_MAP` in `scanner.py`
3. Create or reuse scanner module
4. Add tests with sample files

## Performance Considerations

**Scanning Speed** (rough estimates):
- Small project (< 1MB): < 100ms
- Medium project (10MB): 0.5-1s
- Large project (100MB): 5-10s (limit)

**Memory Usage**:
- Streams file processing (no full ZIP in memory)
- Temporary directory for extraction
- Finding objects relatively lightweight

**Scalability Limits** (by design for Phase 1):
- Single-threaded scanning (good for MVP, can parallelize in Phase 2)
- Synchronous HTTP request (client waits, no background jobs)
- In-memory Finding list (OK up to ~1000 findings)

## Security Considerations

### ZIP Extraction

- Path validation prevents Zip Slip (directory traversal)
- Absolute path rejection prevents writing outside extract dir
- Size limits prevent disk exhaustion
- File count limit prevents CPU exhaustion
- Temp files auto-cleaned (no orphaned temp dirs)

### Secret Handling

- Secrets masked in evidence (show only first/last 3 chars)
- Never exposed in error messages or logs
- Recommended to use environment variables

### Code Execution

- No `eval()` or `exec()` of user code
- No dynamic imports or loading of user files
- AST parsing is read-only (no execution)
- Regex matching is read-only (no execution)

### CORS

- Configured to allow localhost only (Phase 1)
- Should restrict to specific origins in production

## Future Improvements (Phase 2+)

- **Parallel scanning**: Process files concurrently
- **Background jobs**: Async scanning with webhooks
- **Caching**: Cache scan results for same ZIP
- **Incremental scanning**: Only scan changed files
- **ML integration**: Add Gemini API for semantic analysis
- **GitHub integration**: Direct repo scanning
- **Batch API**: Scan multiple ZIPs in one request
- **Custom rules**: User-defined detection patterns
- **Performance optimization**: Lazy loading, streaming responses

## Architecture Decisions

| Decision | Rationale |
|----------|-----------|
| **Regex + AST for detection** | Deterministic, no ML errors, easy to debug & maintain |
| **Modular scanners** | Each rule independent, easy to add/remove rules |
| **Backend-side sorting** | Consistent order for all clients, no duplication logic |
| **Synchronous API** | Simpler for MVP, suitable for small-medium projects |
| **Temp file cleanup via context manager** | Guaranteed cleanup even on errors |
| **ZIP extraction limits** | Prevents resource exhaustion attacks |
| **Relative file paths in findings** | Portable, matches source file names |
| **Masked secrets in evidence** | Balances usefulness with security |

## Testing Coverage

Current test coverage:
- ✓ ZIP handler: ~15 tests (extraction, security, limits)
- ✓ Scanners: ~12 tests (each pattern type)
- ✓ API routes: ~7 tests (endpoint behavior, errors)
- ✓ Total: ~34 tests

Target: > 80% code coverage

Run tests:
```bash
pytest --cov=app backend/tests/
```

---

**VibeGuard AI Phase 1 - Static Security Scanner MVP**
