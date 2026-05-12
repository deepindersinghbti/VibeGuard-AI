"""Finding model for security scan results."""
from enum import Enum
from pydantic import BaseModel, Field, ConfigDict


class Severity(str, Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Category(str, Enum):
    """Categories for findings."""
    SECRETS = "secrets"
    DANGEROUS_CODE = "dangerous-code"
    CONFIG = "config"
    CORS = "cors"
    EXPOSURE = "exposure"


class FileContext(str, Enum):
    """Context for how a scanned file is typically used."""
    PRODUCTION = "Production code"
    TEST_DEMO = "Test/demo file"
    EXAMPLE_TEMPLATE = "Example/template file"
    GENERATED_DEPENDENCY = "Generated/dependency file"


class Finding(BaseModel):
    """A security finding from the scanner."""
    
    rule_id: str = Field(..., description="Unique rule identifier")
    title: str = Field(..., description="Human-readable title")
    severity: Severity = Field(..., description="Severity level")
    category: Category = Field(..., description="Finding category")
    file: str = Field(..., description="Relative path to file")
    line: int = Field(..., description="Line number (1-indexed)")
    evidence: str = Field(..., description="Sanitized code snippet")
    recommendation: str = Field(..., description="Fix suggestion")
    file_context: FileContext = Field(
        default=FileContext.PRODUCTION,
        description="Context for how the scanned file is typically used",
    )
    original_severity: Severity | None = Field(
        default=None,
        description="Severity before context-aware adjustment",
    )
    adjusted_severity_reason: str = Field(
        default="",
        description="Reason context did or did not adjust severity",
    )
    score_penalty: float = Field(
        default=0,
        description="Final score penalty contribution after multipliers",
    )
    
    model_config = ConfigDict(use_enum_values=True)


class ScanSummary(BaseModel):
    """Aggregate scan summary."""
    
    total: int = Field(..., description="Total number of findings")
    critical: int = Field(..., description="Number of critical findings")
    high: int = Field(..., description="Number of high findings")
    medium: int = Field(..., description="Number of medium findings")
    low: int = Field(..., description="Number of low findings")
    score: int = Field(..., description="Security score from 0 to 100")
    risk_label: str = Field(default="Healthy", description="Context-aware risk label")
    warning_message: str = Field(default="", description="Context-aware scan summary message")
    scanned_files: int = Field(default=0, description="Number of files scanned")
    ignored_files: int = Field(default=0, description="Number of files ignored")
    skipped_generated_dependency_files: int = Field(
        default=0,
        description="Number of generated/dependency files skipped",
    )
    production_penalty: int = Field(default=0, description="Score penalty from production code")
    real_env_config_penalty: int = Field(default=0, description="Score penalty from real env/config files")
    test_demo_penalty: int = Field(default=0, description="Score penalty from test/demo files")
    documentation_template_penalty: int = Field(default=0, description="Score penalty from docs/templates")
    duplicate_caps_applied: bool = Field(default=False, description="Whether duplicate penalty caps were applied")
    production_critical_count: int = Field(default=0, description="Critical findings in production code")
    env_critical_count: int = Field(default=0, description="Critical findings in real env/config files")
    test_demo_critical_count: int = Field(default=0, description="Critical findings in test/demo files")
    docs_template_critical_count: int = Field(default=0, description="Critical findings in docs/templates")
    generated_dependency_critical_count: int = Field(default=0, description="Critical findings in generated/dependency files")


class ScanResponse(BaseModel):
    """Response returned by a ZIP scan."""
    
    summary: ScanSummary
    findings: list[Finding]


class GitHubScanRequest(BaseModel):
    """Request to scan a public GitHub repository."""
    
    repo_url: str = Field(..., description="Public GitHub repository URL")


class ExplainFinding(BaseModel):
    """Finding payload used for AI explanation."""
    
    rule_id: str
    title: str
    severity: Severity
    file: str
    line: int
    evidence: str
    recommendation: str


class ExplainRequest(BaseModel):
    """Request to explain one finding."""
    
    finding: ExplainFinding


class ExplainResponse(BaseModel):
    """AI explanation response for one finding."""
    
    explanation: str
    attack_scenario: str = ""
    fix_details: str = ""
    error_code: str = ""  # Internal error code for debugging: ai_rate_limited, ai_timeout, ai_empty_response, ai_invalid_response, ai_invalid_key, etc.
