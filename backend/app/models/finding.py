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
    
    model_config = ConfigDict(use_enum_values=True)
