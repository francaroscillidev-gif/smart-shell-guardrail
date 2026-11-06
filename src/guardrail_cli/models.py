import enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class RiskLevel(str, enum.Enum):
    SAFE = "SAFE"
    WARNING = "WARNING"
    BLOCKED = "BLOCKED"

class SecurityCheckResult(BaseModel):
    allowed: bool
    risk_level: RiskLevel
    reasons: List[str] = Field(default_factory=list)
    detected_secrets: List[str] = Field(default_factory=list)
    suggested_safe_command: Optional[str] = None

class SystemDiagnostics(BaseModel):
    error_category: str
    summary: str
    details: Dict[str, Any] = Field(default_factory=dict)
    suggested_actions: List[str] = Field(default_factory=list)
    quick_fix_command: Optional[str] = None
    is_auto_fixable: bool = False

class DiffResult(BaseModel):
    created_files: List[str] = Field(default_factory=list)
    modified_files: List[str] = Field(default_factory=list)
    deleted_files: List[str] = Field(default_factory=list)

class ResourceUsage(BaseModel):
    duration_ms: float = 0.0
    cpu_percent: float = 0.0
    max_memory_mb: float = 0.0

class ExecutionResult(BaseModel):
    command: str
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: float = 0.0
    timed_out: bool = False
    truncated: bool = False
    resources: Optional[ResourceUsage] = None
    diff: Optional[DiffResult] = None
    diagnostics: Optional[SystemDiagnostics] = None
