import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from .models import SecurityCheckResult, ExecutionResult

class AuditLogger:
    def __init__(self, log_path: str):
        self.log_path = Path(os.path.expanduser(log_path))
        self._ensure_dir()

    def _ensure_dir(self):
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

    def log_event(
        self,
        command: str,
        security_check: SecurityCheckResult,
        execution_result: Optional[ExecutionResult] = None,
        duration_ms: Optional[float] = None
    ):
        try:
            record = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "command": command,
                "allowed": security_check.allowed,
                "risk_level": security_check.risk_level.value,
                "reasons": security_check.reasons,
                "secrets_detected": security_check.detected_secrets,
                "duration_ms": duration_ms,
                "exit_code": execution_result.exit_code if execution_result else None,
                "error_category": execution_result.diagnostics.error_category if (execution_result and execution_result.diagnostics) else None
            }
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except Exception:
            pass
