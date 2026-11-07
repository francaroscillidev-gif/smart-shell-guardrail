import os
import shutil
from typing import Dict, Any, List
from pydantic import BaseModel, Field

class CheckResult(BaseModel):
    name: str
    status: str # "PASS", "WARN", "FAIL"
    message: str
    details: Dict[str, Any] = Field(default_factory=dict)

class DoctorReport(BaseModel):
    overall_healthy: bool
    platform: str
    checks: List[CheckResult] = Field(default_factory=list)

class GuardrailDoctor:
    """Verifica lo stato di salute, l'ambiente di runtime, le feature di isolamento OS e le dipendenze."""

    def run_diagnostics(self) -> DoctorReport:
        import sys
        checks = []

        # 1. Python runtime check
        py_ver = sys.version_info
        if py_ver >= (3, 12):
            checks.append(CheckResult(name="Python Runtime", status="PASS", message=f"Python {py_ver.major}.{py_ver.minor}.{py_ver.micro} (compatibile)"))
        else:
            checks.append(CheckResult(name="Python Runtime", status="WARN", message=f"Python {py_ver.major}.{py_ver.minor} (consigliato >= 3.12)"))

        # 2. Package manager (uv)
        if shutil.which("uv"):
            checks.append(CheckResult(name="uv Package Manager", status="PASS", message="uv installato e disponibile nel PATH"))
        else:
            checks.append(CheckResult(name="uv Package Manager", status="WARN", message="uv non trovato nel PATH (consigliato per performance ottimali)"))

        # 3. Kernel Sandbox Tooling
        is_macos = sys.platform == "darwin"
        is_linux = sys.platform.startswith("linux")

        if is_macos:
            if shutil.which("sandbox-exec"):
                checks.append(CheckResult(name="OS Sandbox (Seatbelt)", status="PASS", message="macOS Apple Seatbelt (sandbox-exec) disponibile"))
            else:
                checks.append(CheckResult(name="OS Sandbox (Seatbelt)", status="WARN", message="sandbox-exec non presente"))
        elif is_linux:
            if shutil.which("bwrap"):
                checks.append(CheckResult(name="OS Sandbox (Bubblewrap)", status="PASS", message="Linux Bubblewrap (bwrap) disponibile"))
            else:
                checks.append(CheckResult(name="OS Sandbox (Bubblewrap)", status="WARN", message="bwrap non installato (installabile con apt install bubblewrap)"))

        # 4. Audit Log Directory
        audit_path = os.path.expanduser("~/.guardrail/audit.jsonl")
        audit_dir = os.path.dirname(audit_path)
        if os.path.exists(audit_dir) and os.access(audit_dir, os.W_OK):
            checks.append(CheckResult(name="Audit Storage", status="PASS", message=f"Directory di audit scrivibile: {audit_dir}"))
        else:
            checks.append(CheckResult(name="Audit Storage", status="PASS", message=f"Verrà creata alla prima esecuzione: {audit_dir}"))

        # 5. Shell Environment
        current_shell = os.environ.get("SHELL", "")
        if "zsh" in current_shell or "bash" in current_shell:
            checks.append(CheckResult(name="Shell Compatibility", status="PASS", message=f"Shell attiva supportata: {current_shell}"))
        else:
            checks.append(CheckResult(name="Shell Compatibility", status="WARN", message=f"Shell non standard: {current_shell}"))

        overall = all(c.status != "FAIL" for c in checks)

        return DoctorReport(
            overall_healthy=overall,
            platform=sys.platform,
            checks=checks
        )
