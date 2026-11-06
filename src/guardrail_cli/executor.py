import os
import time
import threading
import subprocess
from typing import Optional
from .models import ExecutionResult
from .guardrail import SecurityGuardrail
from .diagnostics import SystemDiagnosticEngine
from .config import GuardrailConfig
from .rollback import RollbackManager, WorkspaceSnapshot
from .monitor import ProcessMonitor

class Executor:
    def __init__(self, guardrail: SecurityGuardrail, diagnostic_engine: SystemDiagnosticEngine, config: GuardrailConfig):
        self.guardrail = guardrail
        self.diagnostic_engine = diagnostic_engine
        self.config = config
        self.rollback_mgr = RollbackManager(config.working_dir_restriction)

    def run(self, command: str, capture_snapshot: bool = False) -> ExecutionResult:
        start_time = time.time()
        cwd = self.config.working_dir_restriction or os.getcwd()

        snapshot: Optional[WorkspaceSnapshot] = None
        if capture_snapshot:
            try:
                snapshot = self.rollback_mgr.create_snapshot()
            except Exception:
                pass

        try:
            process = subprocess.Popen(
                command,
                shell=True,
                executable="/bin/zsh",
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # Monitor delle risorse in thread separato
            monitor = ProcessMonitor(process.pid)
            stop_monitoring = threading.Event()

            def monitor_loop():
                while not stop_monitoring.is_set():
                    monitor.sample()
                    time.sleep(0.05)

            monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
            monitor_thread.start()

            # Timeout enforcement
            stdout, stderr = process.communicate(timeout=self.config.timeout_seconds)
            exit_code = process.returncode
            timed_out = False

            stop_monitoring.set()
            monitor_thread.join(timeout=0.2)
            resources = monitor.get_summary()

        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            exit_code = 124
            timed_out = True
            stderr = (stderr or "") + f"\n[GUARDRAIL ERROR] Il comando ha superato il timeout massimo consentito di {self.config.timeout_seconds}s."
            resources = None

        duration_ms = round((time.time() - start_time) * 1000, 2)
        if resources:
            resources.duration_ms = duration_ms

        # Troncamento output
        max_bytes = self.config.max_output_kb * 1024
        truncated = False

        if len(stdout.encode("utf-8")) > max_bytes:
            stdout = stdout[:max_bytes] + "\n...[OUTPUT TRONCATO DAL GUARDRAIL]..."
            truncated = True

        if len(stderr.encode("utf-8")) > max_bytes:
            stderr = stderr[:max_bytes] + "\n...[STDERR TRONCATO DAL GUARDRAIL]..."
            truncated = True

        # Calcolo Diff del workspace se lo snapshot era attivo
        diff = None
        if snapshot:
            diff = self.rollback_mgr.compute_diff(snapshot)

        diagnostics = None
        if exit_code != 0:
            diagnostics = self.diagnostic_engine.analyze(command, exit_code, stdout, stderr)

        return ExecutionResult(
            command=command,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_ms=duration_ms,
            timed_out=timed_out,
            truncated=truncated,
            resources=resources,
            diff=diff,
            diagnostics=diagnostics
        )
