import os
import re
import shutil
import subprocess
from typing import Optional
from .models import SystemDiagnostics

class SystemDiagnosticEngine:
    def analyze(self, command: str, exit_code: int, stdout: str, stderr: str) -> Optional[SystemDiagnostics]:
        if exit_code == 0:
            return None

        output = f"{stdout}\n{stderr}"

        # 1. Conflitto porta (Port already in use / EADDRINUSE)
        port_match = re.search(r"(?:address already in use|EADDRINUSE).*?(?:port\s+|:)([0-9]{2,5})", output, re.IGNORECASE)
        if not port_match:
            port_match = re.search(r"port\s+([0-9]{2,5})\s+is already in use", output, re.IGNORECASE)

        if port_match:
            port = port_match.group(1)
            return self._diagnose_port_conflict(port)

        # 2. Permission Denied / EACCES
        if re.search(r"(?:permission denied|EACCES)", output, re.IGNORECASE):
            return self._diagnose_permission_denied(command, output)

        # 3. Command not found / Missing binary
        cmd_not_found = re.search(r"(?:command not found|zsh: command not found:?|bash: (.*?): command not found)\s*([a-zA-Z0-9_\-\.]+)?", output, re.IGNORECASE)
        if cmd_not_found or exit_code == 127:
            binary = cmd_not_found.group(2) if (cmd_not_found and cmd_not_found.group(2)) else command.strip().split()[0]
            return self._diagnose_missing_command(binary)

        # 4. Modulo Python non trovato
        py_module = re.search(r"ModuleNotFoundError:\s+No module named\s+['\"]([^'\"]+)['\"]", output)
        if py_module:
            module_name = py_module.group(1)
            return self._diagnose_python_module(module_name)

        # 5. Git lock file
        if "index.lock" in output:
            return SystemDiagnostics(
                error_category="git_lock",
                summary="Git index è bloccato da un'altra operazione o da un processo crashato.",
                details={"lock_file": ".git/index.lock"},
                suggested_actions=["Rimuovi il file di lock se nessun altro comando git è in esecuzione."],
                quick_fix_command="rm -f .git/index.lock",
                is_auto_fixable=True
            )

        # 6. Spazio su disco esaurito (No space left on device)
        if "no space left on device" in output.lower():
            return SystemDiagnostics(
                error_category="disk_full",
                summary="Spazio su disco o quota inode esaurita.",
                details={},
                suggested_actions=[
                    "Controlla lo spazio disponibile con `df -h`.",
                    "Svuota cache temporanee o directory di log."
                ],
                quick_fix_command="df -h",
                is_auto_fixable=False
            )

        # Fallback generico per comandi falliti
        return SystemDiagnostics(
            error_category="generic_error",
            summary=f"Il comando è terminato con exit code {exit_code}.",
            details={"exit_code": exit_code},
            suggested_actions=["Ispeziona i dettagli in stderr sopra riportati."],
            is_auto_fixable=False
        )

    def _diagnose_port_conflict(self, port: str) -> SystemDiagnostics:
        occupying_process = None
        pid = None
        cmdline = None

        try:
            res = subprocess.run(
                ["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN"],
                capture_output=True,
                text=True,
                timeout=2
            )
            lines = res.stdout.strip().split("\n")
            if len(lines) > 1:
                parts = lines[1].split()
                occupying_process = parts[0]
                pid = parts[1]
                ps_res = subprocess.run(["ps", "-p", pid, "-o", "command="], capture_output=True, text=True, timeout=2)
                cmdline = ps_res.stdout.strip()
        except Exception:
            pass

        actions = [f"La porta {port} è già occupata da un altro servizio."]
        quick_fix = None
        is_auto_fixable = False

        if pid:
            actions.append(f"Processo rilevato: '{occupying_process}' (PID: {pid}) -> `{cmdline}`")
            quick_fix = f"kill -15 {pid}"
            actions.append(f"Puoi terminare il processo con: `{quick_fix}`")
            is_auto_fixable = True
        else:
            quick_fix = f"lsof -i :{port}"
            actions.append(f"Usa `{quick_fix}` per visualizzare il processo e liberare la porta.")

        return SystemDiagnostics(
            error_category="port_conflict",
            summary=f"Conflitto di rete: la porta {port} è già in uso.",
            details={"port": port, "pid": pid, "process": occupying_process, "cmd": cmdline},
            suggested_actions=actions,
            quick_fix_command=quick_fix,
            is_auto_fixable=is_auto_fixable
        )

    def _diagnose_permission_denied(self, command: str, output: str) -> SystemDiagnostics:
        path_match = re.search(r"['\"]?(/[^\s'\"\)\]]+|(?:\./|[a-zA-Z0-9_\-]+/)[^\s'\"\)\]]+)['\"]?", output)
        target_path = path_match.group(1) if path_match else None

        details = {"target_path": target_path}
        actions = []
        is_auto_fixable = False
        quick_fix = None

        if target_path and os.path.exists(target_path):
            stat_info = os.stat(target_path)
            details["mode"] = oct(stat_info.st_mode)
            details["owner_uid"] = stat_info.st_uid
            current_uid = os.getuid()
            if stat_info.st_uid != current_uid:
                actions.append(f"Il file o cartella `{target_path}` appartiene a un altro utente (UID {stat_info.st_uid}).")
                quick_fix = f"sudo chown -R $(whoami) {target_path}"
            else:
                actions.append(f"Non hai i permessi di scrittura/esecuzione su `{target_path}`.")
                quick_fix = f"chmod +rw {target_path}"
                is_auto_fixable = True
        else:
            actions.append("L'operazione richiede privilegi elevati o permessi di scrittura.")
            quick_fix = f"sudo {command}" if not command.startswith("sudo ") else None

        return SystemDiagnostics(
            error_category="permission_denied",
            summary="Accesso negato: permessi insufficienti per completare l'operazione.",
            details=details,
            suggested_actions=actions,
            quick_fix_command=quick_fix,
            is_auto_fixable=is_auto_fixable
        )

    def _diagnose_missing_command(self, binary: str) -> SystemDiagnostics:
        package_managers = []
        if shutil.which("brew"):
            package_managers.append(f"brew install {binary}")
        if shutil.which("npm"):
            package_managers.append(f"npm install -g {binary}")
        if shutil.which("uv"):
            package_managers.append(f"uv tool install {binary}")

        return SystemDiagnostics(
            error_category="command_not_found",
            summary=f"Eseguibile `{binary}` non trovato nel PATH di sistema.",
            details={"binary": binary},
            suggested_actions=[
                "Verifica che il programma sia installato e presente nelle variabili d'ambiente PATH.",
                f"Possibili comandi di installazione: {', '.join(package_managers)}" if package_managers else "Installa l'eseguibile tramite il tuo package manager."
            ],
            quick_fix_command=package_managers[0] if package_managers else None,
            is_auto_fixable=False
        )

    def _diagnose_python_module(self, module_name: str) -> SystemDiagnostics:
        in_venv = os.environ.get("VIRTUAL_ENV") is not None
        fix_cmd = f"uv add {module_name}" if shutil.which("uv") else f"pip install {module_name}"

        return SystemDiagnostics(
            error_category="python_module_missing",
            summary=f"Il modulo Python '{module_name}' non è installato nell'ambiente corrente.",
            details={"module": module_name, "virtual_env": os.environ.get("VIRTUAL_ENV")},
            suggested_actions=[
                f"Installa il pacchetto nell'ambiente {'virtuale' if in_venv else 'di sistema'}.",
                f"Esegui: `{fix_cmd}`"
            ],
            quick_fix_command=fix_cmd,
            is_auto_fixable=True
        )
