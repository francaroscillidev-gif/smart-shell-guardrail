import os
import sys
import shutil
import tempfile
from pathlib import Path
from typing import List, Optional

class SandboxProfile:
    """Configurazione del profilo di sandbox OS-level."""
    def __init__(
        self,
        allow_read: bool = True,
        allow_network: bool = True,
        writable_paths: Optional[List[str]] = None,
        readonly_paths: Optional[List[str]] = None
    ):
        self.allow_read = allow_read
        self.allow_network = allow_network
        self.writable_paths = [str(Path(p).resolve()) for p in (writable_paths or [os.getcwd()])]
        self.readonly_paths = [str(Path(p).resolve()) for p in (readonly_paths or ["/usr", "/bin", "/sbin", "/opt", "/System", "/Library"])]

class OSSandboxRunner:
    """Esegue comandi dentro sandbox a livello di kernel OS (Seatbelt su macOS, Landlock/bwrap su Linux)."""
    
    def __init__(self, profile: Optional[SandboxProfile] = None):
        self.profile = profile or SandboxProfile()
        self.is_macos = sys.platform == "darwin"
        self.is_linux = sys.platform.startswith("linux")

    def wrap_command(self, command: str) -> List[str]:
        """Avvolge il comando con gli strumenti di sandboxing disponibili sul sistema."""
        if self.is_macos and shutil.which("sandbox-exec"):
            return self._build_macos_sandbox(command)
        elif self.is_linux and shutil.which("bwrap"):
            return self._build_linux_bwrap(command)
        
        # Fallback se non ci sono tool di sandbox OS: esegui direttamente nella shell
        return ["/bin/zsh", "-c", command]

    def _build_macos_sandbox(self, command: str) -> List[str]:
        # Profilo Tiny Scheme per macOS sandbox-exec (Apple Seatbelt)
        sb_lines = [
            "(version 1)",
            "(deny default)",
            "(allow process-exec*)",
            "(allow process-fork)",
            "(allow sysctl-read)",
            "(allow file-read*)"
        ]

        if self.profile.allow_network:
            sb_lines.append("(allow network*)")
        else:
            sb_lines.append("(deny network*)")

        # Permessi di scrittura confinati solo ai path ammessi e tmp
        sb_lines.append("(allow file-write* (subpath \"/private/tmp\"))")
        sb_lines.append("(allow file-write* (subpath \"/dev/null\"))")
        sb_lines.append("(allow file-write* (subpath \"/dev/tty\"))")
        
        for w_path in self.profile.writable_paths:
            sb_lines.append(f'(allow file-write* (subpath "{w_path}"))')

        scheme_profile = "\n".join(sb_lines)
        return ["sandbox-exec", "-p", scheme_profile, "/bin/zsh", "-c", command]

    def _build_linux_bwrap(self, command: str) -> List[str]:
        # Bubblewrap command builder per Linux
        args = ["bwrap", "--ro-bind", "/usr", "/usr", "--ro-bind", "/lib", "/lib"]
        if os.path.exists("/lib64"):
            args.extend(["--ro-bind", "/lib64", "/lib64"])
        args.extend(["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"])
        
        for w_path in self.profile.writable_paths:
            args.extend(["--bind", w_path, w_path])

        if not self.profile.allow_network:
            args.append("--unshare-net")

        args.extend(["--", "/bin/bash", "-c", command])
        return args
