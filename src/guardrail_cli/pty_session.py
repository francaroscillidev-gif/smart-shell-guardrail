import os
import sys
import pty
import select
import termios
import tty
import time
from typing import Optional, Callable
from .models import ExecutionResult, RiskLevel
from .guardrail import SecurityGuardrail
from .diagnostics import SystemDiagnosticEngine
from .config import GuardrailConfig

class PTYInteractiveInterceptionEngine:
    """Intercetta stdin/stdout/stderr a livello di pseudoterminale POSIX (PTY).
    Supporta programmi complessi a schermo intero (vim, nano, top, git log)
    mentre monitora i keystroke e blocca combinazioni distruttive o trap.
    """

    def __init__(self, guardrail: SecurityGuardrail, config: GuardrailConfig):
        self.guardrail = guardrail
        self.config = config

    def spawn_interactive_pty(self, shell_path: str = "/bin/zsh"):
        """Avvia una vera subshell PTY trasparente per l'utente umano."""
        if not sys.stdin.isatty():
            # Non siamo in una tty interattiva, fallback
            os.system(shell_path)
            return

        old_tty = termios.tcgetattr(sys.stdin)
        master_fd, slave_fd = pty.openpty()

        pid = os.fork()
        if pid == 0:
            # Child: diventa il processo collegato allo slave PTY
            os.close(master_fd)
            os.setsid()
            os.dup2(slave_fd, 0)
            os.dup2(slave_fd, 1)
            os.dup2(slave_fd, 2)
            os.close(slave_fd)
            os.execv(shell_path, [shell_path])
        else:
            # Parent: proxy trasparente con monitor
            os.close(slave_fd)
            tty.setraw(sys.stdin.fileno())

            input_buffer = []

            try:
                while True:
                    r, _, _ = select.select([sys.stdin.fileno(), master_fd], [], [], 0.05)
                    if sys.stdin.fileno() in r:
                        data = os.read(sys.stdin.fileno(), 1024)
                        if not data:
                            break
                        # Ispezione buffer su ritorno a capo (invio comando)
                        for b in data:
                            if b in (ord('\r'), ord('\n')):
                                typed_cmd = bytes(input_buffer).decode('utf-8', errors='ignore').strip()
                                input_buffer = []
                                # Valuta se il comando digitato in tempo reale viola il guardrail
                                if typed_cmd:
                                    chk = self.guardrail.evaluate(typed_cmd)
                                    if not chk.allowed:
                                        # Notifica immediata su PTY senza inviare enter alla shell sottostante
                                        os.write(master_fd, b"\x03") # Invia SIGINT per cancellare riga
                                        msg = f"\r\n\x1b[1;31m[GUARDRAIL BLOCKED]\x1b[0m Comando non consentito: {', '.join(chk.reasons)}\r\n"
                                        os.write(sys.stdout.fileno(), msg.encode())
                                        continue
                            elif b in (127, 8): # Backspace
                                if input_buffer:
                                    input_buffer.pop()
                            elif b >= 32:
                                input_buffer.append(b)

                        os.write(master_fd, data)

                    if master_fd in r:
                        data = os.read(master_fd, 1024)
                        if not data:
                            break
                        os.write(sys.stdout.fileno(), data)

            except Exception:
                pass
            finally:
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_tty)
                os.close(master_fd)
                try:
                    os.waitpid(pid, 0)
                except Exception:
                    pass
