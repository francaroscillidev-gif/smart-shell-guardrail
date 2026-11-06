import math
import re
from typing import List, Tuple
from .models import RiskLevel, SecurityCheckResult
from .config import GuardrailConfig

BLOCKED_PATTERNS: List[Tuple[str, str]] = [
    (r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*)\s+(/|/\*|~|~/\*|\$HOME|\$HOME/\*)(\s+|$)", "Tentativo di cancellazione ricorsiva forzata della root o home directory (`rm -rf /` o `~`)."),
    (r"\b(mkfs(\.[a-zA-Z0-9]+)?|fdisk|parted)\b", "Operazione a basso livello di formattazione o partizionamento disco."),
    (r"\bdd\s+.*if=.*of=(/dev/sd[a-z]|/dev/nvme[0-9]n[0-9]|/dev/disk[0-9])\b", "Scrittura diretta su blocco raw di sistema tramite `dd`."),
    (r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", "Fork bomb rilevata."),
    (r">\s*(/dev/sda|/dev/disk[0-9]|/etc/passwd|/etc/shadow|/etc/sudoers)", "Sovrascrittura diretta di file critici o device di sistema."),
    (r"\bchmod\s+(-R\s+)?(777|a\+rwx)\s+(/|/etc|/var|/usr|~)", "Permessi aperti insicuri (777) applicati a directory critiche."),
]

WARNING_PATTERNS: List[Tuple[str, str]] = [
    (r"\brm\s+(-[a-zA-Z]*r|--recursive)\b", "Cancellazione ricorsiva di cartelle/file."),
    (r"\b(git\s+reset\s+--hard|git\s+clean\s+-[a-zA-Z]*f|git\s+push\s+.*--force)\b", "Operazione git distruttiva con possibile perdita di dati."),
    (r"\bkill\s+-9\s+[0-9]+", "Invio di segnale SIGKILL non gestibile dal processo."),
    (r"\b(systemctl\s+stop|service\s+.*stop)\b", "Arresto di un demone o servizio di sistema."),
    (r"\b(drop\s+database|truncate\s+table)\b", "Comando SQL di cancellazione database o tabella."),
    (r"\bcurl\b.*\|\s*(sh|bash|zsh)\b", "Download ed esecuzione remota immediata di script non verificato via pipe.")
]

SECRET_PATTERNS: List[Tuple[str, str]] = [
    (r"ghp_[a-zA-Z0-9]{36,255}", "GitHub Personal Access Token"),
    (r"github_pat_[a-zA-Z0-9_]{50,255}", "GitHub Fine-Grained Token"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,99}", "Stripe API Key"),
    (r"AIza[0-9A-Za-z\\-_]{35}", "Google API Key"),
    (r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}", "Slack Token"),
    (r"-----BEGIN (RSA|EC|DSA|OPENSSH|PRIVATE) KEY-----", "Private Cryptographic Key"),
    (r"(?:Bearer\s+|api[_-]?key[\s=:'\"]+)[A-Za-z0-9_\-\.]{20,}", "Possibile Token di autorizzazione / API Key in chiaro")
]

def shannon_entropy(data: str) -> float:
    """Calcola l'entropia di Shannon per rilevare stringhe casuali/crittografiche ad alta entropia."""
    if not data:
        return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy

class SecurityGuardrail:
    def __init__(self, config: GuardrailConfig):
        self.config = config

    def evaluate(self, command: str) -> SecurityCheckResult:
        cleaned_cmd = command.strip()
        reasons = []
        detected_secrets = []

        # 0. Controllo Whitelist (se definita)
        if self.config.allowed_commands_whitelist:
            cmd_prefix = cleaned_cmd.split()[0] if cleaned_cmd else ""
            if cmd_prefix not in self.config.allowed_commands_whitelist:
                return SecurityCheckResult(
                    allowed=False,
                    risk_level=RiskLevel.BLOCKED,
                    reasons=[f"Il comando `{cmd_prefix}` non è presente nella whitelist dei comandi ammessi."],
                    suggested_safe_command=None
                )

        # 1. Scansione Segreti (Pattern Deterministi)
        for pattern, desc in SECRET_PATTERNS:
            matches = re.findall(pattern, cleaned_cmd)
            if matches:
                detected_secrets.append(desc)
                reasons.append(f"Rilevato possibile secret/credential: {desc}")

        # 2. Scansione Heuristica ad Alta Entropia (Secret Anomali non catalogati)
        words = re.findall(r"[A-Za-z0-9_\-]{24,}", cleaned_cmd)
        for w in words:
            # Escludiamo path e comandi comuni
            if not any(prefix in w for prefix in ("sha256", "docker", "commit")):
                ent = shannon_entropy(w)
                if ent >= 4.3:  # Soglia di entropia per secret generati casualmente
                    detected_secrets.append(f"Stringa ad alta entropia ({ent:.2f}): {w[:6]}...{w[-4:]}")
                    reasons.append(f"Rilevata potenziale chiave/secret casuale ad alta entropia.")
                    break

        if detected_secrets:
            return SecurityCheckResult(
                allowed=False,
                risk_level=RiskLevel.BLOCKED,
                reasons=reasons,
                detected_secrets=detected_secrets,
                suggested_safe_command="Usa variabili d'ambiente (es. $MY_TOKEN) invece di inserire segreti nel comando."
            )

        # 3. Controllo Custom Blocked Patterns da Config
        for custom_pattern in self.config.custom_blocked_patterns:
            if re.search(custom_pattern, cleaned_cmd, re.IGNORECASE):
                reasons.append(f"Bloccato da policy personalizzata: pattern `{custom_pattern}`")
                return SecurityCheckResult(
                    allowed=False,
                    risk_level=RiskLevel.BLOCKED,
                    reasons=reasons
                )

        # 4. Controllo Comandi Bloccati di Default
        for pattern, desc in BLOCKED_PATTERNS:
            if re.search(pattern, cleaned_cmd, re.IGNORECASE):
                reasons.append(f"Blocco di sicurezza: {desc}")
                return SecurityCheckResult(
                    allowed=False,
                    risk_level=RiskLevel.BLOCKED,
                    reasons=reasons,
                    suggested_safe_command=None
                )

        # 5. Controllo Comandi a Rischio (WARNING)
        for pattern, desc in WARNING_PATTERNS:
            if re.search(pattern, cleaned_cmd, re.IGNORECASE):
                reasons.append(desc)

        if reasons:
            allowed = not self.config.strict_mode
            return SecurityCheckResult(
                allowed=allowed,
                risk_level=RiskLevel.WARNING,
                reasons=reasons,
                suggested_safe_command=None
            )

        return SecurityCheckResult(
            allowed=True,
            risk_level=RiskLevel.SAFE,
            reasons=[]
        )
