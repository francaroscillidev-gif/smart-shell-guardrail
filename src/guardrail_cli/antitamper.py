import re
from typing import List, Tuple, Optional
from pydantic import BaseModel, Field

class ObfuscatedDeobfuscationResult(BaseModel):
    is_obfuscated: bool
    technique: Optional[str] = None
    decoded_command: Optional[str] = None
    risk_notes: List[str] = Field(default_factory=list)

class AntiTamperEngine:
    """Rileva tentativi di evasione, offuscamento e proxy execution di comandi malevoli."""

    BASE64_PIPE_REGEX = r"(?:base64\s+(?:-d|--decode)|openssl\s+enc\s+-d\s+-a)\s*\|\s*(?:sh|bash|zsh)"
    HEX_EVAL_REGEX = r"(?:printf|echo)\s+['\"].*?\\x[0-9a-fA-F]{2}.*?['\"]\s*\|\s*(?:sh|bash|zsh)"
    ENV_EXPANSION_REGEX = r"\$\{[^}]+\}"
    SUB_SHELL_NESTING_REGEX = r"\$\([^\)]*\$\([^\)]*\)[^\)]*\)"

    def inspect(self, command: str) -> ObfuscatedDeobfuscationResult:
        cmd = command.strip()
        risk_notes = []

        # 1. Base64 pipe to shell (es: echo "cm0gLXJmIC8=" | base64 -d | sh)
        if re.search(self.BASE64_PIPE_REGEX, cmd, re.IGNORECASE):
            risk_notes.append("Rilevata esecuzione tramite pipeline Base64 verso shell.")
            # Prova a estrarre la stringa base64 (almeno 8 caratteri)
            b64_match = re.search(r"['\"]([A-Za-z0-9+/=]{8,})['\"]", cmd)
            decoded = None
            if b64_match:
                import base64
                try:
                    raw_b64 = b64_match.group(1)
                    decoded = base64.b64decode(raw_b64).decode('utf-8', errors='ignore').strip()
                    risk_notes.append(f"Payload decodificato in chiaro: `{decoded}`")
                except Exception:
                    pass
            return ObfuscatedDeobfuscationResult(
                is_obfuscated=True,
                technique="base64_pipeline_eval",
                decoded_command=decoded,
                risk_notes=risk_notes
            )

        # 2. Hex escape execution (es: printf '\x72\x6d\x20\x2d\x72\x66\x20\x2f' | sh)
        if re.search(self.HEX_EVAL_REGEX, cmd, re.IGNORECASE):
            risk_notes.append("Rilevata esecuzione offuscata tramite sequenze escape esadecimali (hex bypass).")
            return ObfuscatedDeobfuscationResult(
                is_obfuscated=True,
                technique="hex_escape_eval",
                decoded_command=None,
                risk_notes=risk_notes
            )

        # 3. Concatenazioni spezzate tipo r''m -''rf (IFS o quote insertion)
        if re.search(r"\b(r['\"]*m['\"]*\s+-[a-zA-Z0-9'\"]*r)", cmd):
            if "'" in cmd.split()[0] or '"' in cmd.split()[0]:
                risk_notes.append("Rilevata tecnica di offuscamento tramite spezzamento stringhe (quote tampering).")
                return ObfuscatedDeobfuscationResult(
                    is_obfuscated=True,
                    technique="quote_tampering",
                    decoded_command=cmd.replace("'", "").replace('"', ''),
                    risk_notes=risk_notes
                )

        # 4. Proxy execution via xargs / eval / bash -c
        if re.search(r"\b(eval|bash\s+-c|sh\s+-c|zsh\s+-c)\s+['\"].*?['\"]", cmd):
            # Isola il comando interno
            inner_match = re.search(r"\b(?:eval|bash\s+-c|sh\s+-c|zsh\s+-c)\s+['\"](.*?)['\"]", cmd)
            inner_cmd = inner_match.group(1) if inner_match else None
            risk_notes.append("Comando incapsulato in proxy execution (eval/bash -c).")
            return ObfuscatedDeobfuscationResult(
                is_obfuscated=True,
                technique="proxy_eval",
                decoded_command=inner_cmd,
                risk_notes=risk_notes
            )

        return ObfuscatedDeobfuscationResult(
            is_obfuscated=False,
            technique=None,
            decoded_command=None,
            risk_notes=[]
        )
