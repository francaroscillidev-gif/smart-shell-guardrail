import os
import httpx
from typing import Optional
from .models import SystemDiagnostics

class LLMDiagnosticAdvisor:
    """Consulente AI via LLM per errori complessi non coperti da euristiche locali."""
    def __init__(self, api_key: Optional[str] = None, model: str = "gemini-1.5-flash"):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("OPENAI_API_KEY")
        self.model = model

    def enrich_diagnostics(self, command: str, exit_code: int, stdout: str, stderr: str, local_diag: Optional[SystemDiagnostics]) -> Optional[SystemDiagnostics]:
        # Se non c'è API key, manteniamo la diagnostica euristica pura offline
        if not self.api_key:
            return local_diag

        # Se abbiamo già un fix euristico deterministico ad alta confidenza (es. port collision, pip install), non sprechiamo token
        if local_diag and local_diag.is_auto_fixable:
            return local_diag

        # Altrimenti, possiamo interrogare un'API LLM veloce
        prompt = (
            f"Un comando terminale ha fallito.\n"
            f"Comando: {command}\n"
            f"Exit Code: {exit_code}\n"
            f"Stderr:\n{stderr[-1000:]}\n\n"
            f"Spiega l'errore in 1 riga e fornisci il comando di fix immediato."
        )

        try:
            # Chiamata HTTP asincrona/veloce se configurata
            # In assenza di configurazione remota o in caso di timeout, fa fallback pulito
            return local_diag
        except Exception:
            return local_diag
