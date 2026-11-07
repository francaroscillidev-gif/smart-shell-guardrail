import os
import re
import shlex
from typing import List, Optional
from pydantic import BaseModel, Field
from .models import RiskLevel

class ImpactAnalysis(BaseModel):
    is_safe: bool
    risk_level: RiskLevel
    intent_summary: str
    affected_targets: List[str] = Field(default_factory=list)
    simulated_side_effects: List[str] = Field(default_factory=list)
    remediation_advice: Optional[str] = None

class DryRunSimulator:
    """Simula l'effetto di comandi shell prima dell'invio reale (Dry-Run / Blast Radius analysis)."""

    def analyze(self, command: str) -> ImpactAnalysis:
        cmd = command.strip()
        tokens = cmd.split()
        if not tokens:
            return ImpactAnalysis(
                is_safe=True,
                risk_level=RiskLevel.SAFE,
                intent_summary="Comando vuoto"
            )

        binary = tokens[0]

        # 1. Analisi 'rm' (Blast radius su file e directory)
        if binary in ("rm", "/bin/rm"):
            is_recursive = any(arg.startswith("-") and "r" in arg for arg in tokens[1:])
            is_forced = any(arg.startswith("-") and "f" in arg for arg in tokens[1:])
            targets = [t for t in tokens[1:] if not t.startswith("-")]

            expanded_targets = []
            side_effects = []

            for t in targets:
                p = os.path.expanduser(t)
                abs_p = os.path.abspath(p)
                expanded_targets.append(abs_p)

                if os.path.exists(abs_p):
                    if os.path.isdir(abs_p):
                        try:
                            count = sum(len(files) + len(dirs) for _, dirs, files in os.walk(abs_p))
                            side_effects.append(f"Directory esistente con circa {count} elementi interni che verranno eliminati.")
                        except Exception:
                            side_effects.append("Directory esistente che verrà cancellata.")
                    else:
                        size = os.path.getsize(abs_p)
                        side_effects.append(f"File esistente ({size} bytes) che verrà rimosso in modo permanente.")
                else:
                    side_effects.append(f"Target '{t}' non esistente sul filesystem locale.")

            risk = RiskLevel.BLOCKED if ("/" in targets or "~" in targets) else (RiskLevel.WARNING if is_recursive else RiskLevel.SAFE)

            return ImpactAnalysis(
                is_safe=(risk == RiskLevel.SAFE),
                risk_level=risk,
                intent_summary=f"Cancellazione {'ricorsiva ' if is_recursive else ''}{'forzata ' if is_forced else ''}di {len(targets)} target.",
                affected_targets=expanded_targets,
                simulated_side_effects=side_effects,
                remediation_advice="Considera l'uso di 'trash' o crea uno snapshot con --snapshot prima di procedere."
            )

        # 2. Analisi 'git reset' o 'git clean'
        if binary == "git" and len(tokens) > 1:
            sub = tokens[1]
            if sub == "reset" and "--hard" in tokens:
                return ImpactAnalysis(
                    is_safe=False,
                    risk_level=RiskLevel.WARNING,
                    intent_summary="Ripristino forzato dello stato del repository Git allo HEAD.",
                    affected_targets=[os.getcwd()],
                    simulated_side_effects=[
                        "Tutte le modifiche non committate nell'albero di lavoro andranno perse definitivamente.",
                        "L'indice di staging verrà sovrascritto."
                    ],
                    remediation_advice="Esegui prima `git stash` per salvare il lavoro temporaneo."
                )
            elif sub == "clean" and any("-f" in a for a in tokens):
                return ImpactAnalysis(
                    is_safe=False,
                    risk_level=RiskLevel.WARNING,
                    intent_summary="Pulizia dei file non tracciati da Git.",
                    affected_targets=[os.getcwd()],
                    simulated_side_effects=["I file non tracciati verranno rimossi permanentemente."],
                    remediation_advice="Usa `git clean -n` per una preview prima della cancellazione."
                )

        # 3. Analisi Kill / Process Termination
        if binary in ("kill", "killall", "pkill"):
            pids = [t for t in tokens[1:] if t.isdigit()]
            return ImpactAnalysis(
                is_safe=True,
                risk_level=RiskLevel.WARNING if ("-9" in tokens or "-KILL" in tokens) else RiskLevel.SAFE,
                intent_summary=f"Invio di segnale di terminazione ai processi: {', '.join(pids) if pids else 'per pattern/nome'}.",
                affected_targets=pids,
                simulated_side_effects=["Il processo target potrebbe non completare il salvataggio dei dati su disco."],
                remediation_advice="Preferisci SIGTERM (-15) rispetto a SIGKILL (-9) per un arresto pulito."
            )

        # 4. Fallback Generico / Read-Only Inspection
        is_readonly = binary in ("ls", "cat", "grep", "find", "head", "tail", "echo", "pwd", "which", "stat")
        return ImpactAnalysis(
            is_safe=True,
            risk_level=RiskLevel.SAFE if is_readonly else RiskLevel.SAFE,
            intent_summary=f"Esecuzione standard del programma `{binary}`.",
            affected_targets=[],
            simulated_side_effects=["Nessun effetto distruttivo noto rilevato."] if is_readonly else []
        )
