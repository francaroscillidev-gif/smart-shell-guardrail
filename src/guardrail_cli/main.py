import sys
import json
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from prompt_toolkit import PromptSession
from prompt_toolkit.history import InMemoryHistory

from .models import RiskLevel
from .config import load_config
from .audit import AuditLogger
from .guardrail import SecurityGuardrail
from .diagnostics import SystemDiagnosticEngine
from .executor import Executor

console = Console()

@click.group()
def cli():
    """Smart Guardrail CLI: Copilot e Firewall per Shell."""
    pass

@cli.command("simulate")
@click.argument("command", nargs=-1, required=True)
@click.option("--json-output", is_flag=True, help="Restituisce il report di simulazione in formato JSON.")
def simulate_command(command, json_output):
    """Simula l'esecuzione del comando calcolando l'impatto sul filesystem prima dell'invio (Dry-Run)."""
    from .simulator import DryRunSimulator
    full_cmd = " ".join(command)
    simulator = DryRunSimulator()
    analysis = simulator.analyze(full_cmd)

    if json_output:
        print(analysis.model_dump_json(indent=2))
        return

    color = "green" if analysis.is_safe else ("yellow" if analysis.risk_level.value == "WARNING" else "red")
    body = (
        f"Comando: [bold]{full_cmd}[/bold]\n"
        f"Intento Rilevato: {analysis.intent_summary}\n"
        f"Livello Rischio: [{color} bold]{analysis.risk_level.value}[/{color} bold]\n\n"
    )

    if analysis.affected_targets:
        body += "[bold cyan]Target Identificati:[/bold cyan]\n"
        for t in analysis.affected_targets:
            body += f" • {t}\n"
        body += "\n"

    if analysis.simulated_side_effects:
        body += "[bold yellow]Effetti Collaterali Simulati:[/bold yellow]\n"
        for effect in analysis.simulated_side_effects:
            body += f" ⚠ {effect}\n"
        body += "\n"

    if analysis.remediation_advice:
        body += f"[bold green]Suggerimento di Sicurezza:[/bold green] {analysis.remediation_advice}"

    console.print(Panel(
        body.strip(),
        title="🔮 Dry-Run & Blast Radius Simulator",
        border_style=color
    ))

@cli.command("doctor")
def run_doctor():
    """Esegue un checkup completo dell'ambiente di sistema, isolamento e configurazione."""
    from .doctor import GuardrailDoctor
    doctor = GuardrailDoctor()
    report = doctor.run_diagnostics()

    table = Table(title=f"🩺 Smart Shell Guardrail Doctor ({report.platform})")
    table.add_column("Componente", style="bold")
    table.add_column("Stato")
    table.add_column("Dettagli", style="dim")

    for c in report.checks:
        if c.status == "PASS":
            status_text = "[bold green]✔ PASS[/bold green]"
        elif c.status == "WARN":
            status_text = "[bold yellow]⚠ WARN[/bold yellow]"
        else:
            status_text = "[bold red]✖ FAIL[/bold red]"

        table.add_row(c.name, status_text, c.message)

    console.print(table)
    if report.overall_healthy:
        console.print("\n[bold green]✓ Il sistema soddisfa tutti i requisiti operativi per l'esecuzione protetta.[/bold green]\n")
    else:
        console.print("\n[bold yellow]! Rilevate alcune raccomandazioni di sistema non critiche.[/bold yellow]\n")

@cli.command("exec")
@click.argument("command", nargs=-1, required=True)
@click.option("--strict", is_flag=True, default=False, help="In strict mode blocca anche comandi di warning.")
@click.option("--timeout", type=int, default=None, help="Timeout in secondi per il comando (default: 120s).")
@click.option("--snapshot", is_flag=True, default=False, help="Crea uno snapshot del workspace prima di eseguire e calcola il diff.")
@click.option("--sandbox", is_flag=True, default=False, help="Esegue il comando confinato nel sandbox OS (Seatbelt/bwrap).")
@click.option("--config", "config_file", type=str, default=None, help="Path a file di configurazione YAML.")
@click.option("--auto-fix", is_flag=True, default=False, help="Esegue automaticamente il Quick Fix diagnostico se disponibile e sicuro.")
@click.option("--json-output", is_flag=True, help="Restituisce il risultato strutturato in formato JSON (ideale per agenti AI).")
def execute_cmd(command, strict, timeout, snapshot, sandbox, config_file, auto_fix, json_output):
    """Esegue un comando singolo applicando guardrail, audit, timeout, monitor risorse e diagnostica."""
    full_cmd = " ".join(command)
    cfg = load_config(config_file)
    if strict:
        cfg.strict_mode = True
    if timeout:
        cfg.timeout_seconds = timeout

    audit_logger = AuditLogger(cfg.audit.log_file) if cfg.audit.enabled else None
    guardrail = SecurityGuardrail(cfg)
    diagnostics = SystemDiagnosticEngine()
    executor = Executor(guardrail, diagnostics, cfg)

    # 1. Valutazione Guardrail
    check = guardrail.evaluate(full_cmd)

    if not check.allowed:
        if audit_logger:
            audit_logger.log_event(full_cmd, check)

        if json_output:
            print(json.dumps({
                "status": "blocked",
                "risk_level": check.risk_level.value,
                "reasons": check.reasons,
                "secrets_detected": check.detected_secrets,
                "suggested_safe_command": check.suggested_safe_command
            }, indent=2))
        else:
            console.print(Panel(
                f"[bold red]COMANDO BLOCCATO DAL GUARDRAIL[/bold red]\n\n"
                f"Livello di rischio: [bold yellow]{check.risk_level.value}[/bold yellow]\n"
                f"Motivazioni:\n" + "\n".join([f" • {r}" for r in check.reasons]) +
                (f"\n\n[green]Suggerimento:[/green] {check.suggested_safe_command}" if check.suggested_safe_command else ""),
                title="🛡️ Security Guardrail",
                border_style="red"
            ))
        sys.exit(1)

    if check.risk_level == RiskLevel.WARNING and not json_output:
        console.print(f"[bold yellow]⚠️  Attenzione:[/bold yellow] Rilevata operazione sensibile: {', '.join(check.reasons)}")

    # 2. Esecuzione del comando
    result = executor.run(full_cmd, capture_snapshot=snapshot, use_sandbox=sandbox)

    if audit_logger:
        audit_logger.log_event(full_cmd, check, result, duration_ms=result.duration_ms)

    # 3. Gestione Auto-Fix per Agenti/Utenti
    auto_fixed_result = None
    if result.exit_code != 0 and auto_fix and result.diagnostics and result.diagnostics.quick_fix_command:
        quick_fix = result.diagnostics.quick_fix_command
        if not json_output:
            console.print(f"\n[bold yellow]⚡ Tentativo Auto-Fix in corso:[/bold yellow] [cyan]{quick_fix}[/cyan]...")
        fix_check = guardrail.evaluate(quick_fix)
        if fix_check.allowed:
            fix_exec = executor.run(quick_fix)
            if fix_exec.exit_code == 0:
                if not json_output:
                    console.print(f"[bold green]✓ Quick Fix applicato con successo![/bold green] Riprovo il comando originale...\n")
                # Riesegue il comando originario
                result = executor.run(full_cmd)
                if audit_logger:
                    audit_logger.log_event(f"[AUTO-RETRY] {full_cmd}", check, result, duration_ms=result.duration_ms)

    if json_output:
        print(result.model_dump_json(indent=2))
        sys.exit(result.exit_code)

    # 4. Output a terminale
    if result.stdout:
        console.print(result.stdout, end="")
    if result.stderr:
        console.print(f"[red]{result.stderr}[/red]", end="")

    if result.timed_out:
        console.print(Panel(f"[bold red]TIMEOUT RAGGIUNTO ({cfg.timeout_seconds}s)[/bold red]: Il processo è stato terminato forzatamente per prevenire loop infiniti o freeze.", border_style="red"))

    # 5. Box Diagnostico Copilot
    if result.diagnostics:
        diag = result.diagnostics
        body = f"[bold]{diag.summary}[/bold]\n\n"
        if diag.suggested_actions:
            body += "[cyan]Diagnosi & Suggerimenti:[/cyan]\n"
            for action in diag.suggested_actions:
                body += f" • {action}\n"
        if diag.quick_fix_command:
            body += f"\n[green bold]Quick Fix consigliato:[/green bold] [underline]{diag.quick_fix_command}[/underline]"

        console.print(Panel(
            body,
            title=f"🔧 Diagnostic Copilot ({diag.error_category})",
            border_style="cyan"
        ))

    sys.exit(result.exit_code)

@cli.command("pty")
@click.option("--config", "config_file", type=str, default=None, help="Path a file di configurazione YAML.")
def start_native_pty(config_file):
    """Avvia una vera subshell PTY interattiva (supporta vim, nano, htop con guardrail in tempo reale)."""
    from .pty_session import PTYInteractiveInterceptionEngine
    cfg = load_config(config_file)
    guardrail = SecurityGuardrail(cfg)
    console.print(Panel(
        "[bold cyan]Avvio Pseudo-Terminale (PTY) con Intercettazione Hardware[/bold cyan]\n"
        "Tutti i keystroke e i comandi vengono ispezionati in tempo reale prima di raggiungere la shell.\n"
        "Supporta completamente programmi curses, editor (vim, nano) e segnali di controllo.\n"
        "Digita [bold]exit[/bold] per tornare al terminale host.",
        title="🖥️ Native PTY Guardrail",
        border_style="cyan"
    ))
    pty_engine = PTYInteractiveInterceptionEngine(guardrail, cfg)
    pty_engine.spawn_interactive_pty()

@cli.command("session")
@click.option("--strict", is_flag=True, default=False, help="In strict mode blocca anche comandi di warning.")
@click.option("--config", "config_file", type=str, default=None, help="Path a file di configurazione YAML.")
def interactive_session(strict, config_file):
    """Avvia una sessione shell interattiva protetta con autodiagnostica."""
    cfg = load_config(config_file)
    if strict:
        cfg.strict_mode = True

    audit_logger = AuditLogger(cfg.audit.log_file) if cfg.audit.enabled else None
    guardrail = SecurityGuardrail(cfg)
    diagnostics = SystemDiagnosticEngine()
    executor = Executor(guardrail, diagnostics, cfg)
    session = PromptSession(history=InMemoryHistory())

    console.print(Panel(
        "[bold cyan]Smart Shell Guardrail & Copilot Attivo[/bold cyan]\n"
        f"• Audit Log attivo su: [dim]{cfg.audit.log_file}[/dim]\n"
        f"• Timeout per comando: [yellow]{cfg.timeout_seconds}s[/yellow]\n"
        "• Protezione Secret Leak, Comandi Distruttivi e Auto-Diagnostica attiva.\n"
        "Digita [bold]exit[/bold] o premi Ctrl+D per uscire.",
        title="🚀 Sessione Protetta",
        border_style="cyan"
    ))

    while True:
        try:
            cmd = session.prompt("guardrail ❯ ")
            if not cmd.strip():
                continue
            if cmd.strip() in ("exit", "quit"):
                break

            check = guardrail.evaluate(cmd)
            if not check.allowed:
                if audit_logger:
                    audit_logger.log_event(cmd, check)
                console.print(Panel(
                    f"[bold red]COMANDO BLOCCATO[/bold red]\n"
                    f"Rischio: [bold yellow]{check.risk_level.value}[/bold yellow]\n"
                    + "\n".join([f" • {r}" for r in check.reasons]),
                    title="🛡️ Guardrail Alert",
                    border_style="red"
                ))
                continue

            if check.risk_level == RiskLevel.WARNING:
                console.print(f"[yellow]⚠️  Warning: {', '.join(check.reasons)}[/yellow]")
                confirm = session.prompt("Vuoi procedere comunque? [y/N]: ")
                if confirm.lower() not in ("y", "yes", "s", "si"):
                    console.print("[dim]Esecuzione annullata.[/dim]")
                    continue

            result = executor.run(cmd)
            if audit_logger:
                audit_logger.log_event(cmd, check, result, duration_ms=result.duration_ms)

            if result.stdout:
                console.print(result.stdout, end="")
            if result.stderr:
                console.print(f"[red]{result.stderr}[/red]", end="")

            if result.diagnostics:
                diag = result.diagnostics
                body = f"[bold]{diag.summary}[/bold]\n\n"
                for action in diag.suggested_actions:
                    body += f" • {action}\n"
                if diag.quick_fix_command:
                    body += f"\n[green bold]Quick Fix:[/green bold] {diag.quick_fix_command}"

                console.print(Panel(
                    body,
                    title="🔧 Diagnostic Copilot",
                    border_style="cyan"
                ))

                if diag.is_auto_fixable and diag.quick_fix_command:
                    apply_fix = session.prompt("Vuoi applicare il quick fix ora? [y/N]: ")
                    if apply_fix.lower() in ("y", "yes", "s", "si"):
                        console.print(f"[cyan]Esecuzione fix:[/cyan] {diag.quick_fix_command}")
                        fix_res = executor.run(diag.quick_fix_command)
                        if fix_res.stdout:
                            console.print(fix_res.stdout, end="")
                        if fix_res.exit_code == 0:
                            console.print("[green]Fix applicato con successo![/green]")

        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Uscita dalla sessione protetta.[/dim]")
            break

@cli.command("audit-logs")
@click.option("--limit", type=int, default=10, help="Numero di eventi da mostrare.")
@click.option("--config", "config_file", type=str, default=None, help="Path a file di configurazione YAML.")
def view_audit_logs(limit, config_file):
    """Visualizza gli ultimi log di audit e comandi intercettati."""
    import os
    cfg = load_config(config_file)
    from pathlib import Path
    p = Path(os.path.expanduser(cfg.audit.log_file))
    if not p.exists():
        console.print("[dim]Nessun log di audit trovato.[/dim]")
        return

    lines = p.read_text(encoding="utf-8").strip().split("\n")
    recent = lines[-limit:]

    table = Table(title=f"📜 Ultimi Eventi di Audit ({cfg.audit.log_file})")
    table.add_column("Timestamp", style="dim")
    table.add_column("Comando", style="cyan")
    table.add_column("Esito", style="bold")
    table.add_column("Rischio")
    table.add_column("Durata (ms)")

    for line in recent:
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
            status = "[green]ALLOWED[/green]" if entry.get("allowed") else "[red]BLOCKED[/red]"
            risk = entry.get("risk_level", "UNKNOWN")
            risk_styled = f"[red]{risk}[/red]" if risk == "BLOCKED" else (f"[yellow]{risk}[/yellow]" if risk == "WARNING" else f"[green]{risk}[/green]")
            table.add_row(
                entry.get("timestamp", "")[:19],
                entry.get("command", "")[:40],
                status,
                risk_styled,
                str(entry.get("duration_ms", "-"))
            )
        except Exception:
            continue

    console.print(table)

@cli.command("mcp")
@click.option("--config", "config_file", type=str, default=None, help="Path a file di configurazione YAML.")
@click.option("--generate-config", type=click.Choice(["claude", "cursor", "antigravity", "generic"], case_sensitive=False), default=None, help="Genera il blocco JSON di configurazione MCP per il client specificato.")
def start_mcp_server(config_file, generate_config):
    """Avvia il server MCP (Model Context Protocol) o genera la configurazione per client AI."""
    import asyncio
    import os
    import sys
    from pathlib import Path
    from .mcp_server import GuardrailMCPServer

    if generate_config:
        # Determina il percorso dell'eseguibile guardrail o uv run
        guardrail_bin = "guardrail"
        config_path = str(Path(config_file).resolve()) if config_file else None

        args = ["mcp"]
        if config_path:
            args.extend(["--config", config_path])

        mcp_entry = {
            "command": guardrail_bin,
            "args": args,
            "env": {
                "PYTHONUNBUFFERED": "1"
            }
        }

        if generate_config.lower() == "claude":
            output = {
                "mcpServers": {
                    "smart-shell-guardrail": mcp_entry
                }
            }
            console.print(Panel(
                f"[bold cyan]Configurazione MCP per Claude Desktop[/bold cyan]\n"
                f"Aggiungi questo blocco al tuo file:\n"
                f"[dim]~/Library/Application Support/Claude/claude_desktop_config.json[/dim]\n\n"
                f"[green]{json.dumps(output, indent=2)}[/green]",
                title="📋 Claude Desktop MCP Config",
                border_style="cyan"
            ))
        elif generate_config.lower() == "cursor":
            output = {
                "mcpServers": {
                    "smart-shell-guardrail": mcp_entry
                }
            }
            console.print(Panel(
                f"[bold cyan]Configurazione MCP per Cursor[/bold cyan]\n"
                f"Aggiungi questo blocco nel file del tuo progetto:\n"
                f"[dim].cursor/mcp.json[/dim]\n\n"
                f"[green]{json.dumps(output, indent=2)}[/green]",
                title="📋 Cursor MCP Config",
                border_style="cyan"
            ))
        else:
            output = {"smart-shell-guardrail": mcp_entry}
            console.print(Panel(
                f"[bold cyan]Configurazione MCP Generica / Antigravity[/bold cyan]\n\n"
                f"[green]{json.dumps(output, indent=2)}[/green]",
                title="📋 Generic MCP Config",
                border_style="cyan"
            ))
        return

    cfg = load_config(config_file)
    server = GuardrailMCPServer(cfg)
    try:
        asyncio.run(server.run_stdio())
    except (KeyboardInterrupt, EOFError):
        pass

def main():
    cli()

if __name__ == "__main__":
    main()
