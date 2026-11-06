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
def start_mcp_server(config_file):
    """Avvia il server MCP (Model Context Protocol) per integrazione con Claude Desktop, Cursor e agenti autonomi."""
    import asyncio
    from .mcp_server import GuardrailMCPServer
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
