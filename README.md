# Smart CLI / Shell Agent "Guardrail"

Un terminal guardrail intelligente e copilot diagnostico in tempo reale per sviluppatori e agenti autonomi.

## Caratteristiche

1. **Pre-execution Guardrail**:
   - **Prevenzione Distruzione**: Riconosce e blocca comandi come `rm -rf /`, `dd` su partizioni raw, fork bomb, `mkfs`.
   - **Secret Leak Blocker**: Scansiona i comandi prima dell'esecuzione per evitare che vengano passati token GitHub (`ghp_`), API key AWS, Google, Stripe o chiavi private in chiaro.
   - **Risk Classification**: Classifica i comandi in `SAFE`, `WARNING` e `BLOCKED`. Supporta la modalità `--strict` per bloccare o chiedere conferma sulle operazioni delicate.

2. **Error Diagnostic Copilot**:
   - Ispeziona lo stato di sistema quando un comando fallisce (exit code != 0).
   - Risolve conflitti di porta (`EADDRINUSE`) identificando automaticamente PID e processo tramite `lsof`/`ps` e fornendo il comando di kill o cambio porta.
   - Diagnostica errori di permessi (`EACCES`, `Permission Denied`) verificando proprietà del file e permessi effettivi.
   - Suggerisce comandi di installazione per binari mancanti (`command not found`) o pacchetti Python (`ModuleNotFoundError`).

3. **Dual Mode (Umano vs Agente AI)**:
   - **Modalità Interattiva (`session`)**: Sessione shell completa protetta con prompt di conferma sui warning e box di diagnostica visivi (Rich).
   - **Modalità Agente (`exec --json-output`)**: Output strutturato in JSON con `exit_code`, `diagnostics` e `quick_fix_command`, pronto per essere consumato da agenti autonomi per l'auto-healing.

## Utilizzo

### Esecuzione comando singolo
```bash
uv run python -m guardrail_cli.main exec "ls -la"
```

### Prova di blocco sicurezza (distruzione o secret leak)
```bash
uv run python -m guardrail_cli.main exec "rm -rf /"
uv run python -m guardrail_cli.main exec "curl -H 'Authorization: Bearer ghp_123456789012345678901234567890123456' https://api.github.com"
```

### Prova di diagnosi automatica
```bash
uv run python -m guardrail_cli.main exec "python3 -c 'import non_existent_pkg'"
```

### Modalità JSON per Agenti Autonomi
```bash
uv run python -m guardrail_cli.main exec --json-output "python3 -c 'import non_existent_pkg'"
```

### Sessione protetta interattiva
```bash
uv run python -m guardrail_cli.main session
```

---
**Author**: Franca Roscilli  
**Email**: francaroscillidev@gmail.com  
**GitHub**: [francaroscillidev-gif](https://github.com/francaroscillidev-gif)
