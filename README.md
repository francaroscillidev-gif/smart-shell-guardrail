<p align="center">
  <img src="assets/logo.png" alt="Smart Shell Guardrail Logo" width="180" height="180" />
</p>

<h1 align="center">Smart CLI / Shell Agent "Guardrail"</h1>

<p align="center">
  <b>AI-Powered Terminal Copilot & Autonomous Agent Security Sandbox</b>
</p>

<p align="center">
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.12+-blue.svg" alt="Python Version"></a>
  <a href="https://github.com/francaroscillidev-gif/smart-shell-guardrail/stargazers"><img src="https://img.shields.io/github/stars/francaroscillidev-gif/smart-shell-guardrail?style=social" alt="GitHub Stars"></a>
</p>

Un guardrail intelligente da terminale e copilot diagnostico in tempo reale per sviluppatori umani e agenti autonomi di intelligenza artificiale.

---

## 🎮 Terminal Showcase

### 1. Intercettazione Comando Distruttivo / Secret Leak
```ansi
╭─────────────────────────── 🛡️ Security Guardrail ────────────────────────────╮
│ COMANDO BLOCCATO DAL GUARDRAIL                                               │
│                                                                              │
│ Livello di rischio: BLOCKED                                                  │
│ Motivazioni:                                                                 │
│  • Blocco di sicurezza: Tentativo di cancellazione ricorsiva forzata della   │
│ root o home directory (`rm -rf /` o `~`).                                    │
│  • Rilevato possibile secret: GitHub Personal Access Token (ghp_***)         │
│                                                                              │
│ Suggerimento: Usa variabili d'ambiente (es. $MY_TOKEN) invece di inserire    │
│ segreti nel comando.                                                         │
╰──────────────────────────────────────────────────────────────────────────────╯
```

### 2. Autodiagnosi Istantanea Conflitto Porta (Port Already in Use)
```ansi
╭───────────────── 🔧 Diagnostic Copilot (port_conflict) ──────────────────────╮
│ Conflitto di rete: la porta 3000 è già in uso.                               │
│                                                                              │
│ Diagnosi & Suggerimenti:                                                     │
│  • Processo rilevato: 'node' (PID: 4921) -> `node server.js`                 │
│  • Puoi terminare il processo con: `kill -15 4921`                           │
│                                                                              │
│ Quick Fix consigliato: kill -15 4921                                         │
╰──────────────────────────────────────────────────────────────────────────────╯
```

---

## 💡 Il Problema
Dare accesso diretto alla shell a un agente autonomo (es. via tool `run_command` in loop) è pericoloso:
1. **Comandi Distruttivi**: Rischio di cancellazione file accidentale (`rm -rf`, sovrascrittura di partizioni o `.git`).
2. **Leak di Segreti**: Rischio di inviare token, chiavi API o credenziali all'interno di stringhe di comando visibili nei log.
3. **Loop Infiniti & Blocco**: Comandi che attendono input non fornito o vanno in timeout senza restituire contesto strutturato.
4. **Mancanza di Comprensione dello Stato**: I copilot convenzionali suggeriscono comandi generici senza ispezionare se la porta è occupata, chi la occupa o se i permessi sono insufficienti.

---

## 🛡️ Architettura & Funzionalità

### 1. Pre-execution Security Guardrail
- **Pattern Matcher di Sicurezza**: Riconosce e blocca istantaneamente comandi pericolosi (`rm -rf /`, `mkfs`, fork bomb, `dd` su partizioni raw).
- **Scanner Anti-Secret Leak con Entropia di Shannon**: 
  - Regex deterministiche per token noti (GitHub, AWS, Stripe, Slack, certificati RSA/SSH).
  - Algoritmo di **Shannon Entropy** ($H(X) \ge 4.3$) per intercettare password complesse, token e chiavi crittografiche casuali non categorizzate preventivamente.
- **Motore Anti-Tamper & De-offuscamento Dinamico (`antitamper.py`)**:
  - Intercetta payload offuscati in **Base64** inviati in pipe a shell (`echo ... | base64 -d | sh`), decodifica il payload in chiaro in sandbox e lo sottopone a scansione prima dell'esecuzione.
  - Neutralizza tecniche di quote tampering (es. `r''m -''rf /`) e hex escapes (`\x72\x6d`).
- **Network Egress Guard & Data Exfiltration Blocker (`network.py`)**:
  - Ispezione delle connessioni in uscita nei comandi shell (`curl`, `wget`, `nc`, `ssh`, `scp`).
  - Blocca l'esfiltrazione verso host non autorizzati se `block_external_egress: true` in configurazione, consentendo solo host locali o domini in whitelist.
- **AST Pipeline Parser (`parser.py`)**: Scompone pipeline complesse (`|`), redirezioni (`>`, `>>`) e concatenazioni logiche (`&&`, `||`, `;`) per analizzare atomicamente ogni singolo sottocomando, prevenendo tentativi di evasione da guardrail.
- **Tassonomia dei Rischi**: Classifica i comandi in `SAFE`, `WARNING` e `BLOCKED`. Supporta `--strict` per forzare l'approvazione sui warning.
- **Configurazione Estensibile (`.guardrail.yaml`)**: Regole custom per progetto (es. blocco di `npm publish` o comandi SQL di alterazione).

### 2. Auto-Diagnostic Copilot & Telemetria di Sistema
Quando un comando fallisce (`exit_code != 0`), il motore esegue una diagnosi euristica immediata (0ms) dello stato del sistema:
- **Conflitto di Porte (`EADDRINUSE`)**: Esegue `lsof` e `ps` per individuare il PID colpevole e propone `kill -15 <PID>` o cambio porta.
- **Permessi (`EACCES`)**: Esamina l'ownership (`os.stat`) e calcola se serve `chmod +rw` o `chown`.
- **Comando / Modulo mancante**: Trova il gestore di pacchetti locale (`uv`, `npm`, `brew`) e formula il comando di installazione.
- **Git Lock**: Rileva blocchi `.git/index.lock` e propone la rimozione sicura.

### 3. PTY Interattivo Nativo con Hardware Keystroke Interception (`guardrail pty`)
- Pseudo-terminale POSIX trasparente con passaggio di terminal raw: supporta programmi complessi curses (come `vim`, `nano`, `htop`, `git log`) bloccando i comandi malevoli digitati in tempo reale sul ritorno a capo prima che raggiungano la shell.

### 4. Simulatore di Impatto & Dry-Run Blast Radius (`guardrail simulate`)
- Esegue una stima preventiva dell'impatto di un comando sul filesystem locale senza eseguirlo.
- Calcola ricorsivamente il conteggio degli elementi coinvolti in un `rm`, la dimensione dei file impattati o i commit persi in un `git reset --hard`.

### 5. Checkup di Sistema Automatico (`guardrail doctor`)
- Verifica la corretta installazione dei componenti di isolamento (Apple Seatbelt, Linux Bubblewrap, uv, permessi directory di audit e compatibilità shell).

### 6. Snapshot, Diff & Rollback del Workspace (`--snapshot`)
- Effettua uno snapshot leggero prima dell'esecuzione del comando.
- Restituisce il delta puntuale di file creati, modificati e cancellati per un controllo granulare dell'impatto dei comandi.
- Fornisce capacità di ripristino istantaneo in caso di errore.

### 4. Monitor Risorse in Tempo Reale
- Campiona in background RAM (RSS di processo e figli) e durata con precisione in millisecondi per prevenire attacchi di tipo resource exhaustion.

### 5. Sandboxing a Livello Kernel OS (`--sandbox`)
- **macOS Seatbelt (`sandbox-exec`)**: Confinamento rigido dei permessi di scrittura filesystem (accesso consentito esclusivamente alla cartella del workspace corrente e `/tmp`). Tentativi di scrittura su `/opt`, `/etc`, `/usr` o cartelle utente esterne vengono bloccati a livello kernel con `Operation not permitted`.
- **Linux Bubblewrap (`bwrap`)**: Isolamento PID, rete e mount point unshare.

### 6. Server MCP (Model Context Protocol) Nativo (`guardrail mcp`)
- Implementa le specifiche standard MCP via JSON-RPC stdio.
- Permette a qualsiasi assistente o client AI compatibile (Claude Desktop, Cursor, Antigravity, cline) di invocare `safe_run_command` come tool nativo sicuro invece di dare accesso diretto e non protetto alla shell.

### 7. Dual Mode: Sviluppatore Umano vs Agente AI
- **Modalità Umana (`session`)**: Shell interattiva protetta con formattazione Rich, box visivi e conferma per i comandi critici.
- **Modalità Agente (`exec --json-output`)**: Output JSON standardizzato (conforme a Pydantic) contenente `diagnostics` e `quick_fix_command`, ideale per dare agli agenti capacità di **auto-healing autonomo**.

---

## 🚀 Installazione e Avvio Rapido

### Installazione Universale in 1 Riga (macOS & Linux)
Puoi installare globalmente Smart Shell Guardrail con un singolo comando:
```bash
curl -fsSL https://raw.githubusercontent.com/francaroscillidev-gif/smart-shell-guardrail/main/install.sh | bash
```

Oppure installa manualmente clonando il repository tramite [uv](https://docs.astral.sh/uv/):
```bash
git clone https://github.com/francaroscillidev-gif/smart-shell-guardrail.git
cd smart-shell-guardrail
uv sync
```

---

## 🤖 Integrazione MCP con Claude Desktop, Cursor & Agenti AI

Smart Shell Guardrail può essere collegato direttamente a **Claude Desktop**, **Cursor** o **Antigravity** tramite il protocollo MCP per proteggere tutte le sessioni agentiche.

### Generazione Automatica Configurazione
```bash
# Per Claude Desktop:
guardrail mcp --generate-config claude

# Per Cursor:
guardrail mcp --generate-config cursor
```

Oppure consulta il file di esempio pronto all'uso: [`mcp-config.example.json`](mcp-config.example.json).

### Esecuzione comando singolo
```bash
uv run python -m guardrail_cli.main exec "ls -la"
```

### Test del Blocco di Sicurezza
```bash
# Blocco distruzione di massa
uv run python -m guardrail_cli.main exec "rm -rf /"

# Blocco leak di segreti
uv run python -m guardrail_cli.main exec "curl -H 'Authorization: Bearer ghp_123456789012345678901234567890123456' https://api.github.com"
```

### Esecuzione con Timeout Guard
```bash
uv run python -m guardrail_cli.main exec --timeout 5 "sleep 10"
```

### Simulazione di Impatto & Blast Radius (Dry-Run)
```bash
guardrail simulate "rm -rf ./temp_folder"
```

### Verifica Salute di Sistema
```bash
guardrail doctor
```

### Esecuzione in Sandbox Kernel OS
```bash
# Esecuzione confinata nel workspace: i tentativi di scrittura su /opt o cartelle esterne falliscono
uv run python -m guardrail_cli.main exec --sandbox "touch /opt/forbidden.txt"
```

### Avvio Server MCP per Agenti AI
```bash
uv run python -m guardrail_cli.main mcp
```

### Auto-Diagnostica per Agenti Autonomi (Output JSON)
```bash
uv run python -m guardrail_cli.main exec --json-output "python3 -c 'import custom_unknown_pkg'"
```

### Avvio Sessione Shell Protetta
```bash
uv run python -m guardrail_cli.main session
```

### Visualizzazione Audit Trail
```bash
uv run python -m guardrail_cli.main audit-logs
```

### Esecuzione Test Suite
```bash
uv run pytest -v
```

---

## 📄 Licenza

Distribuito sotto licenza **Apache 2.0**. Consulta [`LICENSE`](LICENSE) per ulteriori dettagli.

---

## 👤 Autore

**Franca Roscilli**  
- **Email**: francaroscillidev@gmail.com  
- **GitHub**: [@francaroscillidev-gif](https://github.com/francaroscillidev-gif)

---

## 📬 Contact, Support & Commercial Inquiries

If you have questions, feedback, enterprise integration requests, or custom agent governance needs, feel free to reach out directly:

- **Lead Developer & Maintainer**: Franca Roscilli
- **Email**: [francaroscillidev@gmail.com](mailto:francaroscillidev@gmail.com)
- **GitHub**: [@francaroscillidev-gif](https://github.com/francaroscillidev-gif)
- **Bug Reports & Feature Requests**: [Open an issue on GitHub](https://github.com/francaroscillidev-gif/smart-shell-guardrail/issues)
