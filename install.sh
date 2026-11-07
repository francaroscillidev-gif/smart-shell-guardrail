#!/usr/bin/env bash
# ==============================================================================
# Smart CLI / Shell Agent "Guardrail" - Universal One-Line Installer
# Author: Franca Roscilli (francaroscillidev@gmail.com)
# GitHub: https://github.com/francaroscillidev-gif/smart-shell-guardrail
# ==============================================================================

set -e

REPO_URL="https://github.com/francaroscillidev-gif/smart-shell-guardrail.git"
INSTALL_DIR="$HOME/.smart-shell-guardrail"
BIN_DIR="$HOME/.local/bin"

BOLD='\033[1m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${CYAN}${BOLD}"
echo "  ╔═══════════════════════════════════════════════════════════╗"
echo "  ║      Smart CLI / Shell Agent Guardrail Installer          ║"
echo "  ║      AI-Powered Terminal Copilot & Sandbox Architecture    ║"
echo "  ╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# 1. Verifica dipendenze di base: git, python3
if ! command -v git &> /dev/null; then
    echo -e "${RED}[ERROR] 'git' non è installato. Installalo e riprova.${NC}"
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[ERROR] 'python3' (>= 3.12 consigliato) non è installato.${NC}"
    exit 1
fi

# 2. Verifica se 'uv' è disponibile, altrimenti installalo velocemente
if ! command -v uv &> /dev/null; then
    echo -e "${YELLOW}[!] 'uv' package manager non rilevato. Installazione in corso...${NC}"
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$PATH"
fi

# 3. Clone o aggiornamento repository
if [ -d "$INSTALL_DIR" ]; then
    echo -e "${CYAN}[*] Repository esistente trovato in $INSTALL_DIR. Aggiornamento in corso...${NC}"
    cd "$INSTALL_DIR"
    git pull --quiet origin main
else
    echo -e "${CYAN}[*] Clonazione repository in $INSTALL_DIR...${NC}"
    git clone --quiet "$REPO_URL" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

# 4. Creazione virtualenv e installazione dipendenze tramite uv
echo -e "${CYAN}[*] Installazione ambiente virtuale e dipendenze ad alte prestazioni con uv...${NC}"
uv sync --quiet

# 5. Collegamento simbolico del comando globale 'guardrail'
mkdir -p "$BIN_DIR"
WRAPPER_SCRIPT="$BIN_DIR/guardrail"

cat << 'EOF' > "$WRAPPER_SCRIPT"
#!/usr/bin/env bash
INSTALL_DIR="$HOME/.smart-shell-guardrail"
exec uv run --directory "$INSTALL_DIR" python -m guardrail_cli.main "$@"
EOF

chmod +x "$WRAPPER_SCRIPT"

# 6. Verifica PATH
echo -e "${GREEN}${BOLD}✔ Smart Shell Guardrail installato con successo!${NC}"
echo -e "Eseguibile creato in: ${CYAN}$WRAPPER_SCRIPT${NC}"

if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    echo ""
    echo -e "${YELLOW}[AVVISO] La directory $BIN_DIR non sembra presente nel tuo PATH.${NC}"
    echo -e "Aggiungila al tuo file di configurazione shell (~/.zshrc o ~/.bashrc):"
    echo -e "  ${BOLD}export PATH=\"\$HOME/.local/bin:\$PATH\"${NC}"
fi

echo ""
echo -e "${GREEN}Prova subito uno dei seguenti comandi:${NC}"
echo -e "  guardrail exec \"ls -la\""
echo -e "  guardrail session"
echo -e "  guardrail mcp --generate-config claude"
echo ""
