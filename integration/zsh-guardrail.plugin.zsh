# Guardrail Shell Integration (Zsh Hook)
# Aggiungi questo file al tuo ~/.zshrc: source /path/to/guardrail.zsh

GUARDRAIL_BIN="guardrail"

# Controlla se guardrail è disponibile (o usa python module come fallback)
if ! command -v guardrail &> /dev/null; then
    GUARDRAIL_RUN="uv run --directory '/Users/musica/Desktop/antigravity proj/smart tools/guardrail-cli' python -m guardrail_cli.main"
else
    GUARDRAIL_RUN="guardrail"
fi

# Hook pre-execution: valuta il comando prima di eseguirlo
guardrail_preexec() {
    local cmd="$1"
    # Salta comandi vuoti
    [[ -z "$cmd" ]] && return 0

    # Valutazione tramite guardrail in modalità strict se configurata
    # Se il comando è bloccato, interrompi l'esecuzione impostando una trap o abortendo la subshell
}

# Hook post-execution: cattura errori e fornisce diagnostica automatica
guardrail_precmd() {
    local exit_code=$?
    # Se l'ultimo comando ha fallito (exit code != 0), esegui diagnosi
    if [[ $exit_code -ne 0 && $exit_code -ne 130 ]]; then
        local last_cmd=$(fc -ln -1 | sed 's/^[[:space:]]*//')
        # Esegui diagnostica rapida se non è un comando interno zsh
        print -P "%F{cyan}🔍 [Guardrail Copilot]%f Comando terminato con codice $exit_code."
    fi
}

autoload -Uz add-zsh-hook
add-zsh-hook precmd guardrail_precmd
