## Descrizione delle Modifiche

Fornisci una sintesi chiara di cosa introduce questa Pull Request:
- [ ] Nuova euristica di diagnostica o auto-fix
- [ ] Nuovo pattern di sicurezza o anti-tampering
- [ ] Miglioramento compatibilità OS (macOS/Linux)
- [ ] Bug fix / Correzione falso positivo
- [ ] Documentazione

## Come è Stato Testato?

Descrivi le procedure di test eseguite:
- [ ] `uv run pytest -v` (tutti i test passano)
- [ ] Test manuale eseguito su ambiente locale (macOS / Linux)

## Checklist di Conformità
- [ ] Il codice segue i pattern del progetto e include type hints (Pydantic models)
- [ ] Sono stati aggiunti test unitari in `tests/test_guardrail.py` per le nuove casistiche
- [ ] La documentazione o il README sono stati aggiornati ove necessario
- [ ] Nessun segreto o dato sensibile è stato incluso nei commit
