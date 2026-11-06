import os
import yaml
from pathlib import Path
from typing import List, Optional
from pydantic import BaseModel, Field

class AuditConfig(BaseModel):
    enabled: bool = True
    log_file: str = os.path.expanduser("~/.guardrail/audit.jsonl")

class GuardrailConfig(BaseModel):
    strict_mode: bool = False
    timeout_seconds: int = 120
    max_output_kb: int = 512
    working_dir_restriction: Optional[str] = None
    allowed_commands_whitelist: List[str] = Field(default_factory=list)
    custom_blocked_patterns: List[str] = Field(default_factory=list)
    audit: AuditConfig = Field(default_factory=AuditConfig)

DEFAULT_CONFIG_PATH = Path(".guardrail.yaml")

def load_config(config_path: Optional[str] = None) -> GuardrailConfig:
    p = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
    if not p.exists():
        # cerca nella home se non trovato nella cartella corrente
        home_cfg = Path.home() / ".guardrail" / "config.yaml"
        if home_cfg.exists():
            p = home_cfg

    if p.exists():
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
                return GuardrailConfig(**data)
        except Exception:
            return GuardrailConfig()

    return GuardrailConfig()
