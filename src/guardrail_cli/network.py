import os
import re
import socket
from typing import List, Optional
from pydantic import BaseModel, Field

class NetworkPolicyResult(BaseModel):
    allowed: bool
    is_external: bool
    resolved_host: Optional[str] = None
    resolved_ip: Optional[str] = None
    reason: Optional[str] = None

class NetworkEgressGuard:
    """Monitora ed esamina chiamate di rete in comandi shell (curl, wget, ssh, nc, scp)."""

    LOCAL_NETWORKS = [
        "127.", "0.0.0.0", "localhost", "::1", "10.", "192.168.", "172.16.", "172.17.",
        "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
        "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31."
    ]

    NETWORK_COMMANDS_REGEX = r"\b(curl|wget|nc|ncat|netcat|ssh|scp|telnet|ftp|rsync)\b"
    URL_HOST_REGEX = r"(?:https?|ftp)://([^/\s:'\"]+)"

    def __init__(self, block_external_egress: bool = False, allowed_domains: Optional[List[str]] = None):
        self.block_external_egress = block_external_egress
        self.allowed_domains = allowed_domains or [
            "github.com", "api.github.com", "pypi.org", "files.pythonhosted.org",
            "registry.npmjs.org", "crates.io"
        ]

    def check(self, command: str) -> NetworkPolicyResult:
        if not re.search(self.NETWORK_COMMANDS_REGEX, command, re.IGNORECASE):
            return NetworkPolicyResult(allowed=True, is_external=False)

        # Cerca host/URL nel comando
        host = None
        url_match = re.search(self.URL_HOST_REGEX, command, re.IGNORECASE)
        if url_match:
            host = url_match.group(1)
        else:
            # Match di fallback per host bare (es. ssh user@host o curl host:port)
            bare_match = re.search(r"\b(?:curl|wget|ssh|nc)\s+(?:-[a-zA-Z0-9]+\s+)*([a-zA-Z0-9\.\-]+)", command)
            if bare_match:
                cand = bare_match.group(1)
                if not cand.startswith("-") and "." in cand:
                    host = cand

        if not host:
            return NetworkPolicyResult(allowed=True, is_external=False)

        # Risoluzione IP o classificazione locale
        is_local = any(host.startswith(prefix) or host == prefix for prefix in self.LOCAL_NETWORKS)

        if is_local:
            return NetworkPolicyResult(allowed=True, is_external=False, resolved_host=host)

        # Host esterno
        is_whitelisted = any(host == d or host.endswith("." + d) for d in self.allowed_domains)

        if self.block_external_egress and not is_whitelisted:
            return NetworkPolicyResult(
                allowed=False,
                is_external=True,
                resolved_host=host,
                reason=f"Connessione in uscita verso `{host}` bloccata da Network Egress Policy (dominio non in whitelist)."
            )

        return NetworkPolicyResult(
            allowed=True,
            is_external=True,
            resolved_host=host,
            reason=f"Target esterno autorizzato: `{host}`"
        )
