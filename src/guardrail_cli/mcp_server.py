import asyncio
import json
import sys
from typing import Optional
from .models import RiskLevel, SecurityCheckResult
from .guardrail import SecurityGuardrail
from .diagnostics import SystemDiagnosticEngine
from .executor import Executor
from .config import GuardrailConfig

class GuardrailMCPServer:
    """Implementazione server MCP (Model Context Protocol) via JSON-RPC stdio.
    Consente a qualsiasi client MCP (Claude Desktop, Cursor, Antigravity, ecc.)
    di eseguire comandi protetti con auto-healing integrato.
    """

    def __init__(self, config: Optional[GuardrailConfig] = None):
        self.config = config or GuardrailConfig()
        self.guardrail = SecurityGuardrail(self.config)
        self.diagnostics = SystemDiagnosticEngine()
        self.executor = Executor(self.guardrail, self.diagnostics, self.config)

    async def handle_request(self, request: dict) -> dict:
        method = request.get("method")
        msg_id = request.get("id")

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "smart-shell-guardrail-mcp", "version": "0.2.0"}
                }
            }

        elif method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "tools": [
                        {
                            "name": "safe_run_command",
                            "description": "Esegue un comando shell protetto da policy di sicurezza, segreti, loop infiniti e con autodiagnostica.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "command": {"type": "string", "description": "Il comando bash/zsh da eseguire."},
                                    "auto_fix": {"type": "boolean", "description": "Applica automaticamente il quick-fix se disponibile.", "default": False},
                                    "sandbox": {"type": "boolean", "description": "Abilita sandboxing OS-level restrittivo.", "default": False}
                                },
                                "required": ["command"]
                            }
                        },
                        {
                            "name": "audit_logs",
                            "description": "Recupera gli ultimi log di audit di sicurezza sui comandi eseguiti.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "limit": {"type": "integer", "description": "Numero massimo di log da restituire.", "default": 10}
                                }
                            }
                        }
                    ]
                }
            }

        elif method == "tools/call":
            params = request.get("params", {})
            name = params.get("name")
            args = params.get("arguments", {})

            if name == "safe_run_command":
                cmd = args.get("command", "")
                auto_fix = args.get("auto_fix", False)
                use_sb = args.get("sandbox", False)

                check = self.guardrail.evaluate(cmd)
                if not check.allowed:
                    return {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "result": {
                            "content": [{
                                "type": "text",
                                "text": json.dumps({
                                    "status": "blocked",
                                    "risk_level": check.risk_level.value,
                                    "reasons": check.reasons,
                                    "detected_secrets": check.detected_secrets,
                                    "suggested_safe_command": check.suggested_safe_command
                                }, indent=2)
                            }],
                            "isError": True
                        }
                    }

                res = self.executor.run(cmd, use_sandbox=use_sb)
                
                # Auto fix loop
                if res.exit_code != 0 and auto_fix and res.diagnostics and res.diagnostics.quick_fix_command:
                    fix_cmd = res.diagnostics.quick_fix_command
                    fix_chk = self.guardrail.evaluate(fix_cmd)
                    if fix_chk.allowed:
                        fix_res = self.executor.run(fix_cmd)
                        if fix_res.exit_code == 0:
                            res = self.executor.run(cmd, use_sandbox=use_sb)

                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [{
                            "type": "text",
                            "text": res.model_dump_json(indent=2)
                        }],
                        "isError": res.exit_code != 0
                    }
                }

        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Method '{method}' not found"}
        }

    async def run_stdio(self):
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin)
        writer = sys.stdout

        while True:
            line = await reader.readline()
            if not line:
                break
            try:
                raw_str = line.decode().strip()
                if not raw_str:
                    continue
                req = json.loads(raw_str)
                resp = await self.handle_request(req)
                writer.write(json.dumps(resp) + "\n")
                writer.flush()
            except Exception as e:
                err_resp = {"jsonrpc": "2.0", "error": {"code": -32700, "message": str(e)}}
                writer.write(json.dumps(err_resp) + "\n")
                writer.flush()
