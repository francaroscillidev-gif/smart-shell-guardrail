import re
from typing import List, Optional
from pydantic import BaseModel, Field
from .models import RiskLevel

class ASTCommandNode(BaseModel):
    raw_segment: str
    command_name: str
    arguments: List[str] = Field(default_factory=list)
    has_pipe: bool = False
    has_redirection: bool = False
    redirection_targets: List[str] = Field(default_factory=list)

class ASTBashParser:
    """Scompone pipeline, concatenazioni logiche (&&, ||, ;) e subshell
    per analizzare ogni singolo sottocomando individualmente evitando bypass.
    """

    def parse_pipeline(self, command_line: str) -> List[ASTCommandNode]:
        cleaned = command_line.strip()
        # Divide per operatori logici &&, ||, ;
        segments = re.split(r"(?:&&|\|\||;)", cleaned)
        nodes = []

        for seg in segments:
            seg = seg.strip()
            if not seg:
                continue

            # Rileva pipe
            has_pipe = "|" in seg
            pipe_parts = seg.split("|") if has_pipe else [seg]

            for part in pipe_parts:
                part = part.strip()
                if not part:
                    continue

                # Rileva redirezioni (> o >>)
                has_redir = ">" in part
                redir_targets = []
                if has_redir:
                    targets = re.findall(r">{1,2}\s*([^\s;|&]+)", part)
                    redir_targets.extend(targets)

                tokens = part.split()
                cmd_name = tokens[0] if tokens else ""
                args = tokens[1:] if len(tokens) > 1 else []

                nodes.append(ASTCommandNode(
                    raw_segment=part,
                    command_name=cmd_name,
                    arguments=args,
                    has_pipe=has_pipe,
                    has_redirection=has_redir,
                    redirection_targets=redir_targets
                ))

        return nodes
