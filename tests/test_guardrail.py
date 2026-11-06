import pytest
from guardrail_cli.config import GuardrailConfig
from guardrail_cli.guardrail import SecurityGuardrail
from guardrail_cli.models import RiskLevel
from guardrail_cli.diagnostics import SystemDiagnosticEngine

@pytest.fixture
def guardrail():
    cfg = GuardrailConfig()
    return SecurityGuardrail(cfg)

@pytest.fixture
def diagnostic_engine():
    return SystemDiagnosticEngine()

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
    assert res.allowed  # In non-strict mode warning is allowed
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

def test_diagnostics_command_not_found(diagnostic_engine):
    diag = diagnostic_engine.analyze(
        command="invalid_binary_foo",
        exit_code=127,
        stdout="",
        stderr="zsh: command not found: invalid_binary_foo\n"
    )
    assert diag is not None
    assert diag.error_category == "command_not_found"
    assert diag.details.get("binary") == "invalid_binary_foo"
