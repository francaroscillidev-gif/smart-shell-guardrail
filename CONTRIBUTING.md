# Contributing to Smart CLI / Shell Agent Guardrail

First off, thank you for considering contributing to **Smart Shell Guardrail**! 🎉

We welcome contributions of all kinds: bug reports, new security rules, platform compatibility patches (macOS, Linux), diagnostic fixes, documentation improvements, and architectural suggestions.

---

## 🛠️ Development Setup

1. **Fork and Clone the Repository**:
   ```bash
   git clone https://github.com/francaroscillidev-gif/smart-shell-guardrail.git
   cd smart-shell-guardrail
   ```

2. **Install Dependencies using `uv`**:
   We recommend [uv](https://docs.astral.sh/uv/) for lightning-fast, reproducible dependency management:
   ```bash
   uv sync
   ```

3. **Run the Test Suite**:
   Ensure all existing tests pass before making any changes:
   ```bash
   uv run pytest -v
   ```

---

## 🧪 Adding New Guardrail Rules

If you are adding a new security pattern or secret scanner:
1. Open [`src/guardrail_cli/guardrail.py`](src/guardrail_cli/guardrail.py).
2. Add your pattern to `BLOCKED_PATTERNS`, `WARNING_PATTERNS`, or `SECRET_PATTERNS`.
3. Add a corresponding unit test in [`tests/test_guardrail.py`](tests/test_guardrail.py).
4. Run `uv run pytest` to confirm that:
   - Malicious commands are properly identified.
   - Legitimate developer commands do not trigger false positives.

---

## 🔧 Adding New System Diagnostics

If you want to teach the Copilot how to automatically diagnose a new shell error (e.g., Docker daemon not running, out of inodes, etc.):
1. Open [`src/guardrail_cli/diagnostics.py`](src/guardrail_cli/diagnostics.py).
2. Add a new detection branch in `analyze()`.
3. Provide actionable suggestions and, if possible, a safe `quick_fix_command`.
4. Set `is_auto_fixable=True` ONLY if the fix is idempotent and does not cause destructive side effects.

---

## 📐 Pull Request Guidelines

1. **Branch Naming**: Use descriptive branch names like `feat/docker-diagnostics` or `fix/entropy-threshold`.
2. **Commit Messages**: Use semantic, concise commit messages (e.g., `feat: add docker daemon diagnostics`, `fix: handle edge case in base64 pipe`).
3. **Tests**: Every new feature or bug fix must include automated test coverage in `tests/`.
4. **Code Style**: Follow PEP 8 guidelines and type hints (Pydantic models).

---

## 📬 Need Help?

Reach out directly to the maintainer:
- **Lead Maintainer**: Franca Roscilli ([francaroscillidev@gmail.com](mailto:francaroscillidev@gmail.com))
- **GitHub Issues**: [Open an Issue](https://github.com/francaroscillidev-gif/smart-shell-guardrail/issues)
