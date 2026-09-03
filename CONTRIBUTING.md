# Contributing to Cerberus

Thank you for your interest in Cerberus — a runtime behavioral firewall for MCP-based AI agents.

## Development Setup

1. Install `uv`:
   ```bash
   pip install uv
   ```
2. Set up virtual environment and install dependencies:
   ```bash
   uv venv
   uv pip install -e ".[dev]"
   ```
3. Run code quality checks:
   ```bash
   ruff check src tests
   mypy src
   pytest tests/unit
   ```

## Architecture & Code Standards
- All tool calls intercepted must pass through `cerberus.proxy.redactor` before persistent logging.
- Rego policies must reside in `policies/base` and have corresponding tests in `policies/tests`.
- Continuous features fed to `IsolationForest` must be z-score scaled per agent. Categorical transitions are handled strictly by the Markov scorer.
- Pull requests must pass CI linting, type checks, unit tests, and Rego tests.
