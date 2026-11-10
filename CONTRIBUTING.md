# Contributing to Ariadns

Thank you for your interest in contributing to Ariadns! We welcome issues, documentation improvements, and pull requests.

## Development Setup

1. **Clone & Virtual Environment**:
   ```bash
   git clone https://github.com/jontykuan/Ariadns.git
   cd Ariadns
   python -m venv .venv
   # Windows PowerShell:
   .venv\Scripts\activate
   # Linux / macOS:
   source .venv/bin/activate
   pip install -e .
   pip install pytest httpx pillow
   ```

2. **Environment Doctor**:
   ```bash
   ariadns doctor
   ```

3. **Running Tests**:
   ```bash
   pytest tests/ -v
   ```

## Contribution Principles

- **Local-First & Keyless Parity**: Core features must remain 100% operational without requiring paid third-party API keys.
- **Tri-Interface Parity**: New probing capabilities must be exposed symmetrically across CLI (`cli.py`), FastMCP (`mcp_server.py`), and Local Web UI (`web_ui.py`).
- **Test-Driven Development (TDD)**: Every bugfix or new feature must include a corresponding automated pytest test.
- **OPSEC Safeguards**: Any active probe sending packets beyond standard passive DNS must gate behind explicit risk acknowledgement.

## Submitting a Pull Request

1. Create a feature branch: `git checkout -b feature/my-enhancement`.
2. Ensure all tests pass: `pytest tests/ -v`.
3. Submit a PR against `master` describing the rationale and proof of work.
