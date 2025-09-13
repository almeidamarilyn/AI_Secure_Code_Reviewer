# AI-Powered Secure Code Reviewer (Starter)

**Goal:** Run free static analyzers (Semgrep, Bandit, Gitleaks) and apply an **AI triage layer** (local CPU) to rank findings, reduce noise, and suggest fixes. Use it locally via **pre-commit** and in CI via **GitHub Actions**.

## Quickstart

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Optional: install CLIs if preferred
# macOS: brew install semgrep gitleaks
# Linux: use the package manager or pip equivalents

# Run once
python src/cli.py

# Install pre-commit hook
pip install pre-commit
pre-commit install
```

## What it does
1. Runs **Semgrep**, **Bandit**, **Gitleaks** and collects findings (JSON).
2. Normalizes findings into a common schema.
3. Runs **AI triage** to re-label noise / rank severity (CPU-friendly; falls back to heuristics if model not available).
4. Produces `secure_review.md` and a non-zero exit code if HIGH issues found.

## CI (GitHub Actions)
Push this repo to GitHub; the included workflow blocks PRs with HIGH issues.

## Notes
- The AI layer ships with a **safe fallback** (heuristics) so it always works. To enable HF models, ensure internet access on first run (models cached locally).
- You can add custom Semgrep rules in `rules/`.
