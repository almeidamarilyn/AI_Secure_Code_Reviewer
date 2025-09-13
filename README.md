# 🔒 AI-Powered Secure Code Reviewer

An open-source **DevSecOps tool** that combines traditional static analysis (Semgrep, Bandit, Gitleaks) with an **AI triage layer** to make secure code reviews faster and less noisy.  

This project helps developers and security engineers automatically detect vulnerabilities, secrets, and insecure patterns — then ranks, explains, and suggests fixes with AI.

---

## 🧐 Why this project?

Software supply chain security has become one of the **biggest risks** for organizations. Traditional static analyzers are powerful, but they:

- Produce **lots of false positives**
- Don’t explain findings in developer-friendly language
- Lack **contextual severity ranking**

This project combines proven open-source analyzers with an **AI layer** that:
- Ranks findings (HIGH / MEDIUM / LOW)
- Explains why an issue matters
- Suggests practical fixes

The result → **developers fix issues earlier, security teams trust the results, and CI/CD pipelines stay fast**.

---

## ⚙️ Architecture

```text
                ┌─────────────┐
                │   Source    │
                │   Codebase  │
                └──────┬──────┘
                       │
        ┌──────────────┼──────────────┐
        │              │              │
   ┌────▼────┐    ┌────▼────┐    ┌────▼────┐
   │ Semgrep │    │ Bandit  │    │ Gitleaks│
   └────┬────┘    └────┬────┘    └────┬────┘
        │              │              │
        └─────── Findings (JSON) ─────┘
                       │
               ┌───────▼────────┐
               │ Normalization  │
               │  Common Schema │
               └───────┬────────┘
                       │
               ┌───────▼────────┐
               │ AI Triage Layer│
               │  Heuristics/LLM│
               └───────┬────────┘
                       │
              ┌────────▼─────────┐
              │ secure_review.md │
              │  (final report)  │
              └──────────────────┘

```
---

## ✨ Features

- 🧰 **Static Analysis Stack**:
  - **Semgrep** → language-aware pattern detection (e.g., OWASP Top 10)
  - **Bandit** → Python security checks
  - **Gitleaks** → Secret/key detection
- 🤖 **AI Triage Layer**:
  - Classifies findings as **HIGH / MED / LOW**
  - Reduces false positives and noise
  - Explains *why* an issue matters and suggests fixes
- 📄 **Unified Report**:
  - Generates a single `secure_review.md`
  - Highlights **AI-ranked HIGH issues**
  - Non-zero exit code if blocking issues are found (CI/CD friendly)
- ⚡ **Fast & Flexible**:
  - Run locally via CLI or Git pre-commit hook
  - Integrate into CI/CD (GitHub Actions included)

---

## 🚀 Quickstart

```bash
# 1. Setup virtual environment
python -m venv .venv && source .venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run a full scan
PYTHONPATH=. python src/cli.py --target src

# 4. Optional: Install analyzers via CLI
# macOS
brew install semgrep gitleaks
# Linux
apt install semgrep gitleaks  # or use pip equivalents
```
