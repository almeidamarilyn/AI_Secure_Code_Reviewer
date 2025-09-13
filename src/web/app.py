from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from pathlib import Path
import json

# Reuse your normalizers
from src.analyzers.semgrep_runner import normalize_semgrep
from src.analyzers.bandit_runner import normalize_bandit
from src.analyzers.gitleaks_runner import normalize_gitleaks
from src.ai.model_infer import classify_finding, explain_and_fix

app = FastAPI(title="Secure Code Review Dashboard")

BASE = Path(__file__).resolve().parent.parent.parent  # project root
TEMPLATES = BASE / "src" / "web" / "templates"
STATIC = BASE / "src" / "web" / "static"

app.mount("/static", StaticFiles(directory=STATIC), name="static")

def _read_json(p: Path):
    if not p.exists(): 
        return {}
    try:
        return json.loads(p.read_text() or "{}")
    except Exception:
        return {}

def load_findings():
    semgrep = _read_json(BASE / "semgrep.json")
    bandit = _read_json(BASE / "bandit.json")
    gitleaks = _read_json(BASE / "gitleaks.json")

    findings = []
    findings += normalize_semgrep(semgrep)
    findings += normalize_bandit(bandit)
    findings += normalize_gitleaks(gitleaks)

    # AI triage + explanation (lightweight)
    for f in findings:
        f["ai_severity"] = classify_finding(f.get("code",""), f.get("rule_id",""), f.get("message",""))
        exp = explain_and_fix(f.get("code",""), "")
        f["ai_explanation"] = exp.get("explanation")
        # keep patch out of table by default, but still available in JSON
        f["ai_patch"] = exp.get("patch")
    return findings

@app.get("/api/findings")
def api_findings():
    return JSONResponse(load_findings())

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    html = (TEMPLATES / "report.html").read_text()
    return HTMLResponse(html)
