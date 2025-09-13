import json, sys, pathlib, argparse, subprocess
from rich import print
from src.analyzers.semgrep_runner import run_semgrep, normalize_semgrep
from src.analyzers.bandit_runner import run_bandit, normalize_bandit
from src.analyzers.gitleaks_runner import run_gitleaks, normalize_gitleaks
from src.ai.model_infer import classify_finding, explain_and_fix
from src.report import write_markdown

def _read_json(p):
    path = pathlib.Path(p)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text() or "{}")
    except Exception:
        return {}

def _git_changed_files(ref="origin/main...HEAD"):
    # returns a list of changed files in the diff vs. main (adjust branch as needed)
    try:
        out = subprocess.check_output(["git","diff","--name-only",ref], text=True).strip()
        return [f for f in out.splitlines() if f]
    except Exception:
        return []

def main():
    ap = argparse.ArgumentParser(description="AI-Powered Secure Code Review")
    ap.add_argument("--target", default=".", help="Path to scan (default: .)")
    ap.add_argument("--exclude", action="append", default=[], help="Dirs to exclude (repeatable)")
    ap.add_argument("--diff", action="store_true", help="Scan only changed files (git diff vs origin/main)")
    ap.add_argument("--staged", action="store_true", help="Scan only staged files (pre-commit)")
    args = ap.parse_args()

    excludes = args.exclude or [".venv","node_modules","dist","build",".git"]
    target = args.target

    # Resolve file list if diff/staged
    files = None
    if args.diff:
        files = _git_changed_files()
    if args.staged:
        try:
            out = subprocess.check_output(["git","diff","--name-only","--cached"], text=True).strip()
            files = [f for f in out.splitlines() if f]
        except Exception:
            files = []

    print("[bold]Running static analyzers...[/bold]")
    # Pass file allowlist to semgrep/bandit when available; otherwise default to target
    run_semgrep("semgrep.json", target if not files else files, excludes=excludes)
    run_bandit("bandit.json", target if not files else files, excludes=excludes)
    run_gitleaks("gitleaks.json", target)  # keep repo-wide for secrets

    print("[bold]Loading and normalizing findings...[/bold]")
    findings = []
    findings += normalize_semgrep(_read_json("semgrep.json"))
    findings += normalize_bandit(_read_json("bandit.json"))
    findings += normalize_gitleaks(_read_json("gitleaks.json"))

    # De-dupe identical (tool, file, line, rule) to cut noise
    seen, deduped = set(), []
    for f in findings:
        key = (f.get("tool"), f.get("file"), f.get("start_line"), f.get("rule_id"))
        if key in seen: 
            continue
        seen.add(key); deduped.append(f)
    findings = deduped

    print(f"[cyan]Findings (deduped): {len(findings)}[/cyan]")

    # AI triage + lightweight explanation
    for f in findings:
        f["ai_severity"] = classify_finding(f.get("code",""), f.get("rule_id",""), f.get("message",""))
        exp = explain_and_fix(f.get("code",""), language="")
        f["ai_explanation"] = exp.get("explanation")
        f["ai_patch"] = exp.get("patch")

    write_markdown(findings, "secure_review.md")
    highs = [f for f in findings if f.get("ai_severity") == "HIGH"]
    print(f"[green]Report written to secure_review.md[/green]")
    print(f"[bold yellow]AI-triaged findings: {len(findings)} | HIGH: {len(highs)}[/bold yellow]")
    with open("findings.json","w") as w:
    json.dump(findings, w, indent=2)
    sys.exit(1 if highs else 0)
    sev_rank = {"HIGH":3,"MED":2,"LOW":1,"FP":0}
    findings.sort(key=lambda f: sev_rank.get(f.get("ai_severity","LOW"),1), reverse=True)

    # Keep at most 10 per file, 300 overall (tune to taste)
    per_file_cap = 10
    overall_cap = 300
    by_file = {}
    trimmed = []
    for f in findings:
        file = f.get("file","unknown")
        by_file.setdefault(file, 0)
        if by_file[file] >= per_file_cap:
            continue
        trimmed.append(f)
        by_file[file] += 1
        if len(trimmed) >= overall_cap:
            break
    findings = trimmed

    

if __name__ == "__main__":
    main()
