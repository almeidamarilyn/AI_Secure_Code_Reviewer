import json, subprocess, shlex

DEFAULT_CONFIG = "p/owasp-top-ten"

def run_semgrep(output_path="semgrep.json", target=".", excludes=None):
    excludes = excludes or [".venv","node_modules","dist","build",".git"]
    exclude_flags = " ".join(f"--exclude {shlex.quote(e)}" for e in excludes)
    if isinstance(target, list) and target:
        files = " ".join(shlex.quote(f) for f in target)
        cmd = f"semgrep --config {DEFAULT_CONFIG} --json --timeout 180 --max-target-bytes 2000000 {exclude_flags} {files}"
    else:
        cmd = f"semgrep --config {DEFAULT_CONFIG} --json --timeout 180 --max-target-bytes 2000000 {exclude_flags} {shlex.quote(target)}"
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    out = p.stdout.strip() or "{}"
    with open(output_path,"w") as w:
        w.write(out)
    return output_path

def normalize_semgrep(data):
    results = []
    for m in data.get("results", []):
        results.append({
            "tool": "semgrep",
            "rule_id": m.get("check_id"),
            "message": m.get("extra",{}).get("message",""),
            "severity": (m.get("extra",{}).get("severity","LOW") or "LOW").upper(),
            "file": m.get("path"),
            "start_line": m.get("start",{}).get("line"),
            "end_line": m.get("end",{}).get("line"),
            "cwe": (m.get("extra",{}).get("metadata",{}).get("cwe","") or ""),
            "code": m.get("extra",{}).get("lines","")
        })
    return results
