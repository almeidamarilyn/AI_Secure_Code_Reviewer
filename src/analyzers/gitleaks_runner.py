import json, subprocess

def run_gitleaks(output_path="gitleaks.json", target="."):
    cmd = f"gitleaks detect --source {target} --report-format json --report-path {output_path}"
    subprocess.run(cmd, shell=True)
    return output_path

def normalize_gitleaks(data):
    results = []
    for m in data if isinstance(data, list) else data.get("findings", []):
        results.append({
            "tool": "gitleaks",
            "rule_id": m.get("rule","SECRET"),
            "message": m.get("description","Potential secret found"),
            "severity": "HIGH",
            "file": m.get("file",""),
            "start_line": m.get("startLine"),
            "end_line": m.get("endLine"),
            "cwe": "CWE-798",  # hard-coded creds
            "code": m.get("match","")
        })
    return results
