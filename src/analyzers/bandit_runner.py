import subprocess, json, shlex, os

def run_bandit(output_path="bandit.json", target=".", excludes=None):
    excludes = excludes or [".venv","node_modules","dist","build",".git"]
    exclude_list = ",".join(excludes).replace(" ","")
    if isinstance(target, list) and target:
        # bandit can accept multiple paths; filter to .py files
        py = [f for f in target if f.endswith(".py")]
        if not py:
            open(output_path,"w").write(json.dumps({"results":[]}))
            return output_path
        paths = " ".join(shlex.quote(p) for p in py)
        cmd = f"bandit -r {paths} -x {exclude_list} -f json -o {output_path}"
    else:
        cmd = f"bandit -r {shlex.quote(target)} -x {exclude_list} -f json -o {output_path}"
    subprocess.run(cmd, shell=True)
    return output_path

def normalize_bandit(data):
    results = []
    for m in data.get("results", []):
        results.append({
            "tool": "bandit",
            "rule_id": m.get("test_id"),
            "message": m.get("issue_text",""),
            "severity": (m.get("issue_severity","LOW") or "LOW").upper(),
            "file": m.get("filename"),
            "start_line": m.get("line_number"),
            "end_line": m.get("line_number"),
            "cwe": "",
            "code": m.get("code","")
        })
    return results
