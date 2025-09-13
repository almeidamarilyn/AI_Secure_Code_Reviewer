from datetime import datetime
from typing import List, Dict

def write_markdown(findings: List[Dict], path: str):
    lines = []
    lines.append(f"# Secure Code Review Report\n")
    lines.append(f"Generated: {datetime.utcnow().isoformat()}Z\n")
    totals = {"HIGH":0, "MED":0, "LOW":0, "FP":0}
    for f in findings:
        sev = f.get("ai_severity") or f.get("severity","LOW")
        totals[sev] = totals.get(sev,0)+1
    lines.append(f"**Totals** — HIGH: {totals.get('HIGH',0)}, MED: {totals.get('MED',0)}, LOW: {totals.get('LOW',0)}, FP: {totals.get('FP',0)}\n")
    lines.append("---\n")
    for f in findings:
        lines.append(f"## [{f.get('ai_severity','?')}] {f.get('tool')} • {f.get('rule_id')}\n")
        lines.append(f"**Message:** {f.get('message','')}\n")
        if f.get('file'):
            lines.append(f"**File:** `{f['file']}`:{f.get('start_line','?')}\n")
        if f.get('cwe'):
            lines.append(f"**CWE:** {f['cwe']}\n")
        if f.get('code'):
            snippet = f['code']
            if len(snippet) > 800:
                snippet = snippet[:800] + "..."
            lines.append("**Snippet:**\n")
            lines.append("```\n"+snippet+"\n```\n")
        if f.get('ai_explanation'):
            lines.append(f"**AI Explanation:** {f['ai_explanation']}\n")
        if f.get('ai_patch'):
            lines.append("**Proposed Patch:**\n")
            lines.append("```diff\n"+f['ai_patch']+"\n```\n")
        lines.append("---\n")
    with open(path,"w") as w:
        w.write("\n".join(lines))
