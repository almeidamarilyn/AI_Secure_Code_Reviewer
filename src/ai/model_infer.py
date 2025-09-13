from typing import Dict, Optional
import os

# Optional: enable HF model by setting USE_HF=1
USE_HF = os.getenv("USE_HF","0") == "1"

LABELS = ["FP","LOW","MED","HIGH"]

def _heuristic_label(text: str, rule_id: str, message: str) -> str:
    t = f"{rule_id} {message} {text}".lower()
    high_markers = ["hardcoded password","secret","sql injection","command injection","eval(","pickle.loads(","md5(","sha1(","xxe","s3 public","0.0.0.0/0","privileged","cap_sys_admin"]
    med_markers = ["xss","open redirect","csrf","insecure random","yaml.load","path traversal","insecure deserialization"]
    if any(k in t for k in high_markers):
        return "HIGH"
    if any(k in t for k in med_markers):
        return "MED"
    return "LOW"

if USE_HF:
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    _tok = None
    _mdl = None
    _model_name = "microsoft/codebert-base"  # encoder; used here via pooling+linear head attempt
    # For simplicity, we keep heuristic default; HF path is placeholder for later finetune.

def classify_finding(code_snippet:str, rule_id:str, message:str) -> str:
    # Start with robust heuristic until you fine-tune a classifier.
    return _heuristic_label(code_snippet or "", rule_id or "", message or "")

def explain_and_fix(snippet:str, language:str="") -> Dict[str,str]:
    # Lightweight offline explanation; customize later or plug a small HF model.
    why = "Potential insecure pattern detected based on rules and heuristics."
    patch = "/* Replace insecure call with parameterized/validated alternative. */"
    return {"cwe":"TBD","risk":"TBD","explanation":why,"patch":patch}
