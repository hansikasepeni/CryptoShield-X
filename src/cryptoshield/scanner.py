import re, time
from pathlib import Path
from .rules import RULES
EXT_LANG = {".py":"python",".java":"java",".c":"c",".h":"c"}

def scan_path(root):
    root = Path(root).resolve()
    if not root.exists(): raise FileNotFoundError(f"Input path does not exist: {root}")
    if root.is_file():
        candidates = [root] if root.suffix.lower() in EXT_LANG else []
        base = root.parent
    else:
        candidates = sorted(p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in EXT_LANG)
        base = root
    findings=[]; start=time.perf_counter()
    for path in candidates:
        lang=EXT_LANG[path.suffix.lower()]
        lines=path.read_text(encoding="utf-8", errors="replace").splitlines()
        rel=path.relative_to(base).as_posix()
        for number,line in enumerate(lines,1):
            for rule in RULES:
                if lang in rule["languages"] and re.search(rule["pattern"], line):
                    findings.append({"file":rel,"line":number,"language":lang,"rule_id":rule["id"],
                      "matched_evidence":line.strip()[:300],"algorithm":rule["algorithm"],"operation":rule["operation"],
                      "risk":rule["risk"],"confidence":rule["confidence"],"recommendation":rule["recommendation"],
                      "method":"line_regex_rule"})
    return findings, {"scanner":"CryptoShield X baseline","input_path":str(root),"files_scanned":len(candidates),
      "elapsed_seconds":round(time.perf_counter()-start,6),"rule_count":len(RULES),"supported_extensions":sorted(EXT_LANG)}
