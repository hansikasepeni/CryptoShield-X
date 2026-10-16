from collections import Counter
from pathlib import Path
def write_markdown_report(payload, out_path):
    fs=payload.get("findings",[]); meta=payload.get("metadata",{}); counts=Counter(x.get("risk","unknown") for x in fs)
    lines=["# CryptoShield X — Static Crypto Inventory Report","","**Triage only:** findings require source and protocol review; this is not proof of vulnerability.","",
      "## Scan summary","",f"- Files scanned: {meta.get('files_scanned','unknown')}",f"- Scan duration: {meta.get('elapsed_seconds','unknown')} seconds",
      f"- Findings: {len(fs)}",f"- Rules: {meta.get('rule_count','unknown')}","","## Risk distribution","","| Risk | Count |","|---|---:|"]
    lines += [f"| {k} | {v} |" for k,v in sorted(counts.items())]
    lines += ["","## Findings","","| File | Line | Rule | Algorithm | Operation | Risk | Evidence |","|---|---:|---|---|---|---|---|"]
    for f in fs:
        ev=str(f.get("matched_evidence","")).replace("|","\\\\|").replace("\\n"," ")
        lines.append(f"| `{f.get('file','')}` | {f.get('line','')} | `{f.get('rule_id','')}` | {f.get('algorithm','')} | {f.get('operation','')} | {f.get('risk','')} | `{ev}` |")
    lines += ["","## Migration triage notes",""]
    lines += [f"- **{f['file']}:{f['line']} — {f['rule_id']}**: {f['recommendation']}" for f in fs]
    lines += ["","## Limitations","","- Line-based patterns can miss aliases, wrappers and split expressions.",
      "- Risk labels are triage categories, not a formal risk score.","- Recommendations require protocol/library/test validation.",
      "- No precision/recall is reported without authorized ground truth.",""]
    Path(out_path).parent.mkdir(parents=True,exist_ok=True)
    Path(out_path).write_text("\n".join(lines),encoding="utf-8")
