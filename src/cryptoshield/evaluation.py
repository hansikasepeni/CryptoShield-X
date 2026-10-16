import json
from pathlib import Path
def _records(payload): return payload.get("findings",[]) if isinstance(payload,dict) else payload
def _key(x): return (str(x.get("file","")).replace("\\\\","/").lstrip("./"),int(x.get("line",-1)),str(x.get("rule_id","")))
def evaluate_files(predictions_path,ground_truth_path):
    pp=json.loads(Path(predictions_path).read_text(encoding="utf-8")); tt=json.loads(Path(ground_truth_path).read_text(encoding="utf-8"))
    pred={_key(x) for x in _records(pp)}
    truth={_key(x) for x in _records(tt) if x.get("label","positive")=="positive"}
    tp=len(pred&truth); fp=len(pred-truth); fn=len(truth-pred); precision=tp/(tp+fp) if tp+fp else 0.0; recall=tp/(tp+fn) if tp+fn else 0.0
    return {"evaluation_scope":"provided_labeled_data_only","true_positives":tp,"false_positives":fp,"false_negatives":fn,
      "precision":round(precision,6),"recall":round(recall,6),"f1":round(2*precision*recall/(precision+recall),6) if precision+recall else 0.0,
      "matching_contract":"normalized file path + line + rule_id","warning":"Only report as official if labels and matching protocol are organizer-authorized."}
