#!/usr/bin/env python3
import argparse, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent / "src"))
from cryptoshield.scanner import scan_path
from cryptoshield.reporting import write_markdown_report
from cryptoshield.benchmark import run_benchmark
from cryptoshield.evaluation import evaluate_files

def main():
    parser = argparse.ArgumentParser(prog="cryptoshield")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("scan"); p.add_argument("path"); p.add_argument("--out", default="results/findings.json")
    p = sub.add_parser("report"); p.add_argument("findings"); p.add_argument("--out", default="results/risk_report.md")
    p = sub.add_parser("benchmark"); p.add_argument("path"); p.add_argument("--out", default="results/local_benchmark.json"); p.add_argument("--runs", type=int, default=5)
    p = sub.add_parser("evaluate"); p.add_argument("--predictions", required=True); p.add_argument("--ground-truth", required=True)
    a = parser.parse_args()
    if a.command == "scan":
        f, m = scan_path(a.path); out = Path(a.out); out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps({"metadata":m,"findings":f}, indent=2), encoding="utf-8")
        print(f"Scanned {m['files_scanned']} files; {len(f)} findings -> {out}")
    elif a.command == "report":
        write_markdown_report(json.loads(Path(a.findings).read_text(encoding="utf-8")), a.out); print("Report ->", a.out)
    elif a.command == "benchmark":
        result = run_benchmark(a.path, a.runs); out = Path(a.out); out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2), encoding="utf-8"); print(json.dumps(result, indent=2))
    else:
        print(json.dumps(evaluate_files(a.predictions, a.ground_truth), indent=2))
if __name__ == "__main__": main()
