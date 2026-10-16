# CryptoShield X
**Qiskit Fall Fest 2026 — Phase 1 | PS-P2: Crypto Inventory & Migration Planner**

> Starter status: runnable baseline. No official organizer-dataset precision/recall or Platform A/B results are claimed.

## Problem
PS-P2 asks for a static scanner to find classical cryptographic usage in Python, Java and C source code, classify quantum-related risk, and suggest post-quantum migration options. The challenge kit says the organizer-provided sample repository contains planted usages and that ground truth is withheld until judging. Do not invent official metrics.

## Workflow
**Discover → Explain risk → Recommend migration → Verify by rescanning → Measure reproducibly.**

1. Scan `.py`, `.java`, `.c`, and `.h` files with transparent rule-based patterns.
2. Emit JSON evidence including file, line, rule, algorithm, operation, risk, confidence and recommendation.
3. Evaluate precision/recall only against authorized labeled data.
4. Measure repeated scan time and Python allocation peak locally.
5. Run the exact organizer-defined Platform A/B protocol when the official profiles/environment are available. A local laptop run is not an official platform result.

## Quick start (Python 3.10+)
```bash
python main.py scan samples/mini_repo --out results/findings.json
python main.py report results/findings.json --out results/risk_report.md
python main.py benchmark samples/mini_repo --out results/local_benchmark.json --runs 5
```
Core scanner uses only the Python standard library. Install tests with `python -m pip install pytest` if needed.

## Ground-truth format
```json
[
  {"file":"src/example.py","line":12,"rule_id":"PY_RSA_KEYGEN","label":"positive"}
]
```
The evaluator matches normalized relative path + line + rule ID. Change this only if organizers specify another protocol.

## Team of five
1. Scanner/language rules and tests.
2. Risk engine and false-positive analysis.
3. Migration advisor and operation-specific guidance.
4. Reporting/optional UI.
5. Evaluation, benchmarking and integration.

## Important limitations
- Regex is a baseline, not full AST/data-flow analysis; it can miss wrappers/aliases and produce false positives.
- Findings are triage signals, not proof of vulnerability or security.
- ML-KEM is for key establishment; ML-DSA is for signatures. Neither is a universal drop-in replacement.
- No organizer ground truth is included here; no official precision/recall results are reported.
- Fill `docs/platform_profiles.template.json` only from official Platform A/B specifications; do not guess missing fields.

## Phase-1 checklist
- [ ] Integrate official organizer Python/Java/C sample repo as permitted.
- [ ] Refine rules and add test fixtures.
- [ ] Preserve raw scan output and generate report.
- [ ] Evaluate precision/recall against authorized ground truth when available.
- [ ] Run official Platform A/B benchmarks with environment and measurement method recorded.
- [ ] Write measured results, migration rationale, error analysis and limitations.
- [ ] Verify exact repository structure/submission instructions from organizers.
