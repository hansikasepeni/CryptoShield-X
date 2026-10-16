# CryptoShield X — Phase 1 Technical Report

**Problem:** PS-P2 — Crypto Inventory & Migration Planner  
**Event:** Qiskit Fall Fest 2026 — Phase 1  
**Team:** BeyondQ  
**Team Members:** Hansika, Hasini, Pranav, Harsha, Srinidhi  
**Repository commit:**  11f4fe89d5d5a44053f857ecc89c38600c4a11e1
**Report status:** Baseline implementation; official evaluation pending

## 1. Problem and Scope

CryptoShield X is a static source-code scanner intended to identify classical cryptographic API usage in Python, Java, and C source code, classify potential quantum-related migration risk, and recommend post-quantum cryptographic alternatives.

The current implementation is a rule-based baseline. It scans source files, records evidence for matched rules, and generates JSON findings and a Markdown risk report. Official challenge-dataset evaluation and Platform A/B benchmarking remain pending until the required organizer resources and specifications are available.

## 2. Method

The scanner uses regular-expression rules to identify selected cryptographic API patterns in `.py`, `.java`, `.c`, and `.h` files.

Findings include evidence such as file path, line number, rule identifier, algorithm or operation classification, risk, confidence, and migration recommendation, where available in the rule and output schema.

The current method is intended for initial inventory and triage. Pattern matching can miss aliases, wrappers, indirect calls, and usages not represented by existing rules. A match alone does not prove a vulnerability.

## 3. Dataset and Ground Truth

**Dataset used for the local baseline:** `samples/mini_repo`  
**Files scanned:** 3  
**Findings generated:** 3  
**Official organizer dataset:** Not yet evaluated in the recorded baseline  
**Ground-truth status:** Official precision and recall are pending authorized labeled data.

The local sample run is a functional smoke test and must not be presented as a representative evaluation of the full challenge dataset.

## 4. Detection Quality

| Metric | Result | Protocol |
|---|---|---|
| Precision | TBD | Requires authorized labeled ground truth |
| Recall | TBD | Requires authorized labeled ground truth |
| F1 | TBD | Calculate after precision and recall |
| False positives | TBD | Requires labeled-data comparison |
| False negatives | TBD | Requires labeled-data comparison |

No official detection-quality metrics are claimed at this stage.

## 5. Platform A/B Benchmark

Official Platform A/B results have not yet been recorded.

| Platform | Files | Scan time | Memory | Repetitions |
|---|---:|---|---|---:|
| A | TBD | TBD | TBD | TBD |
| B | TBD | TBD | TBD | TBD |

**Local baseline benchmark (not an official Platform A/B result):**

Input: samples/mini_repo

Files scanned per run: 3

Repetitions: 5

Mean scan time: approximately 0.002491 seconds

Median scan time: approximately 0.001822 seconds

Peak Python-tracked allocation: 23,160 bytes, measured using tracemalloc

The recorded durations are local measurements and may vary with machine load, runtime, and environment. Python-tracked allocation is not the same as total process memory.

Official platform specifications, environment details, and measurement protocol must be added after the organizers' Platform A/B requirements are confirmed.

## 6. Migration Recommendations

Recommendations should be based on the detected algorithm and operation, not solely on a generic risk label.

- **Key establishment:** Investigate ML-KEM or another suitable standardized post-quantum key-establishment mechanism where appropriate.
- **Digital signatures:** Investigate ML-DSA or another suitable standardized post-quantum signature scheme where appropriate.
- **Other cryptographic operations:** Review the use case and protocol before choosing a migration strategy.

These algorithms are not universal drop-in replacements. Migration decisions require compatibility, protocol, implementation, key-management, and security review. Final recommendations should cite the corresponding scanner finding and explain the rationale.

## 7. Error Analysis

The current regular-expression approach has known limitations:

- False positives may arise when a matching API name appears in comments, strings, examples, or irrelevant contexts.
- False negatives may occur when cryptographic operations are hidden behind wrappers, aliases, indirect calls, or unsupported API patterns.
- A matched API name does not by itself establish exploitability or prove that a system is insecure.
- Risk classifications and recommendations depend on the coverage and quality of the rule set.

Next improvements include expanding test fixtures, reviewing rule specificity, adding context-aware or AST-based analysis where practical, and evaluating results against authorized ground truth.

## 8. Reproducibility

Run the baseline from the project root:

```bash
python main.py scan samples/mini_repo --out results/findings.json
python main.py report results/findings.json --out results/risk_report.md
python main.py benchmark samples/mini_repo --out results/local_benchmark.json --runs 5
python -m pytest
```

Recorded test environment:

- Operating system: Windows (win32)
- Python: 3.13.5
- pytest: 9.1.1
- Automated tests: 1 passed, 0 failed
- Test duration: 0.07 seconds
## 9. Limitations and Next Steps

The current implementation is a runnable baseline, not a completed official evaluation.

Remaining tasks:

1. Run against the organizer-provided Python/Java/C sample repository, following the event rules.
2. Expand scanner tests and review false-positive and false-negative behavior.
3. Calculate precision, recall, and F1 using the authorized ground-truth protocol when available.
4. Benchmark on the specified Platforms A and B, recording environment, repetitions, timing, and memory methodology.
5. Explain migration recommendations using specific findings and operation context.
6. Record the team members, repository commit, and final submission structure.

All results in this report must remain traceable to actual runs. Unknown platform details and unavailable evaluation metrics must not be guessed.
