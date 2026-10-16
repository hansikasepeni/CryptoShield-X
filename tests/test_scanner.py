from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"src"))
from cryptoshield.scanner import scan_path
def test_sample_repo_detects_python_java_c():
    findings,meta=scan_path(ROOT/"samples"/"mini_repo")
    rules={f["rule_id"] for f in findings}
    assert "PY_RSA_KEYGEN" in rules
    assert "JAVA_EC" in rules
    assert "C_OPENSSL_RSA" in rules
    assert meta["files_scanned"] >= 3
