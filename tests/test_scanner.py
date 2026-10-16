
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cryptoshield.scanner import scan_path


def test_sample_repo_detects_python_java_c():
    findings, meta = scan_path(ROOT / "samples" / "mini_repo")

    rules = {finding["rule_id"] for finding in findings}

    assert "PY_RSA_KEYGEN" in rules
    assert "JAVA_EC" in rules
    assert "C_OPENSSL_RSA" in rules
    assert meta["files_scanned"] >= 3


def test_findings_preserve_file_names_and_line_numbers():
    findings, _ = scan_path(ROOT / "samples" / "mini_repo")

    expected = {
        ("example.py", 2, "PY_RSA_KEYGEN"),
        ("Example.java", 2, "JAVA_EC"),
        ("example.c", 2, "C_OPENSSL_RSA"),
    }

    actual = {
        (finding["file"], finding["line"], finding["rule_id"])
        for finding in findings
    }

    assert expected.issubset(actual)


def test_ordinary_text_does_not_trigger_crypto_findings(tmp_path):
    source_file = tmp_path / "ordinary.py"
    source_file.write_text(
        "message = 'Welcome to the application'\n"
        "total = 10 + 20\n",
        encoding="utf-8",
    )

    findings, meta = scan_path(tmp_path)

    assert findings == []
    assert meta["files_scanned"] == 1


def test_unsupported_files_are_ignored(tmp_path):
    source_file = tmp_path / "notes.txt"
    source_file.write_text(
        "RSA and cryptography are mentioned in this note.\n",
        encoding="utf-8",
    )

    findings, meta = scan_path(tmp_path)

    assert findings == []
    assert meta["files_scanned"] == 0


def test_crypto_api_mentioned_in_comment_is_ignored(tmp_path):
    source_file = tmp_path / "comment_example.py"
    source_file.write_text(
        "# Example: rsa.generate_private_key() is mentioned here\n",
        encoding="utf-8",
    )

    findings, _ = scan_path(tmp_path)

    assert findings == []


def test_crypto_api_in_executable_code_is_still_detected(tmp_path):
    source_file = tmp_path / "crypto_example.py"
    source_file.write_text(
        "# This comment should be ignored\n"
        "private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n",
        encoding="utf-8",
    )

    findings, _ = scan_path(tmp_path)

    assert any(
        finding["rule_id"] == "PY_RSA_KEYGEN"
        and finding["line"] == 2
        for finding in findings
    )
