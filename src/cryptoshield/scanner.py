
import io
import re
import time
import tokenize
from pathlib import Path

from .rules import RULES


EXT_LANG = {
    ".py": "python",
    ".java": "java",
    ".c": "c",
    ".h": "c",
}


def _remove_python_comments(source):
    """Remove Python comments while preserving strings and line numbers."""
    try:
        tokens = tokenize.generate_tokens(io.StringIO(source).readline)
        lines = source.splitlines(keepends=True)

        for token in tokens:
            if token.type == tokenize.COMMENT:
                start_line, start_col = token.start
                end_line, end_col = token.end

                if start_line == end_line:
                    lines[start_line - 1] = (
                        lines[start_line - 1][:start_col]
                        + " " * (end_col - start_col)
                        + lines[start_line - 1][end_col:]
                    )
                else:
                    first = lines[start_line - 1]
                    lines[start_line - 1] = (
                        first[:start_col]
                        + " " * (len(first) - start_col - len(first.lstrip(" \t")))
                        + first[len(first.rstrip("\r\n")):]
                    )

                    for line_number in range(start_line + 1, end_line):
                        lines[line_number - 1] = re.sub(
                            r"[^\r\n]", " ", lines[line_number - 1]
                        )

                    last = lines[end_line - 1]
                    lines[end_line - 1] = (
                        " " * end_col + last[end_col:]
                    )

        return "".join(lines)

    except (tokenize.TokenError, IndentationError):
        # Keep scanning malformed Python rather than crashing.
        return source


def scan_path(root):
    root = Path(root).resolve()

    if not root.exists():
        raise FileNotFoundError(f"Input path does not exist: {root}")

    if root.is_file():
        candidates = [root] if root.suffix.lower() in EXT_LANG else []
        base = root.parent
    else:
        candidates = sorted(
            path
            for path in root.rglob("*")
            if path.is_file() and path.suffix.lower() in EXT_LANG
        )
        base = root

    findings = []
    start = time.perf_counter()

    for path in candidates:
        language = EXT_LANG[path.suffix.lower()]
        source = path.read_text(encoding="utf-8", errors="replace")

        # Python comments are ignored before applying detection rules.
        if language == "python":
            source = _remove_python_comments(source)

        lines = source.splitlines()
        relative_path = path.relative_to(base).as_posix()

        for line_number, line in enumerate(lines, start=1):
            for rule in RULES:
                if language in rule["languages"] and re.search(
                    rule["pattern"], line
                ):
                    findings.append(
                        {
                            "file": relative_path,
                            "line": line_number,
                            "language": language,
                            "rule_id": rule["id"],
                            "matched_evidence": line.strip()[:300],
                            "algorithm": rule["algorithm"],
                            "operation": rule["operation"],
                            "risk": rule["risk"],
                            "confidence": rule["confidence"],
                            "recommendation": rule["recommendation"],
                            "method": "line_regex_rule",
                        }
                    )

    metadata = {
        "scanner": "CryptoShield X baseline",
        "input_path": str(root),
        "files_scanned": len(candidates),
        "elapsed_seconds": round(time.perf_counter() - start, 6),
        "rule_count": len(RULES),
        "supported_extensions": sorted(EXT_LANG),
    }

    return findings, metadata
