"""
ECDAT - Bonus: Source Code Cryptographic Scanner
-------------------------------------------------
Scans source code repositories (Python AST + Regex pattern matching across languages)
for hardcoded crypto calls, weak algorithms (MD5, SHA1, DES, weak RSA), and exposed secret keys.
"""

import ast
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from ecdat_inventory import DEFAULT_DB_PATH, get_db_connection, init_db


CRYPTO_CODE_PATTERNS = {
    "WEAK_HASH_MD5": {
        "pattern": r"hashlib\.md5\(|MD5\(|CryptoJS\.MD5|MessageDigest\.getInstance\(['\"]MD5['\"]\)",
        "severity": "CRITICAL",
        "type": "Weak Hashing Algorithm (MD5)",
    },
    "WEAK_HASH_SHA1": {
        "pattern": r"hashlib\.sha1\(|SHA1\(|CryptoJS\.SHA1|MessageDigest\.getInstance\(['\"]SHA-1['\"]\)",
        "severity": "HIGH",
        "type": "Weak Hashing Algorithm (SHA-1)",
    },
    "WEAK_CIPHER_DES": {
        "pattern": r"DES\.new\(|DES3\.new\(|Cipher\.getInstance\(['\"]DES['\"]\)",
        "severity": "CRITICAL",
        "type": "Deprecated Block Cipher (DES/3DES)",
    },
    "HARDCODED_RSA_KEY": {
        "pattern": r"RSA\.generate\(\s*(1024|512)\b",
        "severity": "HIGH",
        "type": "Weak RSA Key Generation (<2048 bits)",
    },
    "HARDCODED_PRIVATE_KEY": {
        "pattern": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
        "severity": "CRITICAL",
        "type": "Hardcoded Cryptographic Private Key",
    },
    "HARDCODED_SECRET_STRING": {
        "pattern": r"(?:api[_\-]?key|secret[_\-]?key|private[_\-]?key)\s*=\s*['\"][A-Za-z0-9+/=_\-]{16,}['\"]",
        "severity": "MEDIUM",
        "type": "Hardcoded Secret Key String",
    }
}

SUPPORTED_EXTENSIONS = {".py", ".js", ".java", ".c", ".cpp", ".cs", ".go", ".php", ".rb", ".pem", ".txt", ".env", ".yaml", ".yml"}


def scan_file_content(file_path: Path) -> list:
    """Scans a single file using regex rules and AST parsing for Python files."""
    findings = []

    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return findings

    lines = content.splitlines()

    # Regex Rule Engine
    for line_no, line in enumerate(lines, 1):
        for rule_id, rule_data in CRYPTO_CODE_PATTERNS.items():
            if re.search(rule_data["pattern"], line, re.IGNORECASE):
                findings.append({
                    "file_path": str(file_path),
                    "line_number": line_no,
                    "rule_id": rule_id,
                    "finding_type": rule_data["type"],
                    "code_snippet": line.strip()[:150],
                    "severity": rule_data["severity"],
                    "scanned_at": datetime.now(timezone.utc).isoformat()
                })

    # Python AST Detailed Inspection (if Python file)
    if file_path.suffix.lower() == ".py":
        try:
            tree = ast.parse(content, filename=str(file_path))
            for node in ast.walk(tree):
                # Detect hashlib.md5 or hashlib.sha1 function calls
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                    if func_name in ["md5", "sha1"]:
                        severity = "CRITICAL" if func_name == "md5" else "HIGH"
                        findings.append({
                            "file_path": str(file_path),
                            "line_number": node.lineno,
                            "rule_id": f"AST_WEAK_HASH_{func_name.upper()}",
                            "finding_type": f"Python AST: Weak Hash Usage ({func_name.upper()})",
                            "code_snippet": lines[node.lineno - 1].strip() if node.lineno <= len(lines) else "",
                            "severity": severity,
                            "scanned_at": datetime.now(timezone.utc).isoformat()
                        })
        except Exception:
            pass

    return findings


def scan_source_directory(repo_path: str, db_path=DEFAULT_DB_PATH) -> list:
    """
    Walks directory tree, scans code files, stores findings in ecdat.db,
    and returns list of finding records.
    """
    init_db(db_path)
    root = Path(repo_path)

    if not root.exists():
        raise FileNotFoundError(f"Source path not found: {repo_path}")

    all_findings = []

    if root.is_file():
        files = [root]
    else:
        files = [p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in SUPPORTED_EXTENSIONS]

    for f in files:
        # Skip virtualenvs, git, node_modules
        if any(ignored in str(f) for ignored in [".venv", "venv", ".git", "node_modules", "__pycache__"]):
            continue
        file_findings = scan_file_content(f)
        all_findings.extend(file_findings)

    # Persist into SQLite
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    for item in all_findings:
        cursor.execute("""
            INSERT INTO code_findings (file_path, line_number, rule_id, finding_type, code_snippet, severity, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            item["file_path"], item["line_number"], item["rule_id"],
            item["finding_type"], item["code_snippet"], item["severity"], item["scanned_at"]
        ))

    conn.commit()
    conn.close()
    return all_findings


if __name__ == "__main__":
    findings = scan_source_directory(".")
    print(f"Code Scan Complete. Found {len(findings)} cryptographic issues in source code:")
    for f in findings[:5]:
        print(f" - [{f['severity']}] {Path(f['file_path']).name}:{f['line_number']} -> {f['finding_type']} ({f['code_snippet'][:40]})")
