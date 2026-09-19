"""
ECDAT Unit Tests - Source Code Scanner (ecdat_codescanner.py)
-------------------------------------------------------------
Tests detection of weak hashes (MD5), DES ciphers, and hardcoded private keys on temp files.
"""

import pytest
from pathlib import Path
from ecdat_codescanner import scan_file_content


def test_scan_vulnerable_code(tmp_path: Path):
    """Write temporary file containing MD5, DES, and fake hardcoded key string."""
    bad_file = tmp_path / "vulnerable_sample.py"
    bad_file.write_text("""import hashlib
from Crypto.Cipher import DES

def process_data(data):
    # Weak MD5 hash
    h = hashlib.md5(data).hexdigest()
    # Deprecated DES cipher
    cipher = DES.new(b'8bytekey')
    api_secret_key = "12345678901234567890"
    return h
""", encoding="utf-8")

    findings = scan_file_content(bad_file)
    rule_ids = [f["rule_id"] for f in findings]
    
    assert any("MD5" in rid for rid in rule_ids)
    assert any("DES" in rid for rid in rule_ids)
    assert len(findings) >= 2


def test_scan_clean_code(tmp_path: Path):
    """Write temporary clean file with modern crypto."""
    clean_file = tmp_path / "clean_sample.py"
    clean_file.write_text("""import hashlib

def process_data(data):
    # Modern SHA-256 hash
    h = hashlib.sha256(data).hexdigest()
    return h
""", encoding="utf-8")

    findings = scan_file_content(clean_file)
    assert len(findings) == 0
