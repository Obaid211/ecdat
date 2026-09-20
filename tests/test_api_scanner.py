"""
Unit tests for ECDAT API Crypto Scanner (ecdat_apiscanner.py)
"""
import pytest
from pathlib import Path
import json
import base64
import ecdat_apiscanner as apiscan
import ecdat_inventory as inv


def test_decode_jwt_header():
    header = {"alg": "RS256", "typ": "JWT", "kid": "key-123"}
    encoded = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    fake_jwt = f"{encoded}.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"

    decoded = apiscan.decode_jwt_header(fake_jwt)
    assert decoded["alg"] == "RS256"
    assert decoded["kid"] == "key-123"


def test_classify_jwt_alg():
    assert "RSA" in apiscan.classify_jwt_algorithm("RS256")["type"]
    assert "ECDSA" in apiscan.classify_jwt_algorithm("ES256")["type"]
    assert "HMAC" in apiscan.classify_jwt_algorithm("HS256")["type"]
    assert "Post-Quantum" in apiscan.classify_jwt_algorithm("ML-DSA-65")["type"]
    assert apiscan.classify_jwt_algorithm("none")["risk_level"] == "CRITICAL"


def test_scan_api_fixture(tmp_path: Path):
    fixture_path = tmp_path / "sample_api.json"
    header = {"alg": "RS256", "typ": "JWT"}
    enc = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    token = f"{enc}.eyJ1c2VyIjoiYWRtaW4ifQ.fakesig"

    fixture_data = {
        "api_url": "https://api.internal.bank/v1/auth",
        "sample_jwt": token,
        "tls_info": {
            "version": "TLSv1.3",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
            "cert_key_type": "RSA",
            "cert_key_size_bits": 2048,
        },
        "headers": {
            "Content-Type": "application/json"
        }
    }
    fixture_path.write_text(json.dumps(fixture_data), encoding="utf-8")

    db = str(tmp_path / "test_api.db")
    report = apiscan.inspect_api_fixture(str(fixture_path), db_path=db)
    assert report["url"] == "https://api.internal.bank/v1/auth"
    assert report["jwt_analysis"] is not None
    assert report["jwt_analysis"]["classification"]["algorithm"] == "RS256"
    assert "HTTP Strict-Transport-Security (HSTS) header missing" in report["findings"]

    # Verify persistence
    conn = inv.get_db_connection(db)
    cur = conn.cursor()
    cur.execute("SELECT * FROM api_findings")
    rows = cur.fetchall()
    conn.close()
    assert len(rows) == 1
