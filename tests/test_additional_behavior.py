"""
Additional behavioral checks for ECDAT.

These tests exercise boundary and integration-style cases that are not covered
by the original suite.
"""

import json

from ecdat_codescanner import scan_source_directory
from ecdat_inventory import (
    export_cbom,
    get_all_assets,
    get_asset_history,
    ingest_scan_results,
)
from ecdat_scanner import classify_risk, parse_target
from ecdat_simulator import simulate_migration


def test_parse_target_ignores_blank_and_comment_lines():
    assert parse_target("") is None
    assert parse_target("   # ignored host") is None


def test_parse_target_defaults_to_https_port_and_accepts_custom_port():
    assert parse_target("example.com") == ("example.com", 443)
    assert parse_target("example.com:8443") == ("example.com", 8443)


def test_cert_expiring_exactly_30_days_is_flagged():
    flags = classify_risk(
        "TLSv1.3",
        "RSA",
        2048,
        "sha256WithRSAEncryption",
        30,
    )
    assert "CERT_EXPIRING_SOON:30d" in flags


def test_scan_source_directory_skips_unsupported_single_file(tmp_path):
    notes = tmp_path / "notes.md"
    notes.write_text("hashlib.md5(secret)\n", encoding="utf-8")

    findings = scan_source_directory(str(notes), db_path=tmp_path / "ecdat.db")

    assert findings == []


def test_ingest_upserts_current_asset_but_keeps_history(tmp_path):
    scan_file = tmp_path / "scan.json"
    db_path = tmp_path / "ecdat.db"

    scan_file.write_text(
        json.dumps(
            {
                "host": "service.internal",
                "port": 443,
                "scanned_at": "2026-09-19T10:00:00+00:00",
                "status": "success",
                "tls_version": "TLSv1.2",
                "cert_key_type": "RSA",
                "cert_key_size_bits": 1024,
                "risk_flags": ["WEAK_RSA_KEY_SIZE:1024bit"],
            }
        ),
        encoding="utf-8",
    )
    assert ingest_scan_results(scan_file, db_path=db_path) == 1

    scan_file.write_text(
        json.dumps(
            {
                "host": "service.internal",
                "port": 443,
                "scanned_at": "2026-09-19T11:00:00+00:00",
                "status": "success",
                "tls_version": "TLSv1.3",
                "cert_key_type": "RSA",
                "cert_key_size_bits": 3072,
                "risk_flags": [],
            }
        ),
        encoding="utf-8",
    )
    assert ingest_scan_results(scan_file, db_path=db_path) == 1

    assets = get_all_assets(db_path)
    history = get_asset_history("service.internal", 443, db_path=db_path)

    assert len(assets) == 1
    assert assets[0]["tls_version"] == "TLSv1.3"
    assert assets[0]["risk_flags"] == []
    assert len(history) == 2


def test_export_cbom_contains_cyclonedx_crypto_component(tmp_path):
    scan_file = tmp_path / "scan.json"
    db_path = tmp_path / "ecdat.db"
    scan_file.write_text(
        json.dumps(
            {
                "host": "gateway.internal",
                "port": 8443,
                "status": "success",
                "tls_version": "TLSv1.3",
                "cipher_suite": "TLS_AES_256_GCM_SHA384",
                "cert_key_type": "ECC (secp256r1)",
                "cert_key_size_bits": 256,
                "risk_flags": [],
            }
        ),
        encoding="utf-8",
    )
    ingest_scan_results(scan_file, db_path=db_path)

    cbom = json.loads(export_cbom(db_path=db_path))

    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.6"
    assert cbom["components"][0]["type"] == "cryptographic-asset"
    assert cbom["components"][0]["name"] == "TLS Endpoint gateway.internal:8443"


def test_simulate_migration_returns_error_for_missing_asset(tmp_path):
    db_path = tmp_path / "empty.db"

    result = simulate_migration(999, db_path=db_path)

    assert result == {"error": "Asset ID 999 not found."}
