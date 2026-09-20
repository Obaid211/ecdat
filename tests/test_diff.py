"""
Unit tests for ECDAT Rescan & Diff Engine (ecdat_diff.py)
"""
import pytest
from pathlib import Path
import json
import ecdat_inventory as inv
import ecdat_scoring as score_eng
import ecdat_diff as diff_eng


def test_snapshot_and_diff(tmp_path: Path):
    db = str(tmp_path / "test_diff.db")
    scan_file_1 = tmp_path / "scan1.json"
    scan_file_1.write_text(json.dumps([
        {
            "host": "auth.example.com",
            "port": 443,
            "scanned_at": "2026-09-20T00:00:00+00:00",
            "status": "success",
            "tls_version": "TLSv1.2",
            "cert_key_type": "RSA",
            "cert_key_size_bits": 2048,
            "days_to_expiry": 100,
            "risk_flags": []
        }
    ]), encoding="utf-8")

    inv.ingest_scan_results(str(scan_file_1), db_path=db)
    inv.seed_demo_data(db_path=db)
    score_eng.score_all_assets(db_path=db)

    # Create first snapshot
    snap1_id = inv.save_scan_snapshot("Baseline", db_path=db)
    assert snap1_id is not None

    # Now simulate a scan update where cert key size changes or new asset is added
    scan_file_2 = tmp_path / "scan2.json"
    scan_file_2.write_text(json.dumps([
        {
            "host": "auth.example.com",
            "port": 443,
            "scanned_at": "2026-09-21T00:00:00+00:00",
            "status": "success",
            "tls_version": "TLSv1.3",
            "cert_key_type": "RSA",
            "cert_key_size_bits": 4096,
            "days_to_expiry": 365,
            "risk_flags": []
        },
        {
            "host": "new-node.example.com",
            "port": 443,
            "scanned_at": "2026-09-21T00:00:00+00:00",
            "status": "success",
            "tls_version": "TLSv1.3",
            "cert_key_type": "ECC",
            "cert_key_size_bits": 256,
            "days_to_expiry": 300,
            "risk_flags": []
        }
    ]), encoding="utf-8")

    inv.ingest_scan_results(str(scan_file_2), db_path=db)
    inv.seed_demo_data(db_path=db)
    score_eng.score_all_assets(db_path=db)

    # Create second snapshot
    snap2_id = inv.save_scan_snapshot("24h Rescan", db_path=db)
    assert snap2_id is not None

    # Compare snapshots
    diff_report = diff_eng.compare_snapshots(snap1_id, snap2_id, db_path=db)
    assert diff_report is not None
    assert len(diff_report["added"]) == 1
    assert diff_report["added"][0]["host"] == "new-node.example.com"
    assert len(diff_report["modified"]) >= 1

    auth_mod = [m for m in diff_report["modified"] if m["target"] == "auth.example.com:443"][0]
    changed_props = [c["property"] for c in auth_mod["changes"]]
    assert "TLS Version" in changed_props
    assert "Key Size" in changed_props

    # Test markdown report generation
    md = diff_eng.export_diff_markdown(diff_report)
    assert "ECDAT Cryptographic Rescan Diff" in md
    assert "auth.example.com:443" in md
    assert len(diff_report["alerts"]) >= 1
