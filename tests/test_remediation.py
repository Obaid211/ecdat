"""
Unit tests for ECDAT Remediation Center (ecdat_remediation.py)
"""
import pytest
from pathlib import Path
import json
import ecdat_inventory as inv
import ecdat_scoring as score_eng
import ecdat_remediation as rem_eng


def test_remediation_plan_generation(tmp_path: Path):
    db = str(tmp_path / "test_rem.db")
    scan_file = tmp_path / "scan.json"
    scan_file.write_text(json.dumps([
        {
            "host": "127.0.0.1",
            "port": 8443,
            "scanned_at": "2026-09-20T00:00:00+00:00",
            "status": "success",
            "tls_version": "TLSv1.2",
            "cert_key_type": "RSA",
            "cert_key_size_bits": 1024,
            "days_to_expiry": 10,
            "risk_flags": ["WEAK_RSA_KEY_SIZE:1024bit", "CERT_EXPIRING_SOON:10d"]
        },
        {
            "host": "safe-server.internal",
            "port": 443,
            "scanned_at": "2026-09-20T00:00:00+00:00",
            "status": "success",
            "tls_version": "TLSv1.3",
            "cert_key_type": "ECC",
            "cert_key_size_bits": 384,
            "days_to_expiry": 300,
            "risk_flags": []
        }
    ]), encoding="utf-8")

    inv.ingest_scan_results(str(scan_file), db_path=db)
    inv.seed_demo_data(db_path=db)
    score_eng.score_all_assets(db_path=db)

    plan = rem_eng.generate_remediation_plan(db_path=db)
    assert len(plan) == 2
    assert plan[0]["target"] == "127.0.0.1:8443"
    assert "Critical MWQRS" in plan[0]["why_prioritized"] or "Sub-standard RSA" in plan[0]["why_prioritized"]
    assert len(plan[0]["recommended_actions"]) >= 1
    assert "ML-KEM" in plan[0]["migration_direction"]
