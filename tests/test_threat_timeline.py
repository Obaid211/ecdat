"""
Unit tests for ECDAT Mosca-inspired Threat Timeline (ecdat_threat_timeline.py)
"""
import pytest
from pathlib import Path
import json
import ecdat_inventory as inv
import ecdat_scoring as score_eng
import ecdat_threat_timeline as threat_eng


def test_threat_timeline_calculation(tmp_path: Path):
    db = str(tmp_path / "test_threat.db")
    scan_file = tmp_path / "scan.json"
    scan_file.write_text(json.dumps([
        {
            "host": "critical-vault.internal",
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

    inv.ingest_scan_results(str(scan_file), db_path=db)
    inv.seed_demo_data(db_path=db)
    score_eng.score_all_assets(db_path=db)

    # Calculate single asset urgency
    res = threat_eng.calculate_migration_urgency(
        shelf_life_years=10.0,
        migration_time_years=3.0,
        planning_horizon_years=10.0,
        asset_mwqrs=75.0,
        is_quantum_vulnerable=True,
        asset_name="critical-vault.internal:443"
    )
    assert res["combined_requirement_years"] == 13.0
    assert res["margin_or_deficit_years"] == -3.0
    assert res["is_deficit"] is True
    assert res["urgency_level"] == "CRITICAL"
    assert "exceeds the organizational planning assumption" in res["summary_reason"]

    # Calculate inventory-wide urgency
    inventory_results = threat_eng.evaluate_inventory_threat_urgency(db_path=db, planning_horizon_years=10.0)
    assert len(inventory_results) >= 1
    item = inventory_results[0]
    assert "combined_requirement_years" in item
    assert "margin_or_deficit_years" in item
    assert "urgency_level" in item


def test_sensitivity_profiles():
    # Verify profiles exist and have expected ordering of shelf-life
    assert threat_eng.DATA_SENSITIVITY_PROFILES["Critical / National Security (P0)"]["default_shelf_life_years"] >= \
           threat_eng.DATA_SENSITIVITY_PROFILES["Public / Non-Sensitive"]["default_shelf_life_years"]
