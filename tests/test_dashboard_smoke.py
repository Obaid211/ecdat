"""
Smoke tests for dashboard-backed graph and migration data flows.
"""

import json

import ecdat_inventory as inv
import ecdat_scoring as score_eng
import ecdat_simulator as sim_eng


def _seed_scored_demo_asset(tmp_path):
    db_path = tmp_path / "dashboard_smoke.db"
    scan_file = tmp_path / "scan.json"
    scan_file.write_text(
        json.dumps(
            {
                "host": "127.0.0.1",
                "port": 8443,
                "scanned_at": "2026-09-20T00:00:00+00:00",
                "status": "success",
                "tls_version": "TLSv1.2",
                "cipher_suite": "ECDHE-RSA-AES128-GCM-SHA256",
                "cert_key_type": "RSA",
                "cert_key_size_bits": 1024,
                "days_to_expiry": 15,
                "risk_flags": ["WEAK_RSA_KEY_SIZE:1024bit", "CERT_EXPIRING_SOON:15d"],
            }
        ),
        encoding="utf-8",
    )

    inv.ingest_scan_results(scan_file, db_path=db_path)
    inv.seed_demo_data(db_path=db_path)
    scored_assets = score_eng.score_all_assets(db_path=db_path)
    return db_path, scored_assets


def test_dashboard_dependency_graph_has_demo_services(tmp_path):
    db_path, _ = _seed_scored_demo_asset(tmp_path)

    graph = sim_eng.build_dependency_graph(db_path=db_path)

    assert graph.number_of_nodes() >= 6
    assert graph.number_of_edges() >= 5
    assert any(data["name"] == "Legacy Portal" for _, data in graph.nodes(data=True))


def test_dashboard_migration_simulator_returns_roadmap_data(tmp_path):
    db_path, scored_assets = _seed_scored_demo_asset(tmp_path)
    top_asset = scored_assets[0]

    simulation = sim_eng.simulate_migration(top_asset["id"], db_path=db_path)
    roadmap = sim_eng.recommend_migration_order(db_path=db_path)

    assert simulation["host"] == "127.0.0.1"
    assert simulation["recommended_replacement"]
    assert simulation["blast_radius_count"] >= 1
    assert roadmap[0]["asset_id"] == top_asset["id"]
