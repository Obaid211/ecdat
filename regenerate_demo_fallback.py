"""
Regenerates demo_fallback.db and demo_fallback_scan.json correctly —
ensures services + service_dependencies tables are seeded BEFORE the copy,
so Cached Mode has real dependency data for the graph and the PQC simulator.

Run this from inside the ecdat_package project folder, AFTER running:
    python cli.py pipeline --hosts hosts.txt
(with generate_test_certs.py running in a separate terminal)
"""
import shutil
import sqlite3
from pathlib import Path

import ecdat_inventory as inv
import ecdat_scoring as score_eng

DB_PATH = "ecdat.db"
SCAN_JSON = "scan_results.json"
FALLBACK_DB = "demo_fallback.db"
FALLBACK_JSON = "demo_fallback_scan.json"

# 1. Make sure live ecdat.db has real scan data ingested already
if not Path(DB_PATH).exists():
    raise SystemExit(f"{DB_PATH} not found — run the pipeline first.")

# 2. Force re-seed of services + dependencies (idempotent, safe to re-run)
inv.init_db(DB_PATH)
inv.seed_demo_data(DB_PATH)

# 3. Re-score everything so risk_score column is fresh
score_eng.score_all_assets(DB_PATH)

# 4. Verify BEFORE copying — fail loudly if seed data is missing
conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()
cur.execute("SELECT COUNT(*) FROM services")
service_count = cur.fetchone()[0]
cur.execute("SELECT COUNT(*) FROM service_dependencies")
dep_count = cur.fetchone()[0]
cur.execute("SELECT COUNT(*) FROM crypto_assets WHERE linked_service_id IS NOT NULL")
linked_count = cur.fetchone()[0]
cur.execute("SELECT risk_score FROM crypto_assets WHERE host='127.0.0.1' AND port=8443")
row = cur.fetchone()
legacy_score = row[0] if row else None
conn.close()

print(f"Services in DB before copy: {service_count} (expected 6)")
print(f"Dependency edges before copy: {dep_count} (expected 5)")
print(f"Assets linked to a service: {linked_count}")
print(f"127.0.0.1:8443 risk score: {legacy_score} (expected ~90.0)")

if service_count < 6 or dep_count < 5:
    raise SystemExit(
        "REFUSING TO COPY — seed data is incomplete. "
        "Check seed_demo_data() ran without error above."
    )

if legacy_score is None:
    raise SystemExit(
        "REFUSING TO COPY — 127.0.0.1:8443 not found in ecdat.db. "
        "Make sure generate_test_certs.py was running before the pipeline scan."
    )

# 5. Only now copy to fallback — guaranteed to have full graph data
shutil.copy(DB_PATH, FALLBACK_DB)
if Path(SCAN_JSON).exists():
    shutil.copy(SCAN_JSON, FALLBACK_JSON)

print(f"\n[SUCCESS] {FALLBACK_DB} regenerated with {service_count} services, {dep_count} edges.")
print(f"[SUCCESS] {FALLBACK_JSON} regenerated.")
print("\nNext: switch app.py to CACHED MODE and manually verify:")
print("  1. Service Dependency Graph tab shows 6 nodes, 5 edges (not blank)")
print("  2. PQC Migration Simulator on 127.0.0.1:8443 shows 5 affected services, High complexity")
print("     (NOT 'no downstream dependent services affected')")
