"""
ECDAT - Stage 4: Quantum Risk Scoring Engine
---------------------------------------------
Implements Mosca-Weighted Quantum Risk Score (MWQRS) inspired by Mosca's Inequality
(X + Y > Z: migration time + security lifespan > time to quantum computer).

The MWQRS is a *weighted composite score* (0–100 scale) across five risk dimensions
(algorithm vulnerability, key size, TLS version, cert expiry, service criticality),
not a direct numerical evaluation of X + Y > Z.  It captures the *spirit* of Mosca's
framework — that urgency is driven by algorithmic exposure, migration cost, and data
retention — but uses a scoring model rather than the raw three-variable inequality.

Scores assets on a 0 (safe) to 100 (critical) scale and updates ecdat.db.
"""


import json
import sqlite3
from ecdat_inventory import DEFAULT_DB_PATH, get_db_connection, get_all_assets


QUANTUM_VULNERABLE_ALGORITHMS = ["RSA", "ECC", "DH", "DSA"]
QUANTUM_SAFE_ALGORITHMS = ["AES-256", "SHA-3", "ML-KEM", "ML-DSA", "SLH-DSA"]

RISK_WEIGHTS = {
    "algorithm_vulnerability": 0.35,
    "key_size": 0.20,
    "protocol_version": 0.15,
    "cert_expiry": 0.10,
    "service_criticality": 0.20,
}

CRITICALITY_MULTIPLIERS = {
    "P0": 1.5,
    "P1": 1.2,
    "P2": 1.0,
    "P3": 0.8,
}


def calculate_mwqrs(asset_record: dict, service_criticality: str = "P2") -> float:
    """
    Takes a crypto_asset dict + linked service criticality.
    Returns MWQRS score from 0.0 (safe) to 100.0 (critical).
    """
    if asset_record.get("status") != "success":
        return 0.0

    key_type = asset_record.get("cert_key_type") or ""
    key_size = asset_record.get("cert_key_size_bits")
    tls_version = asset_record.get("tls_version") or ""
    days_to_expiry = asset_record.get("days_to_expiry")

    # 1. Algorithm Vulnerability Sub-score (0 - 100)
    algo_score = 0.0
    if any(vuln.lower() in key_type.lower() for vuln in QUANTUM_VULNERABLE_ALGORITHMS):
        algo_score = 100.0
    elif any(safe.lower() in key_type.lower() for safe in QUANTUM_SAFE_ALGORITHMS):
        algo_score = 0.0
    else:
        # Default for classical asymmetric keys if unrecognized
        algo_score = 80.0

    # 2. Key Size Sub-score (0 - 100)
    key_size_score = 0.0
    if key_size:
        if "RSA" in key_type.upper():
            if key_size < 1024:
                key_size_score = 100.0
            elif key_size < 2048:
                key_size_score = 75.0
            elif key_size < 3072:
                key_size_score = 30.0
            else:
                key_size_score = 10.0
        elif "ECC" in key_type.upper():
            if key_size < 256:
                key_size_score = 100.0
            elif key_size < 384:
                key_size_score = 30.0
            else:
                key_size_score = 10.0
        else:
            key_size_score = 50.0
    else:
        key_size_score = 50.0

    # 3. Protocol Version Sub-score (0 - 100)
    protocol_score = 0.0
    if tls_version in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]:
        protocol_score = 100.0
    elif tls_version == "TLSv1.2":
        protocol_score = 50.0
    elif tls_version == "TLSv1.3":
        protocol_score = 10.0
    else:
        protocol_score = 60.0

    # 4. Certificate Expiry Sub-score (0 - 100)
    expiry_score = 0.0
    if days_to_expiry is not None:
        if days_to_expiry < 0:
            expiry_score = 100.0
        elif days_to_expiry <= 30:
            expiry_score = 75.0
        elif days_to_expiry <= 90:
            expiry_score = 35.0
        else:
            expiry_score = 0.0

    # 5. Service Criticality Component
    crit_mult = CRITICALITY_MULTIPLIERS.get(service_criticality, 1.0)
    crit_base = 50.0 if service_criticality in ["P0", "P1"] else 20.0

    # Weighted Sum
    weighted_sum = (
        algo_score * RISK_WEIGHTS["algorithm_vulnerability"] +
        key_size_score * RISK_WEIGHTS["key_size"] +
        protocol_score * RISK_WEIGHTS["protocol_version"] +
        expiry_score * RISK_WEIGHTS["cert_expiry"] +
        crit_base * RISK_WEIGHTS["service_criticality"]
    )

    final_score = min(100.0, weighted_sum * crit_mult)
    return round(final_score, 1)


def score_all_assets(db_path=DEFAULT_DB_PATH):
    """
    Runs calculate_mwqrs on every asset in the DB, updates 'risk_score' column,
    and returns assets sorted by risk score descending.
    """
    assets = get_all_assets(db_path)
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    scored_assets = []
    for a in assets:
        service_crit = a.get("service_criticality") or "P2"
        score = calculate_mwqrs(a, service_criticality=service_crit)
        a["risk_score"] = score
        cursor.execute("UPDATE crypto_assets SET risk_score = ? WHERE id = ?", (score, a["id"]))
        scored_assets.append(a)

    conn.commit()
    conn.close()

    scored_assets.sort(key=lambda x: x["risk_score"], reverse=True)
    return scored_assets


def score_service_aggregate(service_id: int, db_path=DEFAULT_DB_PATH) -> dict:
    """
    Aggregates all assets linked to a service into one service-level score
    (max risk score + average risk score).
    """
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT name, criticality FROM services WHERE id = ?
    """, (service_id,))
    svc = cursor.fetchone()
    if not svc:
        conn.close()
        return {"service_id": service_id, "score": 0.0, "asset_count": 0}

    cursor.execute("""
        SELECT risk_score FROM crypto_assets WHERE linked_service_id = ?
    """, (service_id,))
    rows = cursor.fetchall()
    conn.close()

    scores = [r["risk_score"] for r in rows if r["risk_score"] is not None]
    if not scores:
        return {
            "service_id": service_id,
            "service_name": svc["name"],
            "criticality": svc["criticality"],
            "max_score": 0.0,
            "avg_score": 0.0,
            "asset_count": 0
        }

    max_score = round(max(scores), 1)
    avg_score = round(sum(scores) / len(scores), 1)

    return {
        "service_id": service_id,
        "service_name": svc["name"],
        "criticality": svc["criticality"],
        "max_score": max_score,
        "avg_score": avg_score,
        "asset_count": len(scores)
    }


if __name__ == "__main__":
    scored = score_all_assets()
    print(f"Scored {len(scored)} assets. Top 3 highest risk:")
    for a in scored[:3]:
        print(f" - {a['host']}:{a['port']} -> MWQRS Score: {a['risk_score']} | Key: {a['cert_key_type']} {a['cert_key_size_bits']}b")
