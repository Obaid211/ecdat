"""
ECDAT - Stage 6: Post-Quantum Cryptography (PQC) Migration Simulator
----------------------------------------------------------------------
Simulates quantum migration for vulnerable assets. Determines NIST FIPS replacements,
analyzes dependency graph blast radius, computes complexity, and generates an optimal
topological migration sequence.
"""

import json
import sqlite3
import networkx as nx
from ecdat_inventory import DEFAULT_DB_PATH, get_db_connection, get_all_assets


PQC_MIGRATION_MAP = {
    "RSA": {
        "use_case": "key_exchange_and_signature",
        "replacement": "ML-KEM-768 (Kyber) + ML-DSA-65 (Dilithium)",
        "standards": ["NIST FIPS 203 (ML-KEM)", "NIST FIPS 204 (ML-DSA)"],
        "hybrid_recommended": True,
        "migration_notes": "Deploy dual classical RSA-2048 + ML-KEM-768 hybrid certificate during transition.",
    },
    "RSA_KEY": {
        "use_case": "asymmetric_encryption",
        "replacement": "ML-KEM-768 (Kyber)",
        "standards": ["NIST FIPS 203"],
        "hybrid_recommended": True,
        "migration_notes": "Replace RSA public-key exchange with ML-KEM-768 key encapsulation.",
    },
    "ECC": {
        "use_case": "elliptic_curve_signatures",
        "replacement": "ML-DSA-65 (Dilithium) / SLH-DSA (SPHINCS+)",
        "standards": ["NIST FIPS 204 (ML-DSA)", "NIST FIPS 205 (SLH-DSA)"],
        "hybrid_recommended": True,
        "migration_notes": "Transition ECDSA keys to ML-DSA or stateless hash-based SLH-DSA.",
    },
    "DSA": {
        "use_case": "digital_signatures",
        "replacement": "ML-DSA-65 (Dilithium)",
        "standards": ["NIST FIPS 204"],
        "hybrid_recommended": False,
        "migration_notes": "Deprecate legacy DSA immediately in favor of ML-DSA.",
    }
}


def build_dependency_graph(db_path=DEFAULT_DB_PATH) -> nx.DiGraph:
    """
    Builds a NetworkX Directed Graph representing services (nodes) and dependencies (edges).
    Edge direction: Service A -> Service B means A depends on B.
    """
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    G = nx.DiGraph()

    # Add services as nodes with attributes
    cursor.execute("SELECT id, name, criticality, description FROM services")
    services = cursor.fetchall()
    for s in services:
        G.add_node(s["id"], name=s["name"], criticality=s["criticality"], description=s["description"])

    # Add dependencies as directed edges
    cursor.execute("SELECT service_id, depends_on_service_id FROM service_dependencies")
    deps = cursor.fetchall()
    for d in deps:
        G.add_edge(d["service_id"], d["depends_on_service_id"])

    conn.close()
    return G


def get_affected_dependents(service_id: int, G: nx.DiGraph) -> list:
    """
    Finds all services that depend directly or indirectly on service_id.
    In our graph, if A depends on B, edge is A -> B.
    So reverse reachability from B gives all services that depend on B.
    """
    if service_id not in G:
        return []

    reversed_G = G.reverse(copy=True)
    # Get all nodes reachable from service_id in reversed graph
    affected_ids = nx.descendants(reversed_G, service_id)
    affected_names = [G.nodes[n].get("name", f"Service-{n}") for n in affected_ids]
    return affected_names


def simulate_migration(asset_id: int, db_path=DEFAULT_DB_PATH) -> dict:
    """
    Simulates PQC migration for a given asset ID.
    Returns recommendation details, affected components, complexity rating, and roadmap position.
    """
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT a.*, s.name as service_name, s.criticality as service_criticality
        FROM crypto_assets a
        LEFT JOIN services s ON a.linked_service_id = s.id
        WHERE a.id = ?
    """, (asset_id,))
    asset = cursor.fetchone()
    conn.close()

    if not asset:
        return {"error": f"Asset ID {asset_id} not found."}

    asset_dict = dict(asset)
    key_type = asset_dict.get("cert_key_type") or "RSA"

    # Select PQC mapping
    pqc_info = PQC_MIGRATION_MAP.get("RSA")
    if "ECC" in key_type.upper():
        pqc_info = PQC_MIGRATION_MAP.get("ECC")
    elif "DSA" in key_type.upper():
        pqc_info = PQC_MIGRATION_MAP.get("DSA")

    # Determine affected components using graph
    G = build_dependency_graph(db_path)
    service_id = asset_dict.get("linked_service_id")
    service_name = asset_dict.get("service_name") or "Unlinked Service"

    affected_components = []
    if service_id:
        affected_components = get_affected_dependents(service_id, G)

    total_blast_radius = len(affected_components) + (1 if service_name else 0)

    if total_blast_radius <= 2:
        complexity = "Low"
    elif total_blast_radius <= 4:
        complexity = "Medium"
    else:
        complexity = "High"

    return {
        "asset_id": asset_id,
        "host": asset_dict["host"],
        "port": asset_dict["port"],
        "current_algorithm": f"{key_type} ({asset_dict.get('cert_key_size_bits') or 'Unknown'} bits)",
        "quantum_status": "Vulnerable to CRQC (Shor's Algorithm)" if "RSA" in key_type or "ECC" in key_type else "Quantum-Resistant",
        "service_name": service_name,
        "service_criticality": asset_dict.get("service_criticality") or "P2",
        "recommended_replacement": pqc_info["replacement"],
        "standards": pqc_info["standards"],
        "hybrid_mode": pqc_info["hybrid_recommended"],
        "migration_notes": pqc_info["migration_notes"],
        "affected_dependent_services": affected_components,
        "blast_radius_count": total_blast_radius,
        "migration_complexity": complexity,
    }


def recommend_migration_order(db_path=DEFAULT_DB_PATH) -> list:
    """
    Orders ALL vulnerable assets by recommended migration sequence:
    Prioritizes high MWQRS risk score first, with low blast radius as tie-breaker
    (fix highest-risk, lowest blast radius assets first).
    """
    assets = get_all_assets(db_path)
    G = build_dependency_graph(db_path)

    sequence = []
    for a in assets:
        sim = simulate_migration(a["id"], db_path)
        risk_score = a.get("risk_score") or 0.0
        blast_radius = sim.get("blast_radius_count", 1)

        # Priority score: Higher risk score = earlier sequence, lower blast radius = earlier
        priority_key = (risk_score, -blast_radius)

        sequence.append({
            "sequence_position": 0,
            "asset_id": a["id"],
            "host": f"{a['host']}:{a['port']}",
            "service_name": sim.get("service_name"),
            "risk_score": risk_score,
            "current_algo": sim.get("current_algorithm"),
            "target_pqc": sim.get("recommended_replacement"),
            "complexity": sim.get("migration_complexity"),
            "affected_count": len(sim.get("affected_dependent_services", [])),
            "priority_key": priority_key
        })

    # Sort descending by risk score, then ascending by blast radius
    sequence.sort(key=lambda x: (x["risk_score"], -x["affected_count"]), reverse=True)

    for idx, item in enumerate(sequence, 1):
        item["sequence_position"] = idx
        del item["priority_key"]

    return sequence


def apply_pqc_remediation(asset_id: int, db_path=DEFAULT_DB_PATH):
    """
    Remediates an asset by upgrading its key type to NIST ML-KEM-768 / ML-DSA-65 (PQC),
    updating its risk flags and recalculating system MWQRS scores.
    """
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE crypto_assets
        SET cert_key_type = 'ML-KEM-768 (PQC)',
            cert_key_size_bits = 768,
            days_to_expiry = 365,
            risk_flags = '["PQC_MIGRATED:ML-KEM-768", "QUANTUM_SAFE"]'
        WHERE id = ?
    """, (asset_id,))
    conn.commit()
    conn.close()

    from ecdat_scoring import score_all_assets
    score_all_assets(db_path)


if __name__ == "__main__":
    assets = get_all_assets()
    if assets:
        target_id = assets[0]["id"]
        res = simulate_migration(target_id)
        print(f"Simulation for Asset {target_id} ({res['host']}:{res['port']}):")
        print(json.dumps(res, indent=2))
        print("\nRecommended Migration Roadmap:")
        roadmap = recommend_migration_order()
        for step in roadmap:
            print(f" #{step['sequence_position']} | {step['host']} | Risk: {step['risk_score']} | Replacement: {step['target_pqc']} | Complexity: {step['complexity']}")
