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
from ecdat_inventory import DEFAULT_DB_PATH, get_db_connection, get_all_assets, init_db


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


MIGRATION_STRATEGIES = {
    "HYBRID": {
        "name": "Hybrid Classical + PQC (Recommended Transition Mode)",
        "description": "Deploys a composite or dual certificate combining classical cryptography (for backwards compatibility) with NIST PQC algorithms (for quantum resistance).",
        "standard_reference": "NIST SP 800-227 / RFC 9370 / IETF draft-ietf-tls-hybrid-design",
    },
    "PURE_PQC": {
        "name": "Pure Post-Quantum (FIPS 203 / FIPS 204)",
        "description": "Full replacement of classical asymmetric algorithms with finalized NIST standards. Best for greenfield and high-security internal services.",
        "standard_reference": "NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)",
    },
    "CLASSICAL_HARDENING": {
        "name": "Classical Hardening (Interim Interim Step)",
        "description": "Increases classical key lengths (e.g. RSA-1024 -> RSA-3072+) and upgrades to TLS 1.3 while planning full PQC transition.",
        "standard_reference": "NIST SP 800-52 Rev. 2 (Classical Interim Baseline)",
    }
}


def simulate_migration(asset_id: int, db_path=DEFAULT_DB_PATH, strategy: str = "HYBRID") -> dict:
    """
    Simulates PQC migration for a given asset ID under a chosen migration strategy.
    Returns recommendation details, affected components, complexity rating,
    and a clear BEFORE vs AFTER comparison state.

    Labeled: Migration simulation model (does NOT claim to deploy live production crypto).
    """
    init_db(db_path)
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
    key_type = (asset_dict.get("cert_key_type") or "RSA").strip()
    key_size = asset_dict.get("cert_key_size_bits") or "Unknown"
    current_mwqrs = float(asset_dict.get("risk_score") or 0.0)
    tls_v = asset_dict.get("tls_version") or "Unknown"

    # Base PQC mapping (preserved for backward compatibility)
    pqc_info = PQC_MIGRATION_MAP.get("RSA")
    if "ECC" in key_type.upper():
        pqc_info = PQC_MIGRATION_MAP.get("ECC")
    elif "DSA" in key_type.upper():
        pqc_info = PQC_MIGRATION_MAP.get("DSA")

    # Granular KEM vs Signature categorization per Capability 4 & 9
    is_rsa = "RSA" in key_type.upper()
    is_ecc = "ECC" in key_type.upper() or "ECDSA" in key_type.upper()

    if is_rsa:
        kem_direction = "NIST FIPS 203: ML-KEM-768 (Kyber)"
        sig_direction = "NIST FIPS 204: ML-DSA-65 (Dilithium)"
        hybrid_strategy = "Dual Classical RSA-3072 + ML-KEM-768 / ML-DSA-65"
    elif is_ecc:
        kem_direction = "Hybrid ECDH + NIST FIPS 203: ML-KEM-768"
        sig_direction = "NIST FIPS 204: ML-DSA-65 or NIST FIPS 205: SLH-DSA-128s"
        hybrid_strategy = "Hybrid ECDSA (P-384) + ML-DSA-65 (FIPS 204)"
    else:
        kem_direction = "NIST FIPS 203: ML-KEM-768"
        sig_direction = "NIST FIPS 204: ML-DSA-65"
        hybrid_strategy = "Classical + ML-KEM / ML-DSA Dual Stack"

    strat_choice = strategy.upper()
    if strat_choice == "PURE_PQC":
        rec_replacement = f"Pure {kem_direction} (KEM) & {sig_direction} (Sig)"
        sim_algo = "ML-KEM-768 / ML-DSA-65 (NIST FIPS 203/204)"
        sim_key_size = "768-bit (KEM) / 1952-byte (Sig)"
        sim_mwqrs = 10.0 if "P0" in (asset_dict.get("service_criticality") or "") else 5.0
        sim_qv_status = "Quantum-Resistant (NIST PQC Final Standards)"
        sim_notes = "Pure PQC transition eliminates classical vulnerability to Shor's algorithm. Requires modern TLS client support."
    elif strat_choice == "CLASSICAL_HARDENING":
        rec_replacement = "Hardened Classical RSA-3072 / ECC P-384 with TLS 1.3"
        sim_algo = f"Classical {key_type} (Hardened)"
        sim_key_size = "3072 bits"
        sim_mwqrs = round(max(current_mwqrs * 0.65, 30.0), 1)
        sim_qv_status = "Vulnerable to future CRQC (Shor's Algorithm) — Interim Classical Hardening"
        sim_notes = "Increases classical cryptographic safety factor; does NOT protect against future CRQC. PQC migration still required."
    else:  # HYBRID (default)
        rec_replacement = f"Hybrid Mode: {hybrid_strategy}"
        sim_algo = f"Hybrid Composite: {key_type}-{key_size} + ML-KEM-768"
        sim_key_size = f"{key_size}b Classical + 768b PQC"
        sim_mwqrs = 20.0 if "P0" in (asset_dict.get("service_criticality") or "") else 12.0
        sim_qv_status = "Hybrid Protected (Classical Backwards-Compatible + PQC Secured)"
        sim_notes = "Recommended transition approach: protects confidential traffic against HNDL while preserving interoperability with legacy clients."

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

    before_state = {
        "algorithm": f"{key_type} ({key_size} bits)",
        "algorithm_family": key_type,
        "key_size": key_size,
        "mwqrs_score": current_mwqrs,
        "quantum_status": "Vulnerable to CRQC (Shor's Algorithm)" if (is_rsa or is_ecc) else "Quantum-Resistant",
        "tls_version": tls_v,
        "certificate_expiry_days": asset_dict.get("days_to_expiry"),
    }

    after_state = {
        "strategy_applied": MIGRATION_STRATEGIES.get(strat_choice, {}).get("name", strat_choice),
        "algorithm": sim_algo,
        "key_size": sim_key_size,
        "simulated_mwqrs_score": sim_mwqrs,
        "risk_reduction": round(current_mwqrs - sim_mwqrs, 1),
        "quantum_status": sim_qv_status,
        "tls_version": "TLSv1.3 (Hybrid Enabled)",
        "notes": sim_notes,
    }

    return {
        "asset_id": asset_id,
        "host": asset_dict["host"],
        "port": asset_dict["port"],
        "current_algorithm": f"{key_type} ({key_size} bits)",
        "quantum_status": before_state["quantum_status"],
        "service_name": service_name,
        "service_criticality": asset_dict.get("service_criticality") or "P2",
        "recommended_replacement": rec_replacement,
        "standards": pqc_info["standards"],
        "hybrid_mode": pqc_info["hybrid_recommended"],
        "migration_notes": pqc_info["migration_notes"],
        "kem_replacement": kem_direction,
        "signature_replacement": sig_direction,
        "hybrid_modeling": hybrid_strategy,
        "affected_dependent_services": affected_components,
        "blast_radius_count": total_blast_radius,
        "migration_complexity": complexity,
        "before_state": before_state,
        "after_state": after_state,
        "is_simulation": True,
        "simulation_label": "Migration Simulation Model — Architectural Transition Projection (no production change deployed)",
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
