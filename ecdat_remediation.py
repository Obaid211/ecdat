"""
ECDAT — Remediation Center & Priority Sequencing Engine
--------------------------------------------------------
Generates actionable, explainable cryptographic remediation plans.
Prioritizes remediation sequencing based on multi-factor analysis:
  - Actual MWQRS risk score
  - Service operational criticality (P0/P1/P2/P3)
  - Certificate expiry deadline (<0 expired, <=30 days urgent)
  - Dependency graph blast radius (downstream service impact)
"""

from typing import List, Dict, Any
import json
import ecdat_inventory as inv
import ecdat_simulator as sim_eng


def generate_remediation_plan(db_path: str = inv.DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    """
    Builds an explainable, multi-factor prioritized remediation sequence.
    Explanations and recommended actions are dynamically derived from actual
    asset properties, certificate states, and dependency linkages.
    """
    assets = inv.get_normalized_inventory(db_path)
    if not assets:
        return []

    # Build dependency graph for blast-radius impact
    G = sim_eng.build_dependency_graph(db_path)

    scored_items = []
    for a in assets:
        mwqrs = float(a.get("mwqrs", 0.0))
        crit = a.get("service_criticality") or "P2"
        flags = a.get("risk_flags") or []
        days_exp = a.get("days_to_expiry")
        key_type = (a.get("algorithm") or "Unknown").upper()
        key_size = a.get("key_size")
        service_name = a.get("service") or "Unassigned"

        # Determine downstream blast radius
        conn = inv.get_db_connection(db_path)
        cur = conn.cursor()
        cur.execute("SELECT id FROM services WHERE name = ?", (service_name,))
        s_row = cur.fetchone()
        conn.close()

        downstream = []
        if s_row:
            downstream = sim_eng.get_affected_dependents(s_row["id"], G)
        blast_count = len(downstream)

        # Multi-factor priority scoring index
        # 1. Base MWQRS (0 - 100)
        priority_index = mwqrs * 1.0

        # 2. Criticality bonus
        crit_boost = {"P0": 25.0, "P1": 15.0, "P2": 5.0, "P3": 0.0}.get(crit, 0.0)
        priority_index += crit_boost

        # 3. Expiry urgency bonus
        expiry_urgency = False
        if days_exp is not None:
            if days_exp < 0:
                priority_index += 40.0
                expiry_urgency = True
            elif days_exp <= 30:
                priority_index += 25.0
                expiry_urgency = True
            elif days_exp <= 90:
                priority_index += 10.0

        # 4. Blast radius weighting
        priority_index += min(20.0, blast_count * 4.0)

        # 5. Weak key size bonus
        weak_key = False
        if "RSA" in key_type and isinstance(key_size, int) and key_size < 2048:
            priority_index += 20.0
            weak_key = True

        # Generate transparent explanation ("Why it was prioritized")
        reasons = []
        if mwqrs >= 80.0:
            reasons.append(f"Critical MWQRS quantum risk score ({mwqrs}/100)")
        elif mwqrs >= 50.0:
            reasons.append(f"Elevated MWQRS score ({mwqrs}/100)")

        if crit in ["P0", "P1"]:
            reasons.append(f"Mission-critical tier ({crit} - {service_name})")

        if days_exp is not None:
            if days_exp < 0:
                reasons.append(f"Certificate is ALREADY EXPIRED ({abs(days_exp)} days ago)")
            elif days_exp <= 30:
                reasons.append(f"Certificate expires urgently in {days_exp} days")
            elif days_exp <= 90:
                reasons.append(f"Certificate expiring within standard renewal window ({days_exp} days)")

        if weak_key:
            reasons.append(f"Sub-standard RSA key length ({key_size}-bit < 2048-bit NIST threshold)")

        if any("OUTDATED_TLS" in str(f) for f in flags):
            reasons.append(f"Deprecated TLS protocol version ({a.get('tls_version')})")

        if blast_count > 0:
            reasons.append(f"Affects {blast_count} downstream dependent service(s)")

        if not reasons:
            reasons.append("Routine cryptographic hygiene and quantum readiness planning")

        why_prioritized = "; ".join(reasons) + "."

        # Generate actionable recommended actions
        actions = []
        if days_exp is not None and days_exp <= 30:
            actions.append("Immediate: Renew/replace TLS certificate before service outage or trust warnings occur.")

        if weak_key:
            actions.append("Short-Term: Re-issue certificate with at least RSA-2048 or RSA-3072 to meet baseline classical standards.")

        if any("OUTDATED_TLS" in str(f) for f in flags):
            actions.append("Configuration: Disable TLS 1.0/1.1 on server; enforce TLS 1.2 or TLS 1.3 only.")

        if "RSA" in key_type:
            actions.append("PQC Roadmap: Deploy dual-mode hybrid TLS certificate (RSA-3072 + ML-KEM-768 per NIST FIPS 203).")
            migration_direction = "Classical RSA → Hybrid Classical + ML-KEM-768 → Pure NIST FIPS 203"
        elif "ECC" in key_type or "ECDSA" in key_type:
            actions.append("PQC Roadmap: Evaluate transition to ML-DSA-65 (NIST FIPS 204) or SLH-DSA (FIPS 205) for digital signatures.")
            migration_direction = "Classical ECC → Hybrid ECDSA + ML-DSA-65 → Pure NIST FIPS 204"
        elif "ML-" in key_type:
            actions.append("Verification: Verify PQC implementation against final FIPS 203/204 standard benchmarks.")
            migration_direction = "Already PQC-Migrated (Maintain Compliance)"
        else:
            actions.append("Review: Audit application cipher suite configuration and eliminate legacy algorithms.")
            migration_direction = "Legacy Classical → Modern Classical → Hybrid PQC"

        if blast_count > 0:
            actions.append(f"Coordination: Notify downstream teams for {', '.join(downstream)} before certificate rollover.")

        item = {
            "priority_rank": 0,
            "asset_id": a["asset_id"],
            "target": f"{a['host']}:{a['port']}",
            "host": a["host"],
            "port": a["port"],
            "service": service_name,
            "criticality": crit,
            "algorithm": a["algorithm"],
            "key_size": key_size,
            "tls_version": a["tls_version"],
            "mwqrs": mwqrs,
            "severity": a["severity"],
            "certificate_expiry": a["cert_expiry"],
            "days_to_expiry": days_exp,
            "priority_index": priority_index,
            "why_prioritized": why_prioritized,
            "recommended_actions": actions,
            "migration_direction": migration_direction,
            "dependency_impact": f"{blast_count} downstream service(s)" if blast_count > 0 else "Self-contained / 0 downstream",
            "downstream_services": downstream,
        }
        scored_items.append(item)

    # Sort descending by computed priority index
    scored_items.sort(key=lambda x: x["priority_index"], reverse=True)

    for rank, item in enumerate(scored_items, 1):
        item["priority_rank"] = rank

    return scored_items


def export_remediation_markdown(plan: List[Dict[str, Any]]) -> str:
    """Generates an executive markdown report of the remediation sequence."""
    lines = [
        "# ECDAT Cryptographic Remediation & Migration Plan",
        "",
        "**Generated by:** ECDAT — Enterprise Cryptographic Discovery & Analysis Tool  ",
        "**Prioritization Methodology:** MWQRS Quantum Risk Score + Service Criticality + Expiry Urgency + Graph Blast Radius  ",
        "",
        "---",
        "",
    ]

    for item in plan:
        lines.append(f"### #{item['priority_rank']} — {item['target']} ({item['service']})")
        lines.append(f"- **Criticality Tier:** {item['criticality']} | **MWQRS Risk:** {item['mwqrs']}/100 ({item['severity']})")
        lines.append(f"- **Current Cryptography:** {item['algorithm']} ({item['key_size']}-bit) | **TLS:** {item['tls_version']}")
        lines.append(f"- **Certificate Expiry:** {item['certificate_expiry']} ({item['days_to_expiry']} days remaining)")
        lines.append(f"- **Dependency Impact:** {item['dependency_impact']}")
        lines.append(f"- **Why Prioritized:** {item['why_prioritized']}")
        lines.append(f"- **Migration Direction:** `{item['migration_direction']}`")
        lines.append("- **Recommended Remediation Actions:**")
        for act in item["recommended_actions"]:
            lines.append(f"  - {act}")
        lines.append("")

    return "\n".join(lines)


def export_remediation_json(plan: List[Dict[str, Any]]) -> str:
    """Exports the remediation plan as formatted JSON."""
    return json.dumps(plan, indent=2, default=str)
