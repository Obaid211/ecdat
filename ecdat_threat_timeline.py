"""
ECDAT — Threat-Timeline & Migration Urgency Engine
---------------------------------------------------
Implements a Mosca-inspired migration urgency evaluation framework:
    Required Preparation Window = Data Security Shelf-Life (Y) + Migration Effort (X)
    Planning Horizon Assumption = Estimated Available Preparation Window (Z)

Important Principle:
This module does NOT predict the arrival year of a Cryptographically Relevant
Quantum Computer (CRQC). It provides an engineering urgency framework based on
Mosca's Rule: if the time needed to secure and preserve data exceeds the
organizational planning horizon (X + Y > Z), cryptographic transition planning
must begin immediately to avoid retrospective harvest-now-decrypt-later (HNDL) exposure.
"""

from typing import Dict, Any, List
import ecdat_inventory as inv


DATA_SENSITIVITY_PROFILES = {
    "Public / Non-Sensitive": {
        "description": "Public documentation, non-sensitive landing pages",
        "default_shelf_life_years": 1.0,
        "default_migration_time_years": 1.0,
        "urgency_weight": 0.8,
    },
    "Standard Operational (P2/P3)": {
        "description": "Routine business logs, staff telemetry, internal portals",
        "default_shelf_life_years": 3.0,
        "default_migration_time_years": 2.0,
        "urgency_weight": 1.0,
    },
    "Confidential / PII (P1)": {
        "description": "Citizen records, financial transactions, healthcare data",
        "default_shelf_life_years": 10.0,
        "default_migration_time_years": 3.0,
        "urgency_weight": 1.3,
    },
    "Critical / National Security (P0)": {
        "description": "Core identity databases, cryptographic root keys, sovereign infrastructure",
        "default_shelf_life_years": 20.0,
        "default_migration_time_years": 4.0,
        "urgency_weight": 1.5,
    },
}


def calculate_migration_urgency(
    shelf_life_years: float,
    migration_time_years: float,
    planning_horizon_years: float = 10.0,
    data_sensitivity: str = "Confidential / PII (P1)",
    asset_mwqrs: float = 70.0,
    is_quantum_vulnerable: bool = True,
    asset_name: str = "Selected Asset"
) -> Dict[str, Any]:
    """
    Evaluates migration urgency using the Mosca-inspired equation:
        Combined Requirement = Shelf Life (Y) + Migration Time (X)
        Deficit/Margin = Planning Horizon (Z) - (X + Y)
    """
    shelf_life = max(0.0, float(shelf_life_years))
    mig_time = max(0.1, float(migration_time_years))
    horizon = max(1.0, float(planning_horizon_years))
    
    combined_requirement = round(shelf_life + mig_time, 1)
    margin = round(horizon - combined_requirement, 1)
    
    if not is_quantum_vulnerable:
        urgency_level = "LOW / SECURED"
        color = "green"
        summary_reason = (
            f"Asset uses quantum-resistant or already-migrated cryptography. "
            f"No immediate vulnerability to Shor's algorithm on a future CRQC."
        )
        recommendation = "Maintain current posture; continue routine cryptographic hygiene and monitoring."
    elif combined_requirement > horizon:
        urgency_level = "CRITICAL"
        color = "red"
        deficit = abs(margin)
        summary_reason = (
            f"Combined protection requirement ({combined_requirement} years: {shelf_life}y shelf-life + "
            f"{mig_time}y migration) exceeds the organizational planning assumption ({horizon} years) "
            f"by {deficit} year(s). High exposure to Harvest-Now-Decrypt-Later (HNDL) risk."
        )
        recommendation = (
            "Initiate hybrid PQC migration planning immediately. Prioritize cryptographic agility "
            "and identify key encapsulation (ML-KEM) transition points."
        )
    elif margin <= 2.0 or asset_mwqrs >= 80.0:
        urgency_level = "HIGH"
        color = "orange"
        summary_reason = (
            f"Combined requirement ({combined_requirement} years) leaves very narrow headroom "
            f"({margin} years) against the {horizon}-year planning assumption. "
            f"Combined with high asset MWQRS ({asset_mwqrs}), timely action is required."
        )
        recommendation = (
            "Schedule PQC remediation in the current architectural roadmap. Prepare dual-certificate "
            "or hybrid classical-PQC testing."
        )
    elif margin <= 5.0 or asset_mwqrs >= 50.0:
        urgency_level = "MEDIUM"
        color = "yellow"
        summary_reason = (
            f"Combined requirement ({combined_requirement} years) is within the planning horizon "
            f"({horizon} years) with {margin} years margin, but moderate risk indicators warrant planning."
        )
        recommendation = "Catalogue dependencies and evaluate NIST FIPS 203/204 migration paths in next cycle."
    else:
        urgency_level = "LOW"
        color = "green"
        summary_reason = (
            f"Short data shelf-life ({shelf_life} years) and rapid migration timeline ({mig_time} years) "
            f"provide comfortable margin ({margin} years) under current planning assumptions."
        )
        recommendation = "Standard periodic review; no emergency re-architecture necessary."

    return {
        "asset_name": asset_name,
        "data_sensitivity": data_sensitivity,
        "shelf_life_years": shelf_life,
        "migration_time_years": mig_time,
        "combined_requirement_years": combined_requirement,
        "planning_horizon_years": horizon,
        "margin_or_deficit_years": margin,
        "is_deficit": combined_requirement > horizon,
        "urgency_level": urgency_level,
        "color": color,
        "summary_reason": summary_reason,
        "recommended_action": recommendation,
        "framework_disclaimer": (
            "Mosca-inspired migration urgency framework. Reflects organizational planning "
            "assumptions, NOT an astronomical or guaranteed date for quantum computing capability."
        ),
    }


def evaluate_inventory_threat_urgency(
    db_path: str = inv.DEFAULT_DB_PATH,
    planning_horizon_years: float = 10.0
) -> List[Dict[str, Any]]:
    """
    Evaluates threat-timeline urgency across all assets in the database based on
    their service criticality and detected cryptographic properties.
    """
    assets = inv.get_normalized_inventory(db_path)
    evaluations = []

    for a in assets:
        crit = a.get("service_criticality") or "P2"
        if crit == "P0":
            sens_profile = "Critical / National Security (P0)"
            shelf_life = 15.0
            mig_time = 3.5
        elif crit == "P1":
            sens_profile = "Confidential / PII (P1)"
            shelf_life = 10.0
            mig_time = 2.5
        elif crit == "P2":
            sens_profile = "Standard Operational (P2/P3)"
            shelf_life = 4.0
            mig_time = 1.5
        else:
            sens_profile = "Public / Non-Sensitive"
            shelf_life = 1.0
            mig_time = 1.0

        is_qv = "Quantum-Vulnerable" in a.get("quantum_status", "")
        mwqrs = a.get("mwqrs", 0.0)
        label = f"{a['host']}:{a['port']} ({a['service']})"

        res = calculate_migration_urgency(
            shelf_life_years=shelf_life,
            migration_time_years=mig_time,
            planning_horizon_years=planning_horizon_years,
            data_sensitivity=sens_profile,
            asset_mwqrs=mwqrs,
            is_quantum_vulnerable=is_qv,
            asset_name=label
        )
        res["asset_id"] = a["asset_id"]
        res["service"] = a["service"]
        res["criticality"] = crit
        res["mwqrs"] = mwqrs
        res["algorithm"] = a["algorithm"]
        evaluations.append(res)

    # Sort: CRITICAL first, then HIGH, then MEDIUM, then LOW
    urgency_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "LOW / SECURED": 0}
    evaluations.sort(key=lambda x: (urgency_rank.get(x["urgency_level"], 0), x["mwqrs"]), reverse=True)
    return evaluations
