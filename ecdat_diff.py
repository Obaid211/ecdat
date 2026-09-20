"""
ECDAT — 24-Hour Rescan & Diff-Based Alerting Engine
----------------------------------------------------
Implements scan snapshot comparison and diff detection across rescan cycles:
  - Assets added / removed
  - Cryptographic attribute changes (algorithm, key size, TLS version)
  - MWQRS quantum risk score deltas (increased / decreased)
  - Certificate expiry shifts (approaching expiry / expired)
  - Human-readable diff alert generation
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import json
import ecdat_inventory as inv


def compare_snapshots(
    old_snapshot_id: int,
    new_snapshot_id: int,
    db_path: str = inv.DEFAULT_DB_PATH
) -> Dict[str, Any]:
    """
    Compares two database snapshots and computes an exact cryptographic diff.
    """
    old_snap = inv.get_snapshot_by_id(old_snapshot_id, db_path)
    new_snap = inv.get_snapshot_by_id(new_snapshot_id, db_path)

    if not old_snap or not new_snap:
        return {
            "error": "One or both snapshots could not be found.",
            "old_id": old_snapshot_id,
            "new_id": new_snapshot_id,
        }

    old_assets = {f"{a['host']}:{a['port']}": a for a in old_snap.get("assets", [])}
    new_assets = {f"{a['host']}:{a['port']}": a for a in new_snap.get("assets", [])}

    old_keys = set(old_assets.keys())
    new_keys = set(new_assets.keys())

    added_keys = new_keys - old_keys
    removed_keys = old_keys - new_keys
    shared_keys = old_keys & new_keys

    added = [new_assets[k] for k in sorted(added_keys)]
    removed = [old_assets[k] for k in sorted(removed_keys)]

    modified = []
    alerts = []
    risk_increased_count = 0
    risk_decreased_count = 0
    newly_expiring_count = 0

    for key in sorted(shared_keys):
        o = old_assets[key]
        n = new_assets[key]

        changes = []
        old_mwqrs = float(o.get("mwqrs") or 0.0)
        new_mwqrs = float(n.get("mwqrs") or 0.0)
        mwqrs_delta = round(new_mwqrs - old_mwqrs, 1)

        # Algorithm change
        if str(o.get("algorithm")) != str(n.get("algorithm")):
            changes.append({
                "property": "Algorithm",
                "old": o.get("algorithm"),
                "new": n.get("algorithm"),
            })

        # Key size change
        if str(o.get("key_size")) != str(n.get("key_size")):
            changes.append({
                "property": "Key Size",
                "old": o.get("key_size"),
                "new": n.get("key_size"),
            })

        # TLS version change
        if str(o.get("tls_version")) != str(n.get("tls_version")):
            changes.append({
                "property": "TLS Version",
                "old": o.get("tls_version"),
                "new": n.get("tls_version"),
            })

        # Expiry change
        old_exp = o.get("days_to_expiry")
        new_exp = n.get("days_to_expiry")
        if old_exp != new_exp and new_exp is not None:
            if new_exp <= 30 and (old_exp is None or old_exp > 30):
                newly_expiring_count += 1
                changes.append({
                    "property": "Certificate Expiry (Warning)",
                    "old": f"{old_exp}d remaining",
                    "new": f"{new_exp}d remaining (Approaching Expiry!)",
                })

        # Risk score delta
        if abs(mwqrs_delta) >= 0.1:
            if mwqrs_delta > 0:
                risk_increased_count += 1
            else:
                risk_decreased_count += 1
            changes.append({
                "property": "MWQRS Risk Score",
                "old": old_mwqrs,
                "new": new_mwqrs,
                "delta": mwqrs_delta,
            })

        if changes:
            mod_record = {
                "target": key,
                "host": n.get("host"),
                "port": n.get("port"),
                "service": n.get("service"),
                "criticality": n.get("service_criticality"),
                "old_mwqrs": old_mwqrs,
                "new_mwqrs": new_mwqrs,
                "mwqrs_delta": mwqrs_delta,
                "changes": changes,
            }
            modified.append(mod_record)

            # Generate plain-English alert
            alert_lines = [f"CHANGE DETECTED on **{key}** ({n.get('service')})"]
            for c in changes:
                if "delta" in c:
                    sym = "+" if c["delta"] > 0 else ""
                    alert_lines.append(f"  - {c['property']}: {c['old']} → {c['new']} (Delta: {sym}{c['delta']})")
                else:
                    alert_lines.append(f"  - {c['property']}: {c['old']} → {c['new']}")
            alerts.append("\n".join(alert_lines))

    # Alert for added assets
    for a in added:
        alerts.append(
            f"NEW ASSET DISCOVERED: **{a['host']}:{a['port']}** ({a['service']}) — "
            f"{a['algorithm']} ({a['key_size']}b), MWQRS: {a['mwqrs']}"
        )

    # Alert for removed assets
    for a in removed:
        alerts.append(
            f"ASSET NO LONGER OBSERVED: **{a['host']}:{a['port']}** ({a['service']}) — "
            f"Previous MWQRS: {a['mwqrs']}"
        )

    return {
        "old_snapshot": {
            "id": old_snap["id"],
            "name": old_snap["name"],
            "created_at": old_snap["created_at"],
            "asset_count": old_snap["asset_count"],
            "avg_risk": old_snap["avg_risk"],
        },
        "new_snapshot": {
            "id": new_snap["id"],
            "name": new_snap["name"],
            "created_at": new_snap["created_at"],
            "asset_count": new_snap["asset_count"],
            "avg_risk": new_snap["avg_risk"],
        },
        "summary": {
            "assets_added": len(added),
            "assets_removed": len(removed),
            "assets_modified": len(modified),
            "risk_increased_count": risk_increased_count,
            "risk_decreased_count": risk_decreased_count,
            "newly_expiring_count": newly_expiring_count,
            "net_asset_delta": len(new_keys) - len(old_keys),
            "avg_risk_delta": round((new_snap["avg_risk"] or 0.0) - (old_snap["avg_risk"] or 0.0), 1),
        },
        "added": added,
        "removed": removed,
        "modified": modified,
        "alerts": alerts,
    }


def export_diff_markdown(diff_res: Dict[str, Any]) -> str:
    """Exports snapshot comparison as a formatted markdown report."""
    if "error" in diff_res:
        return f"# Diff Comparison Error\n\n{diff_res['error']}"

    s = diff_res["summary"]
    old_s = diff_res["old_snapshot"]
    new_s = diff_res["new_snapshot"]

    lines = [
        "# ECDAT Cryptographic Rescan Diff & Alert Report",
        "",
        f"**Baseline Snapshot:** #{old_s['id']} ({old_s['name']}, {old_s['created_at']})  ",
        f"**Comparison Snapshot:** #{new_s['id']} ({new_s['name']}, {new_s['created_at']})  ",
        "",
        "---",
        "",
        "## Summary Metrics",
        f"- **Assets Added:** +{s['assets_added']}",
        f"- **Assets Removed:** -{s['assets_removed']}",
        f"- **Assets Modified:** {s['assets_modified']}",
        f"- **Risk Increased Assets:** +{s['risk_increased_count']}",
        f"- **Risk Decreased Assets:** -{s['risk_decreased_count']}",
        f"- **Approaching Expiry:** {s['newly_expiring_count']}",
        f"- **Net Average MWQRS Delta:** {'+' if s['avg_risk_delta'] > 0 else ''}{s['avg_risk_delta']}",
        "",
        "---",
        "",
        "## Diff Alerts",
    ]

    if diff_res["alerts"]:
        for a in diff_res["alerts"]:
            lines.append(f"> [!WARNING]\n> {a}\n")
    else:
        lines.append("No cryptographic regressions or structural changes detected between snapshots.")

    return "\n".join(lines)
