"""
ECDAT - Stage 3: Cryptographic Inventory & CBOM Persistence
-------------------------------------------------------------
Persists TLS scan results, service metadata, and dependency linkages into
a SQLite database ('ecdat.db') and exports CycloneDX Cryptographic Bill
of Materials (CBOM) JSON format.
"""

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_DB_PATH = "ecdat.db"


def get_db_connection(db_path=DEFAULT_DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path=DEFAULT_DB_PATH):
    """Creates database tables if they do not exist."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    # Table: services
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS services (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        criticality TEXT CHECK(criticality IN ('P0','P1','P2','P3')),
        description TEXT
    );
    """)

    # Table: service_dependencies
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS service_dependencies (
        service_id INTEGER,
        depends_on_service_id INTEGER,
        PRIMARY KEY (service_id, depends_on_service_id),
        FOREIGN KEY (service_id) REFERENCES services(id),
        FOREIGN KEY (depends_on_service_id) REFERENCES services(id)
    );
    """)

    # Table: crypto_assets
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS crypto_assets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host TEXT NOT NULL,
        port INTEGER NOT NULL,
        scanned_at TIMESTAMP,
        status TEXT,
        tls_version TEXT,
        cipher_suite TEXT,
        cipher_bits INTEGER,
        cert_subject TEXT,
        cert_issuer TEXT,
        cert_key_type TEXT,
        cert_key_size_bits INTEGER,
        cert_signature_algorithm TEXT,
        cert_not_after TIMESTAMP,
        days_to_expiry INTEGER,
        risk_flags TEXT,
        risk_score REAL DEFAULT 0.0,
        linked_service_id INTEGER,
        FOREIGN KEY (linked_service_id) REFERENCES services(id),
        UNIQUE(host, port)
    );
    """)

    # Table: crypto_assets_history
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS crypto_assets_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host TEXT NOT NULL,
        port INTEGER NOT NULL,
        scanned_at TIMESTAMP,
        status TEXT,
        tls_version TEXT,
        cert_key_type TEXT,
        cert_key_size_bits INTEGER,
        risk_flags TEXT,
        risk_score REAL
    );
    """)

    # Table: code_findings
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS code_findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_path TEXT NOT NULL,
        line_number INTEGER NOT NULL,
        rule_id TEXT NOT NULL,
        finding_type TEXT NOT NULL,
        code_snippet TEXT,
        severity TEXT,
        scanned_at TIMESTAMP,
        UNIQUE(file_path, line_number, rule_id)
    );
    """)

    conn.commit()
    conn.close()


def ingest_scan_results(json_file_path, db_path=DEFAULT_DB_PATH):
    """Reads Stage 1/2 JSON output and inserts or updates records in crypto_assets."""
    init_db(db_path)
    path = Path(json_file_path)
    if not path.exists():
        raise FileNotFoundError(f"Scan file not found: {json_file_path}")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict):
        data = [data]

    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    inserted_count = 0

    for item in data:
        host = item.get("host")
        port = item.get("port", 443)
        scanned_at = item.get("scanned_at")
        status = item.get("status", "unknown")
        tls_version = item.get("tls_version")
        cipher_suite = item.get("cipher_suite")
        cipher_bits = item.get("cipher_bits")
        cert_subject = item.get("cert_subject")
        cert_issuer = item.get("cert_issuer")
        cert_key_type = item.get("cert_key_type")
        cert_key_size_bits = item.get("cert_key_size_bits")
        cert_signature_algorithm = item.get("cert_signature_algorithm")
        cert_not_after = item.get("cert_not_after")
        days_to_expiry = item.get("days_to_expiry")
        risk_flags = item.get("risk_flags", [])

        if isinstance(risk_flags, list):
            risk_flags_str = json.dumps(risk_flags)
        else:
            risk_flags_str = str(risk_flags)

        cursor.execute("""
            INSERT INTO crypto_assets_history (
                host, port, scanned_at, status, tls_version,
                cert_key_type, cert_key_size_bits, risk_flags
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            host, port, scanned_at, status, tls_version,
            cert_key_type, cert_key_size_bits, risk_flags_str
        ))

        cursor.execute("""
        INSERT INTO crypto_assets (
            host, port, scanned_at, status, tls_version, cipher_suite, cipher_bits,
            cert_subject, cert_issuer, cert_key_type, cert_key_size_bits,
            cert_signature_algorithm, cert_not_after, days_to_expiry, risk_flags
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(host, port) DO UPDATE SET
            scanned_at=excluded.scanned_at,
            status=excluded.status,
            tls_version=excluded.tls_version,
            cipher_suite=excluded.cipher_suite,
            cipher_bits=excluded.cipher_bits,
            cert_subject=excluded.cert_subject,
            cert_issuer=excluded.cert_issuer,
            cert_key_type=excluded.cert_key_type,
            cert_key_size_bits=excluded.cert_key_size_bits,
            cert_signature_algorithm=excluded.cert_signature_algorithm,
            cert_not_after=excluded.cert_not_after,
            days_to_expiry=excluded.days_to_expiry,
            risk_flags=excluded.risk_flags;
        """, (
            host, port, scanned_at, status, tls_version, cipher_suite, cipher_bits,
            cert_subject, cert_issuer, cert_key_type, cert_key_size_bits,
            cert_signature_algorithm, cert_not_after, days_to_expiry, risk_flags_str
        ))
        inserted_count += 1

    conn.commit()
    conn.close()
    return inserted_count


def link_asset_to_service(asset_id, service_id, db_path=DEFAULT_DB_PATH):
    """Associates a crypto asset with a service."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE crypto_assets SET linked_service_id = ? WHERE id = ?
    """, (service_id, asset_id))
    conn.commit()
    conn.close()


def get_all_assets(db_path=DEFAULT_DB_PATH, filter_risk_only=False):
    """Returns all assets, optionally filtered to those with non-empty risk flags."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    query = """
        SELECT a.*, s.name as service_name, s.criticality as service_criticality
        FROM crypto_assets a
        LEFT JOIN services s ON a.linked_service_id = s.id
    """
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()

    results = []
    for r in rows:
        item = dict(r)
        rf_raw = item.get("risk_flags")
        if rf_raw:
            try:
                item["risk_flags"] = json.loads(rf_raw)
            except Exception:
                item["risk_flags"] = [rf_raw]
        else:
            item["risk_flags"] = []

        if filter_risk_only and not item["risk_flags"]:
            continue
        results.append(item)

    return results


def get_asset_history(host, port, db_path=DEFAULT_DB_PATH):
    """Returns all historical scan records for a host:port, oldest first."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM crypto_assets_history
        WHERE host = ? AND port = ?
        ORDER BY scanned_at ASC
    """, (host, port))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def seed_demo_data(db_path=DEFAULT_DB_PATH):
    """
    Seeds demo digital services & dependencies representing a government portal backend
    and links existing scanned targets to these services for hackathon demos.
    """
    init_db(db_path)
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    services_data = [
        ("API Gateway", "P0", "Central entry point for national digital services traffic"),
        ("Authentication Service", "P0", "Identity verification & SSO provider"),
        ("Payment Processor", "P1", "Encrypted transaction processing module"),
        ("Citizen Database", "P0", "Central encrypted record storage"),
        ("Internal Admin Panel", "P2", "Staff management dashboard"),
        ("Legacy Portal", "P1", "Older citizen lookup service (deprecated crypto)"),
    ]

    service_map = {}
    for name, crit, desc in services_data:
        cursor.execute("""
            INSERT INTO services (name, criticality, description)
            VALUES (?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET criticality=excluded.criticality, description=excluded.description
        """, (name, crit, desc))
        cursor.execute("SELECT id FROM services WHERE name = ?", (name,))
        service_map[name] = cursor.fetchone()["id"]

    # Dependencies: API Gateway -> Auth, Payment; Auth -> Citizen DB; Legacy Portal -> Auth
    dependencies = [
        (service_map["API Gateway"], service_map["Authentication Service"]),
        (service_map["API Gateway"], service_map["Payment Processor"]),
        (service_map["Authentication Service"], service_map["Citizen Database"]),
        (service_map["Payment Processor"], service_map["Citizen Database"]),
        (service_map["Legacy Portal"], service_map["Authentication Service"]),
    ]

    for s_id, dep_id in dependencies:
        cursor.execute("""
            INSERT OR IGNORE INTO service_dependencies (service_id, depends_on_service_id)
            VALUES (?, ?)
        """, (s_id, dep_id))

    conn.commit()

    # Explicit mapping table — no string-matching guesswork.
    # This is a curated demo dataset representing a mock government service
    # environment, not a real inferred relationship.
    DEMO_SERVICE_MAPPING = {
        ("127.0.0.1", 8443): "Legacy Portal",
        ("127.0.0.1", 8444): "API Gateway",
        ("127.0.0.1", 8445): "Authentication Service",
        ("google.com", 443): "Citizen Database",
        ("github.com", 443): "Internal Admin Panel",
        ("python.org", 443): "Payment Processor",
        ("wikipedia.org", 443): "API Gateway",
    }

    cursor.execute("SELECT id, host, port FROM crypto_assets")
    assets = cursor.fetchall()
    for a in assets:
        key = (a["host"], a["port"])
        service_name = DEMO_SERVICE_MAPPING.get(key, "Internal Admin Panel")  # fallback
        linked_s_id = service_map.get(service_name)
        if linked_s_id:
            cursor.execute("UPDATE crypto_assets SET linked_service_id = ? WHERE id = ?", (linked_s_id, a["id"]))

    conn.commit()
    conn.close()


def seed_offline_demo_data(db_path=DEFAULT_DB_PATH):
    """
    Seeds demo digital services & dependencies for OFFLINE MODE.

    Uses ONLY the three local test server endpoints (127.0.0.1:8443/8444/8445).
    Does NOT reference external public hosts (google.com, github.com, etc.).
    All service descriptions are tagged [Local Demo/Test Environment].

    Safe to call multiple times (INSERT OR IGNORE / ON CONFLICT DO UPDATE).
    """
    init_db(db_path)
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    services_data = [
        ("API Gateway",           "P0", "[Local Demo/Test Environment] Central entry point — api-gateway.internal (127.0.0.1:8444)"),
        ("Authentication Service","P0", "[Local Demo/Test Environment] Identity verification & SSO — auth-service.internal (127.0.0.1:8445)"),
        ("Payment Processor",     "P1", "[Local Demo/Test Environment] Encrypted transaction processing module"),
        ("Citizen Database",      "P0", "[Local Demo/Test Environment] Central encrypted record storage"),
        ("Internal Admin Panel",  "P2", "[Local Demo/Test Environment] Staff management dashboard"),
        ("Legacy Portal",         "P1", "[Local Demo/Test Environment] Older citizen lookup service (deprecated crypto) — legacy-portal.internal (127.0.0.1:8443)"),
    ]

    service_map = {}
    for name, crit, desc in services_data:
        cursor.execute("""
            INSERT INTO services (name, criticality, description)
            VALUES (?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET criticality=excluded.criticality, description=excluded.description
        """, (name, crit, desc))
        cursor.execute("SELECT id FROM services WHERE name = ?", (name,))
        service_map[name] = cursor.fetchone()["id"]

    # Service dependency graph (same topology as seed_demo_data)
    dependencies = [
        (service_map["API Gateway"],           service_map["Authentication Service"]),
        (service_map["API Gateway"],           service_map["Payment Processor"]),
        (service_map["Authentication Service"],service_map["Citizen Database"]),
        (service_map["Payment Processor"],     service_map["Citizen Database"]),
        (service_map["Legacy Portal"],         service_map["Authentication Service"]),
    ]
    for s_id, dep_id in dependencies:
        cursor.execute("""
            INSERT OR IGNORE INTO service_dependencies (service_id, depends_on_service_id)
            VALUES (?, ?)
        """, (s_id, dep_id))

    conn.commit()

    # Asset → service mapping: LOCAL loopback endpoints only
    OFFLINE_SERVICE_MAPPING = {
        ("127.0.0.1",           8443): "Legacy Portal",
        ("127.0.0.1",           8444): "API Gateway",
        ("127.0.0.1",           8445): "Authentication Service",
        # Cert-file assets use CN as host; map known test server CNs
        ("legacy-portal.internal", 0): "Legacy Portal",
        ("api-gateway.internal",   0): "API Gateway",
        ("auth-service.internal",  0): "Authentication Service",
    }

    cursor.execute("SELECT id, host, port FROM crypto_assets")
    assets = cursor.fetchall()
    for a in assets:
        key = (a["host"], a["port"])
        service_name = OFFLINE_SERVICE_MAPPING.get(key, "Internal Admin Panel")
        linked_s_id = service_map.get(service_name)
        if linked_s_id:
            cursor.execute(
                "UPDATE crypto_assets SET linked_service_id = ? WHERE id = ?",
                (linked_s_id, a["id"]),
            )

    conn.commit()
    conn.close()


def export_cbom(db_path=DEFAULT_DB_PATH, format="cyclonedx"):
    """
    Exports the inventory in CycloneDX CBOM (Cryptographic Bill of Materials) JSON format.
    Reference: https://cyclonedx.org/capabilities/cbom/
    """
    assets = get_all_assets(db_path)

    components = []
    for a in assets:
        comp_bom_ref = f"crypto-asset-{a['id']}-{a['host']}:{a['port']}"
        
        crypto_props = [
            {"name": "tls:version", "value": str(a.get("tls_version") or "Unknown")},
            {"name": "tls:cipher_suite", "value": str(a.get("cipher_suite") or "Unknown")},
            {"name": "tls:cipher_bits", "value": str(a.get("cipher_bits") or 0)},
            {"name": "certificate:key_type", "value": str(a.get("cert_key_type") or "Unknown")},
            {"name": "certificate:key_size_bits", "value": str(a.get("cert_key_size_bits") or 0)},
            {"name": "certificate:signature_algorithm", "value": str(a.get("cert_signature_algorithm") or "Unknown")},
            {"name": "risk:mwqrs_score", "value": str(a.get("risk_score") or 0.0)},
        ]

        component = {
            "type": "cryptographic-asset",
            "bom-ref": comp_bom_ref,
            "name": f"TLS Endpoint {a['host']}:{a['port']}",
            "description": f"Subject: {a.get('cert_subject') or 'N/A'} | Issuer: {a.get('cert_issuer') or 'N/A'}",
            "properties": crypto_props,
        }
        components.append(component)

    cbom_document = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [
                {
                    "vendor": "ECDAT",
                    "name": "Enterprise Cryptographic Discovery & Analysis Tool",
                    "version": "1.0.0"
                }
            ],
            "component": {
                "type": "application",
                "name": "ECDAT Inventory Assessment",
                "version": "1.0.0"
            }
        },
        "components": components
    }

    return json.dumps(cbom_document, indent=2)


if __name__ == "__main__":
    init_db()
    seed_demo_data()
    print("Database initialized & seeded with demo services.")
    print("Sample CBOM exported:")
    print(export_cbom()[:400] + "\n...")
