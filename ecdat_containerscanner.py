"""
ECDAT — Container & Dockerfile Cryptographic Scanner
------------------------------------------------------
Analyzes container definitions (Dockerfiles and container build contexts) for:
  - Base image cryptographic posture
  - Installed cryptographic packages & libraries (OpenSSL, GnuTLS, libgcrypt)
  - Exposed/embedded private keys and certificates
  - Insecure TLS/SSL configurations (e.g. SECLEVEL=0, certificate verification disabled)
  - Quantum-vulnerable algorithm references
"""

from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime, timezone
import re
import ecdat_inventory as inv


CONTAINER_CRYPTO_RULES = [
    {
        "id": "CONTAINER_HARDCODED_KEY",
        "pattern": r"(?:COPY|ADD)\s+.*(?:\.(?:key|pem|pkcs8|pfx|p12)\b|id_rsa|id_dsa|id_ecdsa|id_ed25519)",
        "severity": "CRITICAL",
        "type": "Embedded Cryptographic Key in Container Image",
        "recommendation": "Do not embed private keys into container layers. Inject credentials at runtime via secrets management or KMS.",
    },
    {
        "id": "CONTAINER_TLS_VERIFY_DISABLED",
        "pattern": r"(?:NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0['\"]?|--insecure|curl\s+-[a-zA-Z]*k|CURLOPT_SSL_VERIFYPEER\s*,\s*0)",
        "severity": "CRITICAL",
        "type": "TLS Certificate Verification Disabled",
        "recommendation": "Never disable TLS certificate validation in production containers. Configure internal CA certificates into the system trust store.",
    },
    {
        "id": "CONTAINER_WEAK_SECLEVEL",
        "pattern": r"(?:SECLEVEL\s*=\s*0|CipherString\s*=\s*DEFAULT:@SECLEVEL=0)",
        "severity": "HIGH",
        "type": "OpenSSL Security Level Downgraded to SECLEVEL=0",
        "recommendation": "Maintain OpenSSL SECLEVEL=2 or higher to enforce modern cipher suites and key lengths >= 2048-bit.",
    },
    {
        "id": "CONTAINER_DEPRECATED_BASE_IMAGE",
        "pattern": r"FROM\s+(?:ubuntu:(?:12\.|14\.|16\.)|debian:(?:wheezy|jessie|stretch)|centos:(?:6|7)|alpine:(?:2\.|3\.[0-8]\b))",
        "severity": "HIGH",
        "type": "Deprecated Base OS Image with Outdated Cryptographic Stack",
        "recommendation": "Upgrade to a supported base image (e.g. Ubuntu 22.04/24.04, Debian 12 Bookworm, Alpine 3.19+) to ensure modern OpenSSL 3.x and TLS 1.3 support.",
    },
    {
        "id": "CONTAINER_CRYPTO_PACKAGE_INSTALLED",
        "pattern": r"(?:apt-get|apk|yum|microdnf)\s+(?:install|add)\s+.*?\b(openssl|libssl-dev|ca-certificates|gnutls|libgcrypt|crypto-policies)\b",
        "severity": "INFORMATIONAL",
        "type": "Cryptographic Library Dependency Installed",
        "recommendation": "Track cryptographic dependencies in CBOM inventory and ensure packages receive timely security patches.",
    },
    {
        "id": "CONTAINER_LEGACY_CRYPTO_REFERENCE",
        "pattern": r"\b(rsa[-_ ]?1024|des-ede3|md5sum|sha1sum)\b",
        "severity": "MEDIUM",
        "type": "Legacy Cryptographic Algorithm Reference in Container Script",
        "recommendation": "Replace legacy cryptographic algorithms with modern NIST-approved symmetric ciphers or post-quantum alternatives.",
    },
    {
        "id": "CONTAINER_PQC_INTEGRATION_FOUND",
        "pattern": r"\b(oqs|liboqs|ml-kem|ml-dsa|dilithium|kyber)\b",
        "severity": "INFORMATIONAL",
        "type": "Post-Quantum Cryptography (PQC) Library / Provider Detected",
        "recommendation": "PQC integration observed. Validate interoperability against NIST FIPS 203/204 standard conformance test vectors.",
    }
]


def scan_dockerfile_content(content: str, source_path: str = "Dockerfile") -> List[Dict[str, Any]]:
    """Scans Dockerfile text lines against container cryptographic rules."""
    findings = []
    lines = content.splitlines()

    for line_no, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        for rule in CONTAINER_CRYPTO_RULES:
            match = re.search(rule["pattern"], stripped, re.IGNORECASE)
            if match:
                findings.append({
                    "rule_id": rule["id"],
                    "finding_type": rule["type"],
                    "component": match.group(0)[:40],
                    "severity": rule["severity"],
                    "evidence": stripped[:150],
                    "recommendation": rule["recommendation"],
                    "source_file": source_path,
                    "line_number": line_no,
                    "scanned_at": datetime.now(timezone.utc).isoformat(),
                })

    return findings


def scan_container_target(target_path: str, db_path: str = inv.DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    """
    Scans a Dockerfile or directory containing container configurations.
    Persists findings to the container_findings table in SQLite.
    """
    inv.init_db(db_path)
    path = Path(target_path)
    if not path.exists():
        raise FileNotFoundError(f"Container target not found: {target_path}")

    files_to_scan = []
    if path.is_file():
        files_to_scan.append(path)
    else:
        # Search for Dockerfile variants and container configs
        for pattern in ["Dockerfile*", "*.dockerfile", "Containerfile*"]:
            files_to_scan.extend(path.rglob(pattern))

    all_findings = []
    for f in files_to_scan:
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
            findings = scan_dockerfile_content(content, source_path=str(f))
            all_findings.extend(findings)
        except Exception:
            pass

    # Persist findings
    conn = inv.get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM container_findings WHERE target_path = ?", (str(path),))

    for item in all_findings:
        cursor.execute("""
            INSERT INTO container_findings (target_path, component, finding_type, severity, evidence, recommendation, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            str(path),
            item["component"],
            item["finding_type"],
            item["severity"],
            item["evidence"],
            item["recommendation"],
            item["scanned_at"],
        ))

    conn.commit()
    conn.close()
    return all_findings


def get_container_findings(db_path: str = inv.DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    """Retrieves all container findings from the database."""
    inv.init_db(db_path)
    conn = inv.get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM container_findings ORDER BY id DESC")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows
