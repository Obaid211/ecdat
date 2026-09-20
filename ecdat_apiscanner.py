"""
ECDAT — API Cryptographic Scanner
----------------------------------
Inspects API endpoints and API response payloads for cryptographic properties:
  - Transport Layer Security (TLS version, cipher suite, cert key)
  - Security headers (Strict-Transport-Security, etc.)
  - JWT (JSON Web Token) signing algorithm classification (RS256, ES256, HS256)
  - Quantum vulnerability classification for API authentication tokens

Includes offline controlled test fixtures so API scanning can be demonstrated
without depending on external network connectivity.
"""

from typing import Dict, Any, Optional, List
import base64
import json
import socket
import ssl
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

import ecdat_inventory as inv
import ecdat_scanner as scanner_core


def decode_jwt_header(token: str) -> Optional[Dict[str, Any]]:
    """
    Safely extracts and parses the header of a JWT without validating the signature.
    RFC 7519 / RFC 7515 specifies header is base64url encoded.
    """
    if not token or not isinstance(token, str):
        return None
    token = token.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()

    parts = token.split(".")
    if len(parts) < 2:
        return None

    header_b64 = parts[0]
    # Add base64 padding if needed
    rem = len(header_b64) % 4
    if rem > 0:
        header_b64 += "=" * (4 - rem)

    try:
        header_json = base64.urlsafe_b64decode(header_b64.encode("ascii")).decode("utf-8")
        return json.loads(header_json)
    except Exception:
        return None


def classify_jwt_algorithm(alg: str) -> Dict[str, Any]:
    """Classifies a JWT signature algorithm against quantum and classical security standards."""
    alg_upper = (alg or "UNKNOWN").upper()

    if alg_upper in ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"]:
        return {
            "algorithm": alg_upper,
            "type": "RSA Asymmetric Signature (PKCS#1 / PSS)",
            "quantum_status": "Quantum-Vulnerable (Shor's Algorithm on future CRQC)",
            "risk_level": "HIGH",
            "recommendation": "Plan migration to NIST FIPS 204 (ML-DSA-65) or dual-mode hybrid JWT signatures.",
        }
    elif alg_upper in ["ES256", "ES384", "ES512", "EDDSA"]:
        return {
            "algorithm": alg_upper,
            "type": "ECDSA / EdDSA Elliptic Curve Signature",
            "quantum_status": "Quantum-Vulnerable (Shor's Algorithm on future CRQC)",
            "risk_level": "HIGH",
            "recommendation": "Plan migration to NIST FIPS 204 (ML-DSA-65) for API token validation.",
        }
    elif alg_upper in ["HS256", "HS384", "HS512"]:
        return {
            "algorithm": alg_upper,
            "type": "HMAC Symmetric Key Signature",
            "quantum_status": "Quantum-Resistant (Grover's Algorithm requires 256-bit keys)",
            "risk_level": "LOW",
            "recommendation": "Symmetric HMAC is quantum-resistant if secret key >= 256 bits. Maintain secure key distribution.",
        }
    elif alg_upper in ["NONE"]:
        return {
            "algorithm": "none",
            "type": "Unsigned / Insecure Token",
            "quantum_status": "Severely Insecure (No Signature)",
            "risk_level": "CRITICAL",
            "recommendation": "Reject unsigned tokens immediately. Enforce cryptographically verified signatures.",
        }
    elif "ML-DSA" in alg_upper or "DILITHIUM" in alg_upper:
        return {
            "algorithm": alg_upper,
            "type": "NIST FIPS 204 Post-Quantum Digital Signature",
            "quantum_status": "Quantum-Resistant (NIST PQC Standard)",
            "risk_level": "LOW",
            "recommendation": "Post-quantum API signature active. Verify standard conformance and benchmark verification latency.",
        }
    else:
        return {
            "algorithm": alg_upper,
            "type": "Unrecognized Signature Algorithm",
            "quantum_status": "Under Review",
            "risk_level": "MEDIUM",
            "recommendation": "Audit API token configuration and verify against NIST SP 800-52 / FIPS 204 guidance.",
        }


def inspect_api_endpoint(
    url: str,
    sample_jwt: Optional[str] = None,
    timeout: float = 5.0,
    db_path: str = inv.DEFAULT_DB_PATH
) -> Dict[str, Any]:
    """
    Inspects a live or local API endpoint for TLS configuration, security headers,
    and JWT signature algorithm if a token is available.
    """
    inv.init_db(db_path)
    parsed = urllib.parse.urlparse(url)
    if not parsed.scheme:
        # Default to https
        parsed = urllib.parse.urlparse(f"https://{url}")

    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    scheme = parsed.scheme.lower()

    report = {
        "url": url,
        "endpoint": f"{parsed.path or '/'}",
        "host": host,
        "port": port,
        "scheme": scheme,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "tls_info": None,
        "security_headers": {},
        "jwt_analysis": None,
        "overall_risk": "LOW",
        "findings": [],
        "recommendations": [],
    }

    # 1. TLS Inspection if HTTPS
    if scheme == "https":
        tls_res = scanner_core.scan_host(host, port, timeout=timeout)
        if tls_res.get("status") == "success":
            report["tls_info"] = {
                "version": tls_res.get("tls_version"),
                "cipher": tls_res.get("cipher_suite"),
                "cert_key_type": tls_res.get("cert_key_type"),
                "cert_key_size_bits": tls_res.get("cert_key_size_bits"),
                "signature_algorithm": tls_res.get("cert_signature_algorithm"),
                "days_to_expiry": tls_res.get("days_to_expiry"),
            }
            if tls_res.get("cert_key_type") == "RSA" and (tls_res.get("cert_key_size_bits") or 0) < 2048:
                report["findings"].append(f"Weak RSA key ({tls_res.get('cert_key_size_bits')}b) on API TLS certificate")
                report["overall_risk"] = "HIGH"
        else:
            report["tls_info"] = {"error": tls_res.get("error", "TLS handshake unsuccessful")}

    # 2. JWT Analysis if token provided
    if sample_jwt:
        jwt_header = decode_jwt_header(sample_jwt)
        if jwt_header:
            alg = jwt_header.get("alg", "UNKNOWN")
            jwt_class = classify_jwt_algorithm(alg)
            report["jwt_analysis"] = {
                "header": jwt_header,
                "classification": jwt_class,
            }
            if jwt_class["risk_level"] in ["CRITICAL", "HIGH"]:
                report["findings"].append(f"API JWT uses {jwt_class['type']} ({alg}): {jwt_class['quantum_status']}")
                if report["overall_risk"] != "CRITICAL":
                    report["overall_risk"] = jwt_class["risk_level"]
                report["recommendations"].append(jwt_class["recommendation"])

    # Persist to SQLite
    conn = inv.get_db_connection(db_path)
    cur = conn.cursor()
    tls_v_str = report["tls_info"].get("version", "N/A") if report["tls_info"] else "HTTP"
    cert_str = f"{report['tls_info'].get('cert_key_type','')} {report['tls_info'].get('cert_key_size_bits','')}b" if report["tls_info"] and "error" not in report["tls_info"] else "N/A"
    jwt_alg_str = report["jwt_analysis"]["classification"]["algorithm"] if report["jwt_analysis"] else "None"

    cur.execute("""
        INSERT INTO api_findings (endpoint, method, tls_version, cert_key, jwt_algorithm, hsts_enabled, security_headers, risk_level, findings, recommendation, scanned_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        url,
        "GET",
        tls_v_str,
        cert_str,
        jwt_alg_str,
        1 if "Strict-Transport-Security" in report["security_headers"] else 0,
        json.dumps(report["security_headers"]),
        report["overall_risk"],
        "; ".join(report["findings"]) or "No critical cryptographic anomalies observed",
        "; ".join(report["recommendations"]) or "Maintain standard TLS 1.3 and cryptographic monitoring",
        report["scanned_at"],
    ))
    conn.commit()
    conn.close()

    return report


def inspect_api_fixture(fixture_path: str, db_path: str = inv.DEFAULT_DB_PATH) -> Dict[str, Any]:
    """
    Parses a controlled mock API fixture file (JSON) to demonstrate
    API crypto scanning offline without requiring internet access.
    """
    inv.init_db(db_path)
    path = Path(fixture_path)
    if not path.exists():
        raise FileNotFoundError(f"API fixture file not found: {fixture_path}")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    url = data.get("api_url", "https://local-test.internal/api/v1/auth/login")
    jwt_token = data.get("sample_jwt")
    tls_mock = data.get("tls_info")
    headers_mock = data.get("headers", {})

    jwt_analysis = None
    findings = []
    recommendations = []
    overall_risk = "LOW"

    if jwt_token:
        jwt_header = decode_jwt_header(jwt_token)
        if jwt_header:
            alg = jwt_header.get("alg", "UNKNOWN")
            jwt_class = classify_jwt_algorithm(alg)
            jwt_analysis = {
                "header": jwt_header,
                "classification": jwt_class,
            }
            if jwt_class["risk_level"] in ["CRITICAL", "HIGH"]:
                findings.append(f"API JWT uses {jwt_class['type']} ({alg}): {jwt_class['quantum_status']}")
                overall_risk = jwt_class["risk_level"]
                recommendations.append(jwt_class["recommendation"])

    hsts_active = any("strict-transport-security" in k.lower() for k in headers_mock.keys())
    if not hsts_active:
        findings.append("HTTP Strict-Transport-Security (HSTS) header missing")

    report = {
        "url": url,
        "endpoint": urllib.parse.urlparse(url).path or "/",
        "host": urllib.parse.urlparse(url).hostname or "local-test.internal",
        "port": 443,
        "scheme": "https",
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "is_controlled_fixture": True,
        "fixture_name": path.name,
        "tls_info": tls_mock,
        "security_headers": headers_mock,
        "jwt_analysis": jwt_analysis,
        "overall_risk": overall_risk,
        "findings": findings,
        "recommendations": recommendations,
    }

    # Persist finding
    conn = inv.get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO api_findings (endpoint, method, tls_version, cert_key, jwt_algorithm, hsts_enabled, security_headers, risk_level, findings, recommendation, scanned_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        f"[CONTROLLED FIXTURE] {url}",
        "POST",
        tls_mock.get("version", "TLSv1.3") if tls_mock else "TLSv1.3",
        f"{tls_mock.get('cert_key_type','RSA')} {tls_mock.get('cert_key_size_bits','2048')}b" if tls_mock else "RSA 2048b",
        jwt_analysis["classification"]["algorithm"] if jwt_analysis else "N/A",
        1 if hsts_active else 0,
        json.dumps(headers_mock),
        overall_risk,
        "; ".join(findings) or "No critical cryptographic anomalies observed",
        "; ".join(recommendations) or "Maintain standard TLS and token monitoring",
        report["scanned_at"],
    ))
    conn.commit()
    conn.close()

    return report
