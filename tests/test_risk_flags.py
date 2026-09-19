"""
ECDAT Unit Tests - Risk Flag Classification (ecdat_scanner.py)
--------------------------------------------------------------
Tests classify_risk logic for key sizes, TLS versions, signature algorithms, and cert expiry.
"""

import pytest
from ecdat_scanner import classify_risk


def test_weak_rsa_key_flag():
    flags = classify_risk("TLSv1.3", "RSA", 1024, "sha256WithRSAEncryption", 120)
    assert any("WEAK_RSA_KEY_SIZE:1024bit" in f for f in flags)


def test_outdated_tls_flags():
    for weak_tls in ["TLSv1", "TLSv1.1", "SSLv3"]:
        flags = classify_risk(weak_tls, "RSA", 2048, "sha256WithRSAEncryption", 120)
        assert any("OUTDATED_TLS_VERSION" in f for f in flags)


def test_weak_signature_algo_flag():
    flags = classify_risk("TLSv1.2", "RSA", 2048, "sha1WithRSAEncryption", 120)
    assert any("WEAK_SIGNATURE_ALGO" in f for f in flags)


def test_expiring_cert_flag():
    flags = classify_risk("TLSv1.3", "ECC (secp256r1)", 256, "ecdsa-with-sha256", 15)
    assert any("CERT_EXPIRING_SOON:15d" in f for f in flags)


def test_expired_cert_flag():
    flags = classify_risk("TLSv1.3", "ECC (secp256r1)", 256, "ecdsa-with-sha256", -5)
    assert "CERT_EXPIRED" in flags
