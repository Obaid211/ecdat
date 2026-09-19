"""
ECDAT Unit Tests - Scoring Engine (ecdat_scoring.py)
----------------------------------------------------
Tests MWQRS calculation math, worked examples, monotonic properties, and score bounds.
"""

import pytest
from ecdat_scoring import calculate_mwqrs


def test_worked_example_rsa1024_critical():
    """
    Worked Example: RSA-1024, TLS 1.2, days_to_expiry=15, criticality='P1'
    - Algo score: RSA (vuln) -> 100.0 * 0.35 = 35.0
    - Key size score: 1024 (<2048) -> 75.0 * 0.20 = 15.0
    - Protocol score: TLSv1.2 -> 50.0 * 0.15 = 7.5
    - Expiry score: 15d (<=30) -> 75.0 * 0.10 = 7.5
    - Service criticality: P1 -> base 50.0 * 0.20 = 10.0
    - Weighted sum = 35.0 + 15.0 + 7.5 + 7.5 + 10.0 = 75.0
    - Final score = min(100.0, 75.0 * 1.2) = 90.0 (Critical band >= 80.0)
    """
    asset = {
        "status": "success",
        "cert_key_type": "RSA",
        "cert_key_size_bits": 1024,
        "tls_version": "TLSv1.2",
        "days_to_expiry": 15
    }
    score = calculate_mwqrs(asset, service_criticality="P1")
    assert score == 90.0
    assert score >= 80.0  # Lands strictly in Critical band


def test_monotonic_key_size():
    """Smaller key size should score higher risk than larger key size."""
    base_asset_weak = {
        "status": "success",
        "cert_key_type": "RSA",
        "cert_key_size_bits": 1024,
        "tls_version": "TLSv1.3",
        "days_to_expiry": 180
    }
    base_asset_strong = {
        "status": "success",
        "cert_key_type": "RSA",
        "cert_key_size_bits": 3072,
        "tls_version": "TLSv1.3",
        "days_to_expiry": 180
    }
    score_weak = calculate_mwqrs(base_asset_weak, service_criticality="P2")
    score_strong = calculate_mwqrs(base_asset_strong, service_criticality="P2")
    assert score_weak > score_strong


def test_monotonic_cert_expiry():
    """Expired certificate should score higher risk than valid certificate."""
    asset_expired = {
        "status": "success",
        "cert_key_type": "RSA",
        "cert_key_size_bits": 2048,
        "tls_version": "TLSv1.3",
        "days_to_expiry": -5
    }
    asset_valid = {
        "status": "success",
        "cert_key_type": "RSA",
        "cert_key_size_bits": 2048,
        "tls_version": "TLSv1.3",
        "days_to_expiry": 180
    }
    score_expired = calculate_mwqrs(asset_expired, service_criticality="P2")
    score_valid = calculate_mwqrs(asset_valid, service_criticality="P2")
    assert score_expired > score_valid


def test_monotonic_criticality():
    """P0 service criticality should score higher risk than P2 for identical assets."""
    asset = {
        "status": "success",
        "cert_key_type": "ECC (secp256r1)",
        "cert_key_size_bits": 256,
        "tls_version": "TLSv1.3",
        "days_to_expiry": 120
    }
    score_p0 = calculate_mwqrs(asset, service_criticality="P0")
    score_p2 = calculate_mwqrs(asset, service_criticality="P2")
    assert score_p0 > score_p2


def test_score_bounds():
    """All generated scores must lie strictly within [0.0, 100.0]."""
    test_cases = [
        ({"status": "unreachable"}, "P0"),
        ({"status": "success", "cert_key_type": "RSA", "cert_key_size_bits": 512, "tls_version": "SSLv3", "days_to_expiry": -100}, "P0"),
        ({"status": "success", "cert_key_type": "ML-KEM-768", "cert_key_size_bits": 768, "tls_version": "TLSv1.3", "days_to_expiry": 365}, "P3"),
    ]
    for asset, crit in test_cases:
        score = calculate_mwqrs(asset, service_criticality=crit)
        assert 0.0 <= score <= 100.0
