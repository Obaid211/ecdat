"""
ECDAT Unit Tests - PQC Migration Simulator (ecdat_simulator.py)
---------------------------------------------------------------
Tests PQC replacement mappings, blast radius graph analysis, and topological migration sequence.
"""

import pytest
import networkx as nx
from ecdat_simulator import PQC_MIGRATION_MAP, get_affected_dependents


def test_pqc_mapping_rules():
    """Verify classical algorithms map to correct NIST PQC replacements."""
    rsa_info = PQC_MIGRATION_MAP["RSA"]
    assert "ML-KEM-768" in rsa_info["replacement"]
    assert "ML-DSA-65" in rsa_info["replacement"]

    ecc_info = PQC_MIGRATION_MAP["ECC"]
    assert "ML-DSA-65" in ecc_info["replacement"] or "SLH-DSA" in ecc_info["replacement"]


def test_blast_radius_handbuilt_graph():
    """
    Construct small hand-built Directed Graph:
    Service 1 (API Gateway) -> Service 2 (Auth Service) -> Service 3 (Citizen DB)
    If Service 3 is migrated, dependents affected must be [Service 2, Service 1] (or IDs 2, 1).
    """
    G = nx.DiGraph()
    G.add_node(1, name="API Gateway")
    G.add_node(2, name="Auth Service")
    G.add_node(3, name="Citizen DB")

    G.add_edge(1, 2)  # API Gateway depends on Auth Service
    G.add_edge(2, 3)  # Auth Service depends on Citizen DB

    # Get dependents of Service 3 (Citizen DB)
    affected = get_affected_dependents(3, G)
    assert "Auth Service" in affected
    assert "API Gateway" in affected
    assert len(affected) == 2
