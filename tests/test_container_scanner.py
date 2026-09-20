"""
Unit tests for ECDAT Container Scanner (ecdat_containerscanner.py)
"""
import pytest
from pathlib import Path
import ecdat_containerscanner as cscan
import ecdat_inventory as inv


def test_scan_dockerfile_legacy(tmp_path: Path):
    dockerfile_content = """FROM ubuntu:14.04
RUN apt-get update && apt-get install -y openssl libssl-dev
COPY id_rsa /root/.ssh/id_rsa
RUN sed -i 's/DEFAULT@SECLEVEL=2/DEFAULT@SECLEVEL=0/' /etc/ssl/openssl.cnf
ENV NODE_TLS_REJECT_UNAUTHORIZED=0
"""
    findings = cscan.scan_dockerfile_content(dockerfile_content, source_path="Dockerfile.test")
    rule_ids = [f["rule_id"] for f in findings]

    assert "CONTAINER_DEPRECATED_BASE_IMAGE" in rule_ids
    assert "CONTAINER_CRYPTO_PACKAGE_INSTALLED" in rule_ids
    assert "CONTAINER_HARDCODED_KEY" in rule_ids
    assert "CONTAINER_WEAK_SECLEVEL" in rule_ids
    assert "CONTAINER_TLS_VERIFY_DISABLED" in rule_ids


def test_scan_dockerfile_pqc_ready(tmp_path: Path):
    dockerfile_content = """FROM debian:12-slim
RUN apt-get update && apt-get install -y ca-certificates
RUN git clone https://github.com/open-quantum-safe/liboqs.git
WORKDIR /app
COPY --chown=appuser:appuser . .
USER appuser
CMD ["./server"]
"""
    findings = cscan.scan_dockerfile_content(dockerfile_content, source_path="Dockerfile.pqc")
    rule_ids = [f["rule_id"] for f in findings]
    assert "CONTAINER_DEPRECATED_BASE_IMAGE" not in rule_ids
    assert "CONTAINER_WEAK_SECLEVEL" not in rule_ids
    assert "CONTAINER_PQC_INTEGRATION_FOUND" in rule_ids


def test_container_findings_persistence(tmp_path: Path):
    db = str(tmp_path / "test_cont.db")
    df = tmp_path / "Dockerfile"
    df.write_text("FROM ubuntu:14.04\nCOPY cert.pem /app/cert.pem\n", encoding="utf-8")

    findings = cscan.scan_container_target(str(df), db_path=db)
    assert len(findings) >= 1

    loaded = cscan.get_container_findings(db_path=db)
    assert len(loaded) >= 1
    assert loaded[0]["target_path"] == str(df)
