# ECDAT — Enterprise Cryptographic Discovery & Analysis Tool

> **SIH Problem Statement SIH26164** | Post-Quantum Cryptography (PQC) & Keyfactor AgileSec Pipeline Model (NTRO)

ECDAT (Enterprise Cryptographic Discovery & Analysis Tool) is an automated cryptographic inventory, quantum risk assessment, and Post-Quantum Cryptography (PQC) migration simulation pipeline built for enterprise systems and digital public infrastructure.

---

## Key Features & Capabilities

- **Pure-Python TLS Discovery**: Performs polite TLS handshakes to extract TLS versions, cipher suites, certificate key specifications (RSA/ECC/DSA), signature algorithms, and expiry dates without native external binaries.
- **Mosca-Inspired Quantum Risk Score (MWQRS)**: Calculates a 0–100 quantum vulnerability score using a weighted composite inspired by Mosca's Inequality (X+Y>Z), combining algorithm vulnerability (35%), key size (20%), protocol version (15%), cert expiry (10%), and service criticality (20% with P0/P1 multipliers). The score captures the spirit of the framework — exposure urgency, migration cost, data lifetime — as a composite score, not a direct evaluation of the three-variable inequality.
- **CycloneDX CBOM Export**: Generates standardized Cryptographic Bill of Materials documents in CycloneDX Specification 1.6 JSON format.
- **PQC Migration Simulator & Blast Radius**: Maps vulnerable classical algorithms to NIST FIPS 203 (ML-KEM-768), FIPS 204 (ML-DSA-65), and FIPS 205 (SLH-DSA) standards, analyzes dependency graph blast radius via NetworkX, and computes topological migration sequences.
- **Multi-Language Source Code Scanner**: Scans repository source code (AST + regex rules across Python, Java, JS, C/C++) for MD5/SHA1 weak hashing, DES ciphers, weak RSA generation, and exposed private keys.
- **Executive Web Dashboard**: Interactive Streamlit GUI featuring Plotly distribution charts, network dependency graphs, CBOM exporter, requirement mapping views, and real-time TLS scanner.

---

## Architecture Overview

| Component File | Role & Functionality |
| :--- | :--- |
| [ecdat_scanner.py](file:///c:/Users/obaid/Downloads/ecdat_package/ecdat_package/ecdat_scanner.py) | TLS client socket handshake sensor & risk classification engine (`scan_host`, `scan_targets`). |
| [ecdat_inventory.py](file:///c:/Users/obaid/Downloads/ecdat_package/ecdat_package/ecdat_inventory.py) | SQLite database manager (`ecdat.db`) & CycloneDX v1.6 CBOM exporter (`export_cbom`). |
| [ecdat_scoring.py](file:///c:/Users/obaid/Downloads/ecdat_package/ecdat_package/ecdat_scoring.py) | MWQRS quantum risk calculation engine (`calculate_mwqrs`, `score_all_assets`). |
| [ecdat_simulator.py](file:///c:/Users/obaid/Downloads/ecdat_package/ecdat_package/ecdat_simulator.py) | NIST PQC replacement mapper, blast-radius graph engine, and topological sequence planner. |
| [ecdat_codescanner.py](file:///c:/Users/obaid/Downloads/ecdat_package/ecdat_package/ecdat_codescanner.py) | AST + regex source code scanner (`scan_source_directory`). |
| [app.py](file:///c:/Users/obaid/Downloads/ecdat_package/ecdat_package/app.py) | Streamlit executive visual web application. |
| [cli.py](file:///c:/Users/obaid/Downloads/ecdat_package/ecdat_package/cli.py) | Unified command-line interface orchestrating the master pipeline. |

---

## Installation & Setup

1. **Verify Python**: Python 3.8+ required.
2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

---

## Running the ECDAT Pipeline

### ⚠️ IMPORTANT: Local Demo TLS Servers (Two-Terminal Requirement)
The demo hosts in `hosts.txt` include three local loopback endpoints (`127.0.0.1:8443`, `127.0.0.1:8444`, and `127.0.0.1:8445`) representing weak legacy RSA-1024, strong RSA-3072, and medium RSA-2048 services. For these endpoints to respond during a scan, `generate_test_certs.py` **must be running continuously in a separate terminal**:

- **Terminal 1 (Keep running continuously in background):**
  ```bash
  python generate_test_certs.py
  ```
- **Terminal 2 (Execute pipeline & launch dashboard):**
  ```bash
  # Execute full discovery pipeline against hosts
  python cli.py pipeline --hosts hosts.txt

  # Launch executive web dashboard
  streamlit run app.py
  ```
*(Note: If Terminal 1 is not running, the local ports 8443, 8444, and 8445 will be marked as `unreachable` due to connection refusal.)*

The checked-in `*.internal_cert.pem` and `*.internal_key.pem` files are demo-only fixtures generated for these local loopback TLS services. Do not reuse them for real services or production-like environments.

### 1. Execute Full Discovery Pipeline
Run end-to-end TLS scanning, database ingestion, MWQRS scoring, code scanning, migration simulation, and CBOM export:
```bash
python cli.py pipeline --hosts hosts.txt
```
To run fast re-evaluations using cached scan results:
```bash
python cli.py pipeline --skip-scan
```

### 2. Launch Interactive Executive Dashboard
```bash
streamlit run app.py
```

### 3. Run Automated Unit Test Suite
```bash
pytest -q
```

---

## Capability Status: Built vs. Planned

| Capability Feature | Status | Implementation Details |
| :--- | :--- | :--- |
| **TLS Network Endpoint Scanner** | **Built** | Fully implemented in `ecdat_scanner.py` with polite sequential delay. |
| **MWQRS Risk Scoring Engine** | **Built** | Implemented in `ecdat_scoring.py` (0–100 scale, weighted formula). |
| **CycloneDX 1.6 CBOM Export** | **Built** | Implemented in `ecdat_inventory.py` (`export_cbom()`). |
| **PQC Algorithm Mapping** | **Built** | Implemented in `ecdat_simulator.py` (NIST FIPS 203/204/205). |
| **Dependency Blast Radius** | **Built** | Implemented in `ecdat_simulator.py` via NetworkX directed graphs. |
| **Source Code Crypto Scanner** | **Built** | Implemented in `ecdat_codescanner.py` (.py, .js, .java, AST + regex). |
| **Streamlit GUI Dashboard** | **Built** | Implemented in `app.py` with Plotly charts and interactive tabs. |
| **Native Binary Scanner (.so/.dll)** | **Planned** | Binary inspection engine planned for future release. |
| **Container Image Inspection** | **Planned** | Docker/OCI container layer extraction planned for future release. |
| **HSM & Cloud KMS Auto-Discovery** | **Planned** | Hardware and Cloud KMS API connectors planned for future release. |
| **PQC Latency & Cost Modeling** | **Planned** | Performance overhead estimation planned for future release. |

---

## Verification & Compliance Notes

- Risk scoring thresholds are informed by **NIST SP 800-52 Rev. 2** (Guidelines for TLS Selection & Configuration).
- CBOM exports adhere strictly to the **CycloneDX Specification 1.6** Cryptographic Extension standard schema.
