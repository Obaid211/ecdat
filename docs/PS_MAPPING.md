# ECDAT — Problem Statement (SIH26164) Requirement Mapping

This document provides an honest, ground-truth mapping of the requirements specified in **Problem Statement SIH26164** (Post-Quantum Cryptography & Keyfactor AgileSec Pipeline Model / NTRO) against the actual implementation in the ECDAT codebase.

---

## 1. Requirement Coverage Table

| Requirement | Status | Implemented By (File, Function) | 30-Second Demo | Identified Gap / Limitation |
| :--- | :--- | :--- | :--- | :--- |
| **(i) Catalogue Cryptographic Artefacts**<br>*(Algorithms, keys, certificates, protocols, libraries, hardware modules, cloud services)* | **Partial** | [ecdat_scanner.py](file:///c:/Users/obaid/Downloads/ecdat_package/ecdat_package/ecdat_scanner.py) (`scan_host`, `get_key_info`), [ecdat_inventory.py](file:///c:/Users/obaid/Downloads/ecdat_package/ecdat_package/ecdat_inventory.py) (`ingest_scan_results`), [ecdat_codescanner.py](file:///c:/Users/obaid/Downloads/ecdat_package/ecdat_package/ecdat_codescanner.py) (`scan_file_content`) | Run `python cli.py scan --host google.com:443`<br>View extracted TLS version, cipher suite, cert key size/type, sig algo, and code findings. | Hardware Security Modules (HSM) and Cloud KMS services are not catalogued. Libraries scanned via source AST/regex; native binary libraries (.so/.dll) not inspected. |
| **(ii) Classify by Type, Lifetime & Criticality**<br>*(Categorization and business impact assessment)* | **Partial** | [ecdat_inventory.py](file:///c:/Users/obaid/Downloads/ecdat_package/ecdat_package/ecdat_inventory.py) (`init_db`, `seed_demo_data`), [ecdat_scoring.py](file:///c:/Users/obaid/Downloads/ecdat_package/ecdat_package/ecdat_scoring.py) (`CRITICALITY_MULTIPLIERS`) | Launch `streamlit run app.py`<br>Filter assets by criticality tier (P0–P3) and certificate days to expiry (`days_to_expiry`). | Certificate expiry lifetime (`days_to_expiry`) is tracked, but system operational lifetime ($Z$) is not dynamically modeled. **Service dependency graph is mock/seeded (`seed_demo_data`), not automatically discovered from network traffic.**<br>*Note on asset counts: The baseline "10 assets" breakdown is **not verified** — no documentary evidence or commit record exists proving this specific asset count or breakdown.* |
| **(iii) Quantum Risk Assessment (Mosca-inspired)**<br>*(Weighted risk scoring inspired by Mosca's framework)* | **Partial** | [ecdat_scoring.py](file:///c:/Users/obaid/Downloads/ecdat_package/ecdat_package/ecdat_scoring.py) (`calculate_mwqrs`, `score_all_assets`) | Run `python cli.py score`<br>View MWQRS risk scores (0–100 scale) calculated per asset based on algorithm, key size, TLS version, cert expiry, and service criticality. | The scoring model (MWQRS) is **Mosca-inspired** rather than a direct mathematical evaluation of Mosca's inequality ($X + Y > Z$). Data security shelf-life ($Y$) and migration time ($X$) parameters are statically weighted per asset rather than dynamically modeled from business retention policies. |
| **(iv) Recommend PQC/Hybrid Alternatives**<br>*(NIST standards, latency, cost & migration sequence)* | **Partial** | [ecdat_simulator.py](file:///c:/Users/obaid/Downloads/ecdat_package/ecdat_package/ecdat_simulator.py) (`PQC_MIGRATION_MAP`, `simulate_migration`, `recommend_migration_order`) | Run `python cli.py simulate`<br>View recommended NIST FIPS 203/204/205 replacements (ML-KEM-768, ML-DSA-65, SLH-DSA), hybrid mode notes, and topological migration sequence. | **Latency overhead impact and migration cost estimates are absent/not computed.** |
| **(v) Deliverable: CBOM Analytics Tool**<br>*(Source code, binaries, libraries, container images, standard report, interactive GUI)* | **Partial** | [ecdat_inventory.py](file:///c:/Users/obaid/Downloads/ecdat_package/ecdat_package/ecdat_inventory.py) (`export_cbom`), [ecdat_codescanner.py](file:///c:/Users/obaid/Downloads/ecdat_package/ecdat_package/ecdat_codescanner.py) (`scan_source_directory`), [app.py](file:///c:/Users/obaid/Downloads/ecdat_package/ecdat_package/app.py), [cli.py](file:///c:/Users/obaid/Downloads/ecdat_package/ecdat_package/cli.py) (`cbom`) | Run `python cli.py cbom --out cbom.json` for CycloneDX v1.6 CBOM;<br>Launch `streamlit run app.py` for executive GUI. | Source code scanned across multiple languages (.py, .js, .java, etc.); **compiled binaries (.so, .dll, ELF) and container images (Docker/OCI) are not scanned.** |

---

## 2. Executive 5-Line Slide Summary

1. **Discovery & Inventory**: Pure-Python TLS endpoint scanner + CycloneDX v1.6 CBOM exporter (**Implemented** for network endpoints; **Partial** for source code; HSMs/Cloud KMS **Planned**).
2. **Quantum Risk Scoring**: Implements Mosca-Weighted Quantum Risk Score (MWQRS, 0–100 scale) combining algorithm vulnerability (35%), key length (20%), TLS version (15%), cert expiry (10%), and service criticality (20%) (**Partial** — Mosca-inspired composite index, not a direct evaluation of $X+Y>Z$).
3. **PQC Migration Roadmap**: Maps classical algorithms (RSA/ECC/DSA) to NIST FIPS 203 (ML-KEM-768) & FIPS 204 (ML-DSA-65) with hybrid transition modes and NetworkX dependency blast-radius sequence (**Implemented**).
4. **Interactive Dashboard & CLI**: Streamlit executive web application with Plotly analytics, network dependency graphs, CBOM exporter, and unified master CLI (`python cli.py pipeline`) (**Implemented**).
5. **Gaps & Roadmap**: Binary (.so/ELF) scanning, container image inspection, HSM/KMS discovery, and PQC latency/cost estimation are identified as **Planned** enhancements.

---

## 3. Status Definition Legend

- **Implemented**: Fully operational and verified in codebase without caveats.
- **Partial**: Operational for core scope (e.g., TLS endpoints / source code), but incomplete for secondary assets (e.g., binaries, HSMs, latency modeling, or using an inspired composite rather than direct mathematical inequality).
- **Planned**: Architecturally identified but not yet implemented in code.
