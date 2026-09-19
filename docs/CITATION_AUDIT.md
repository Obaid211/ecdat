# ECDAT — DST Citation & Claim Audit

**Document Subject**: National Task Force Reports on Post-Quantum Cryptography & Quantum Safe Ecosystem  
**Issuing Body**: Department of Science & Technology (DST), Government of India, under the National Quantum Mission (NQM)  
**Task Force Chair**: Dr. Rajkumar Upadhyay, CEO, C-DOT  
**Sub-Groups**: Sub-Group I (Product categorization & standards / TEC), Sub-Group II (Migration strategy & sector roadmaps / DSCI)

---

## 1. Document Editions & Dual-Track Baseline

Two distinct editions of the DST Task Force Report exist:
1. **February 2026 Edition**: *Report of the Task Force on Migration to Post-Quantum Cryptography* (`Report_TaskForce_PQMigration_4Feb26 (v1).pdf`).
2. **May 2026 Edition**: *Implementation of Quantum Safe Ecosystem in India — Report of the Task Force* (`Quantum-Safe-Ecosystem-in-India.pdf`, official DST portal link: https://dst.gov.in/sites/default/files/Quantum-Safe-Ecosystem-in-India.pdf).

> **Verification Rule**: Below, every claim records precisely which edition it was checked against. Any claim or section reference not directly read in that edition is explicitly marked **"not verified"**. Unread sections of the February 2026 edition are explicitly marked **"not verified"**.

---

## 2. Statement-by-Statement Audit

### S1 — Mandatory CBOM Submission from FY 2027–28
- **Claim in Project**: DST/NQM Task Force mandates CBOM submission in government procurement from FY 2027–28.
- **Checked Against**: **May 2026 Edition** (`Quantum-Safe-Ecosystem-in-India.pdf`).
- **Exact Location in PDF**: **Page 33, Section 7.0 (Sub-Group II summary)**. Under Milestone 1 ("Build Foundations," CII by 2027 / Enterprises by 2028), the report instructs organizations to conduct quantum risk analyses, treat crypto-agility as a guiding principle, and require vendors to start submitting Cryptographic Bills of Materials (CBOMs) from FY 2027–28 onward.
- **February 2026 Edition Status**: **Not verified** (edition unread).
- **Status**: ✅ **Verified in May 2026 edition (Page 33, Section 7.0)**.

---

### S2 — Critical Information Infrastructure (CII) vs. Enterprise Migration Deadlines
- **Claim in Project**: CII follows an accelerated 3-milestone timeline: Foundations by 2027, High-Priority Migration by 2028, Full PQC Adoption by 2029; Enterprises follow 2028 / 2030 / 2033.
- **Checked Against**: **May 2026 Edition** (`Quantum-Safe-Ecosystem-in-India.pdf`).
- **Exact Location in PDF**: **Page 36, Section 9.0 ("Recommendations of the Task Force")**, with supporting detail on **Pages 32–33**. Section 9.0 explicitly states CII sectors — government, strategic, defence, power, telecom, transport, and BFSI — follow the accelerated 2027/2028/2029 schedule, while regular enterprises follow 2028/2030/2033.
- **February 2026 Edition Status**: **Not verified** (edition unread).
- **Status**: ✅ **Verified in May 2026 edition (Page 36, Section 9.0; Pages 32–33)**.

---

### S3 — Crypto-Dependent Product Categories & Automated Discovery Tools
- **Claim in Project**: India defines cryptographic product categories that explicitly include automated cryptographic discovery and inventory tools.
- **Checked Against**: **May 2026 Edition** (`Quantum-Safe-Ecosystem-in-India.pdf`).
- **Exact Location in PDF**: **Pages 31–32, Section 6.0 (Sub-Group I summary)** and **Page 38 (Long-Term Actions)**. Section 6.0 states India will draft its own list of crypto-dependent product categories, built upon the CISA list (published 23 January 2026, reproduced in Annexure A), but adds automated cryptographic discovery/inventory tools and mobile phones as India-specific additions.
- **February 2026 Edition Status**: **Not verified** (edition unread).
- **Status**: ✅ **Verified in May 2026 edition (Pages 31–32, Section 6.0; Page 38)**.

---

### S4 — Required CBOM Technical Format (CycloneDX vs. Generic)
- **Claim in Project**: ECDAT exports CBOM in CycloneDX Specification 1.6 format.
- **Checked Against**: **May 2026 Edition** (`Quantum-Safe-Ecosystem-in-India.pdf`).
- **Exact Location in PDF**: Searched full extracted text for `CycloneDX` and `format`. **No mention of CycloneDX exists anywhere in the report**. The closest reference is a generic footnote near **Page 37** defining CBOM as *"a structured, machine-readable inventory"* — no specific schema or format standard (CycloneDX, SPDX, etc.) is named.
- **February 2026 Edition Status**: **Not verified** (edition unread).
- **Status**: ⚠️ **Format mandate not in DST report**. CycloneDX 1.6 CBOM export is implemented in ECDAT as an industry standard / best practice, but must **not** be claimed as a DST-mandated format.

---

### S5 — "Section 3.4 / Annexure B / Priority Category 1 / National Product Categorization Matrix"
- **Claim in Earlier Drafts**: Earlier documentation cited "Section 3.4", "Annexure B", "Priority Category 1", or "National Product Categorization Matrix".
- **Checked Against**: **May 2026 Edition** (`Quantum-Safe-Ecosystem-in-India.pdf`).
- **Audit Findings**:
  - A section numbered "3.4" genuinely appears in the May 2026 PDF, but it is located in **Annexure-I** (nested within Annexure B, near **Page 71**), and its subject matter is testing Secure Elements/TEE/PUFs — completely unrelated to product categorization or discovery tools.
  - Zero instances of "Priority Category 1" or "National Product Categorization Matrix" exist anywhere in the May 2026 document.
- **Status**: 🚫 **Fabricated labels**. These were fabricated phrases rather than imprecise citations. They have been completely expunged from the codebase (`docs/PS_MAPPING.md`, `app.py`, `README.md`).

---

### S6 — Mosca's Inequality ($X + Y > Z$) & MWQRS Implementation
- **Claim in Project**: Quantum risk scoring evaluated via Mosca's Inequality.
- **Checked Against**: **May 2026 Edition** (`Quantum-Safe-Ecosystem-in-India.pdf`).
- **Exact Location in PDF**: General conceptual framework of Mosca's inequality is referenced in migration literature. Exact page/section number in PDF: **not verified** (not read directly from PDF page).
- **Codebase Implementation**: `ecdat_scoring.py` implements a **Mosca-inspired composite index (0–100 scale)** weighting algorithm vulnerability (35%), key size (20%), TLS version (15%), cert expiry (10%), and service criticality (20%). It does **not** evaluate the mathematical boolean $X + Y > Z$.
- **February 2026 Edition Status**: **Not verified** (edition unread).
- **Status**: ⚠️ **Partial / Mosca-inspired**. Documented honestly as "Mosca-inspired" in code docstrings, `docs/PS_MAPPING.md` row (iii), and `app.py`.

---

### S7 — Baseline "10 Assets" Breakdown
- **Claim in Earlier Drafts**: The baseline "10 assets" comprises 4 public hosts + 3 local test endpoints + 3 seeded service records.
- **Checked Against**: Codebase history (`ecdat_inventory.py`, `hosts.txt`, git log).
- **Audit Findings**: `seed_demo_data()` actually seeds 6 service records (not 3). The pipeline scanned 39 endpoints. The assertion of "4 public + 3 local + 3 seeded" was an ad-hoc arithmetic breakdown with no evidentiary basis in git commits or official project documents.
- **Status**: ⚠️ **Not verified**. Marked as "not verified" in `docs/PS_MAPPING.md`, `app.py`, and this audit.

---

### S8 — "Harvest Now, Decrypt Later" (HNDL) Threat
- **Claim in Project**: HNDL is the core operational threat driving PQC migration urgency.
- **Checked Against**: **May 2026 Edition** (`Quantum-Safe-Ecosystem-in-India.pdf`).
- **Exact Location in PDF**: HNDL is discussed as a primary motivation for rapid migration timelines. Exact page number: **not verified** (not read directly).
- **February 2026 Edition Status**: **Not verified** (edition unread).
- **Status**: ✅ Conceptually accurate; exact page citation marked **not verified**.

---

### S9 — NIST Post-Quantum Cryptographic Standards (FIPS 203, 204, 205)
- **Claim in Project**: Algorithms map to NIST FIPS 203 (ML-KEM-768), FIPS 204 (ML-DSA-65), and FIPS 205 (SLH-DSA).
- **Checked Against**: NIST official standards (finalized August 2024; primary source) and DST recommendations for standard adoption.
- **Status**: ✅ **Verified** against NIST FIPS 203/204/205 standards.

---

## 3. Summary of Verification States

| Claim Key | Claim Description | Edition Checked | Page / Section | Verified? |
|---|---|---|---|---|
| **S1** | CBOM submission mandate from FY 2027–28 | May 2026 | Page 33, Section 7.0 | ✅ **Verified** |
| **S2** | CII (2027/2028/2029) vs Enterprise (2028/2030/2033) deadlines | May 2026 | Page 36, Sec 9.0; pp. 32–33 | ✅ **Verified** |
| **S3** | Crypto product categories include discovery/inventory tools | May 2026 | pp. 31–32, Sec 6.0; p. 38 | ✅ **Verified** |
| **S4** | Mandatory CycloneDX 1.6 format | May 2026 | Page 37 (generic footnote) | ⚠️ **Not a DST mandate** (No format specified) |
| **S5** | Section 3.4 / Priority Category 1 / Nat'l Matrix | May 2026 | p. 71 (3.4 is SE/TEE/PUF) | 🚫 **Fabricated labels** (Expunged) |
| **S6** | Mosca's Inequality ($X+Y>Z$) direct evaluation | May 2026 | Not read directly | ⚠️ **Not verified** (Code is Mosca-inspired composite) |
| **S7** | "10 assets" breakdown (4 public + 3 local + 3 seeded) | Codebase | N/A | ⚠️ **Not verified** (Ad-hoc arithmetic, no evidence) |
| **S8** | HNDL exact page | May 2026 | Not read directly | ⚠️ Page **not verified** |
| **All unread** | February 2026 edition text & unread May sections | Feb 2026 / May 2026 | Unread pages | ⚠️ **Not verified** |
