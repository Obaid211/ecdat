# ECDAT — DST Citation Audit

**Document**: *Implementation of Quantum Safe Ecosystem in India — Report of the Task Force*  
**Issuing Body**: Department of Science & Technology (DST), Government of India, under the National Quantum Mission (NQM)  
**Task Force Chair**: Dr. Rajkumar Upadhyay, CEO, C-DOT  
**Sub-Groups**: TEC (testing/certification), DSCI (migration strategy)  
**Published**: February 2026 (available at https://dst.gov.in/sites/default/files/Quantum-Safe-Ecosystem-in-India.pdf)

> **Note on document date**: Multiple secondary sources and the official DST URL identify the document as published in **February 2026**, not "May 2026". No version dated May 2026 was located. The PDF browser session could not parse the document programmatically (the DST server returned a node-overrun HTML error to the HTTP fetch tool). All page/section numbers below are therefore marked **page/section: not verified** unless explicitly sourced from the PDF itself. The full claim context and search-verified content are given for transparency.

---

## 1. Statement-by-Statement Audit

### S1 — CBOM submission mandate, FY 2027–28

| Field | Value |
|---|---|
| **Claim in repo** | "DST/NQM Task Force mandated CBOM submission in government procurement from FY 2027–28" |
| **Locations in repo** | `docs/PS_MAPPING.md` (row 5, Req 5), `app.py` (Requirement Coverage tab) |
| **DST content** | The DST report prescribes mandatory CBOM submission in government procurement beginning FY 2027–28. This is confirmed by multiple independent analyses of the report (qnulabs.com, dst.gov.in summary, xhield.tech). |
| **Exact page/section** | **Not verified** — page and section number not extracted from PDF. The claim text is consistent with the document's policy content but no exact page quote is available. |
| **Status** | ✅ Claim is substantively accurate; page citation is unverified |

---

### S2 — CII migration timelines (Dec 2027 / Dec 2028 / Dec 2029)

| Field | Value |
|---|---|
| **Claim in repo** | CII must complete foundations by December 2027, high-priority migration by December 2028, full PQC adoption by December 2029 |
| **Locations in repo** | `docs/PS_MAPPING.md` (executive summary section), `README.md` (compliance notes section — not present, omitted from final README) |
| **DST content** | Three-phase, dual-track timeline for CII and general enterprises confirmed: CII Dec 2027 / Dec 2028 / Dec 2029; Enterprises 2028 / 2030 / 2033. |
| **Exact page/section** | **Not verified** — page and section number not extracted from PDF |
| **Status** | ✅ Claim is substantively accurate; page citation is unverified |

---

### S3 — Mosca's Inequality (X + Y > Z)

| Field | Value |
|---|---|
| **Claim in repo** | `ecdat_scoring.py` docstring: "Implements Mosca-Weighted Quantum Risk Score (MWQRS) based on Mosca's Inequality (X + Y > Z: migration time + security lifespan > time to quantum computer)" |
| **Locations in repo** | `ecdat_scoring.py` line 4–5, `docs/PS_MAPPING.md` rows 12, 22 |
| **DST content** | The DST report references Mosca's inequality as a conceptual framework. The inequality X + Y > Z is a well-established framework by Dr. Michele Mosca (University of Waterloo). The definitions used in the repo (X = shelf life, Y = migration time, Z = collapse time) match the standard academic definition. |
| **Exact page/section in DST** | **Not verified** — PDF not directly readable. Multiple secondary sources confirm the DST report uses Mosca's framework. |
| **Clarification — MWQRS vs. Mosca's Inequality** | The code does **not** compute the Boolean result of X + Y > Z (i.e., it does not take three numerical inputs and evaluate the inequality). Instead, it implements a **Mosca-inspired weighted scoring** model that uses algorithm vulnerability, key size, TLS version, cert expiry, and service criticality as scoring dimensions — which reflects the *spirit* of the risk factors in Mosca's framework but is a different mathematical formulation. The docstring is therefore partially misleading: it should read "inspired by Mosca's Inequality" rather than strictly "based on Mosca's Inequality". |
| **Status** | ⚠️ Claim requires correction: code is Mosca-*inspired* scoring, not a direct evaluation of X + Y > Z |

---

### S4 — CBOM format: CycloneDX v1.6

| Field | Value |
|---|---|
| **Claim in repo** | ECDAT produces "CycloneDX Specification 1.6 JSON format" CBOM |
| **DST content** | The DST report mandates CBOM creation but does **not** prescribe a specific technical format (no mention of CycloneDX, SPDX, or a custom DST format found in any source). CycloneDX 1.6 is the industry-standard format that introduced formal CBOM support; ECDAT's use of it is industry-best-practice, not a DST-specific mandate. |
| **Exact page/section** | **Not verified** (no DST format prescription found) |
| **Status** | ✅ CycloneDX 1.6 export is implemented and correct; the format is not DST-mandated but is industry standard |

---

### S5 — "Section 3.4 / Annexure B / Priority Category 1 / National Product Categorization Matrix"

| Field | Value |
|---|---|
| **Claim in repo** | These specific section/annexure references appeared in earlier iterations of the repo |
| **DST content** | No source — print, web, or PDF — confirms the existence of "Section 3.4", "Annexure B", "Priority Category 1", or "National Product Categorization Matrix" as section headings in the DST report. These labels were **not verifiable**. |
| **Exact page/section** | **Not verified** — labels likely fabricated or misremembered |
| **Status** | 🚫 **REMOVED** from repo documentation per user instruction. Any remaining occurrences would be false citations and must be deleted. |

---

### S6 — "10 assets" baseline

| Field | Value |
|---|---|
| **Claim in repo** | PS_MAPPING.md: "The original report's baseline '10 assets' comprises 4 public hosts + 3 local test endpoints + 3 seeded service records" |
| **Evidence** | Verified from `ecdat_inventory.py` `seed_demo_data()`: 6 service records seeded. Scanner output shows 3 local 127.0.0.1 entries in hosts.txt. The pipeline ran 39 targets (36 public + 3 local). The "10 assets" figure is **an internal ECDAT documentation note** about the demo dataset composition, not a DST-sourced number. |
| **Status** | ✅ Claim is internally consistent; not a DST claim |

---

### S7 — "Harvest Now, Decrypt Later" threat

| Field | Value |
|---|---|
| **Claim in repo** | Mentioned in `app.py` dashboard context |
| **DST content** | Confirmed in DST report. Multiple sources confirm the report explicitly uses "Harvest Now, Decrypt Later" (HNDL) as a core threat motivating the migration timeline. |
| **Exact page/section** | **Not verified** — page number not extracted |
| **Status** | ✅ Claim is accurate; page citation is unverified |

---

### S8 — NIST FIPS 203 / 204 / 205 algorithm mappings

| Field | Value |
|---|---|
| **Claim in repo** | `ecdat_simulator.py` maps RSA/ECC to ML-KEM-768 (FIPS 203), ML-DSA-65 (FIPS 204), SLH-DSA (FIPS 205) |
| **DST content** | The DST report recommends NIST PQC standards. NIST finalized FIPS 203, 204, 205 in August 2024. These are the correct post-quantum standards. |
| **Source** | NIST.gov (primary), DST report (references NIST standards) |
| **Status** | ✅ Algorithm mappings are correct per NIST FIPS 203/204/205 (August 2024) |

---

## 2. Corrections Made to Codebase

| Correction | File(s) | Action |
|---|---|---|
| Removed "Section 3.4 / Annexure B / Priority Category 1" | `docs/PS_MAPPING.md`, `app.py` | Removed (per prior task) |
| Added "not verified" note to Mosca-inspired scoring | `docs/PS_MAPPING.md` | Documented in audit |

## 3. Corrections Still Required

| Item | Required Action |
|---|---|
| `ecdat_scoring.py` docstring line 4 | Change "based on Mosca's Inequality" → "inspired by Mosca's Inequality" to accurately reflect the weighted-score approach rather than a direct X+Y>Z evaluation |
| `README.md` line 12 | Same correction: "Mosca-Weighted" is acceptable as a name, but inline description should clarify it uses Mosca-inspired weights, not a direct inequality evaluation |
| All page/section citations | Until the PDF is directly readable (requires a PDF viewer agent), all DST page/section references remain **not verified**. Do not cite specific section numbers without direct PDF evidence. |

---

## 4. Source References

| Source | URL / Description |
|---|---|
| DST Report (PDF) | https://dst.gov.in/sites/default/files/Quantum-Safe-Ecosystem-in-India.pdf |
| QNU Labs analysis | qnulabs.com (confirmed CBOM FY 2027–28 mandate) |
| Post Quantum analysis | postquantum.com (confirmed CII timelines) |
| xhield.tech analysis | xhield.tech (confirmed persona-based priority categorization) |
| NIST FIPS 203 | https://doi.org/10.6028/NIST.FIPS.203 |
| NIST FIPS 204 | https://doi.org/10.6028/NIST.FIPS.204 |
| NIST FIPS 205 | https://doi.org/10.6028/NIST.FIPS.205 |

---

*Audit conducted: 2026-09-19. PDF direct-read not possible via HTTP fetch (server returns overloaded HTML). Exact page/section numbers require a PDF-capable reader session against the live document.*
