# ECDAT Detailed Test Report

**Project:** Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)  
**Report type:** Extended behavioral and regression testing  
**Test date:** 2026-09-19  
**Final result:** **PASS**

## 1. Executive Summary

The original automated test suite was extended with seven additional behavioral and integration tests covering boundary values, invalid or unsupported input, persistence behavior, CBOM output, and missing-record handling.

The first extended run exposed three defects. All three were corrected and the complete suite passed after the fixes.

| Result | Count |
|---|---:|
| Original tests passed | 14 |
| Additional tests added | 7 |
| Final tests passed | 21 |
| Final tests failed | 0 |
| Final runtime | 0.66 seconds |

## 2. Test Scope

The additional tests were intentionally different from the existing tests. They focused on:

- Blank and comment-only scan target lines.
- Default HTTPS port and custom port parsing.
- The exact certificate-expiry boundary of 30 days.
- Unsupported single-file input to the source scanner.
- Database upsert behavior while preserving historical scan records.
- CycloneDX 1.6 CBOM crypto component output.
- Migration simulation when the requested asset does not exist.

## 3. Additional Test Cases

| Test case | Expected behavior | Result |
|---|---|---|
| Blank target line | Returns `None` and is ignored | PASS |
| Comment-only target line | Returns `None` and is ignored | PASS |
| Host without port | Defaults to port `443` | PASS |
| Host with custom port | Preserves the supplied port, such as `8443` | PASS |
| Certificate expires in exactly 30 days | Adds `CERT_EXPIRING_SOON:30d` | PASS |
| Unsupported single file | Skips unsupported extensions and returns no findings | PASS |
| Re-ingest the same asset | Updates current inventory while retaining two history records | PASS |
| CBOM export | Produces CycloneDX `1.6` with a `cryptographic-asset` component | PASS |
| Missing migration asset | Returns a clear asset-not-found error | PASS |

## 4. Defects Found and Corrected

### 4.1 Certificate expiry boundary

Certificates expiring exactly 30 days from the scan were not classified as expiring soon because the implementation used a strict less-than comparison.

**Correction:** The boundary now includes 30 days, so the condition is inclusive.

**File:** `ecdat_scanner.py`

### 4.2 Unsupported single-file scanning

Passing an unsupported file such as `notes.md` directly to `scan_source_directory` caused it to be scanned instead of skipped.

**Correction:** Direct file scans now run only for extensions listed in `SUPPORTED_EXTENSIONS`.

**File:** `ecdat_codescanner.py`

### 4.3 Migration simulation with a new database

Calling `simulate_migration` with a database path that did not yet contain ECDAT tables raised a SQLite error instead of returning the documented missing-asset response.

**Correction:** The simulator now initializes the database schema before querying the requested asset.

**File:** `ecdat_simulator.py`

## 5. Verification Commands

The original suite passed with 14 tests. The expanded suite was then executed with:

```text
python -m pytest -q
```

Final output:

```text
21 passed in 0.66s
```

The new tests are located in:

```text
tests/test_additional_behavior.py
```

## 6. Final Assessment

The tested ECDAT behaviors are working as expected for the covered scenarios. The fixes are limited to boundary handling, input filtering, and database initialization. No additional failures were observed in the final regression run.

This report covers automated tests only. It does not replace manual verification of the Streamlit dashboard, live TLS connectivity to external hosts, or deployment-specific behavior.
