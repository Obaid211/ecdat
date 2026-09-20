# ECDAT Stage 1 — Setup & Test Guide

## 1. Install Python (if not already installed)
Check first:
```
python3 --version
```
Need Python 3.8+. If not installed, download from python.org.

## 2. Install the one dependency
```
pip install -r requirements.txt
```
(On some systems you may need: `pip install cryptography --break-system-packages`)

## 3. Test A — Scan real internet hosts
```
python3 ecdat_scanner.py --hosts hosts.txt --out real_scan_results.json
```
This scans google.com, github.com, python.org, wikipedia.org (edit hosts.txt to add your own).
You'll see a summary table in the terminal, and full details in real_scan_results.json.

## 4. Test B — Reproduce the weak/strong crypto demo locally (Two-Terminal Requirement)
This is what generated the screenshot for your PPT.

> **CRITICAL DEMO REQUIREMENT**: For local endpoints (127.0.0.1:8443, 8444, 8445) to respond during any scan or pipeline execution, `generate_test_certs.py` MUST be running continuously in a dedicated terminal. If closed, the scan will report "Connection refused".

**Terminal 1 (Keep running continuously):**
```bash
python generate_test_certs.py
```
Leave it running. It starts 3 local mock servers:
- legacy-portal.internal (weak, 1024-bit RSA, expiring soon) on port 8443
- api-gateway.internal (strong, 3072-bit RSA) on port 8444
- auth-service.internal (medium, 2048-bit RSA) on port 8445

**Terminal 2 (Run scan or full pipeline):**
```bash
# Scan individual endpoints:
python ecdat_scanner.py --host 127.0.0.1:8443 --out weak_test.json
python ecdat_scanner.py --host 127.0.0.1:8444 --out strong_test.json
python ecdat_scanner.py --host 127.0.0.1:8445 --out medium_test.json

# Or run the complete automated pipeline:
python cli.py pipeline --hosts hosts.txt

# Or launch the Streamlit dashboard:
streamlit run app.py
```
You will see the weak endpoint (8443) flagged with `WEAK_RSA_KEY_SIZE` and `CERT_EXPIRING_SOON`, while the other two show valid configurations.

## 5. What's NOT included (still needs building)
This package only contains Stage 1 (Discovery/Scanning). Still to build:
- Stage 3: SQLite inventory database (schema is in ECDAT_Technical_Approach.md)
- Stage 4: Weighted risk scoring engine (formula is in ECDAT_Technical_Approach.md)
- Stage 5: Dashboard (Streamlit or React)
- Stage 6: Migration simulator
- Source code / binary / container scanning (separate from this TLS scanner)

## Troubleshooting
- "Connection refused" errors on 127.0.0.1 tests → make sure generate_test_certs.py
  is still running in its own terminal window when you run the scanner
- If real internet hosts show identical/wrong certificate info → you may be on a
  network with TLS interception (corporate firewall, some VPNs, some sandboxed
  dev environments) — try a different network, e.g. mobile hotspot
- "ee key too small" errors → this is expected for very old OpenSSL versions
  refusing weak keys; not an issue with the scanner itself
