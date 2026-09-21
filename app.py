"""
ECDAT - Stage 5: Executive Dashboard & Interactive Visualizer
--------------------------------------------------------------
Streamlit visual web application showcasing real-time inventory, MWQRS quantum risk scoring,
CycloneDX CBOM exports, dependency graph visualization, PQC migration simulation, and live scanner runner.
"""

import json
import sqlite3
import urllib.parse
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import networkx as nx
import streamlit as st
from pathlib import Path

import ecdat_inventory as inv
import ecdat_scoring as score_eng
import ecdat_simulator as sim_eng
import ecdat_codescanner as code_eng
import ecdat_scanner as scanner_core
import ecdat_offline as offline_eng
import ecdat_remediation as rem_eng
import ecdat_threat_timeline as threat_eng
import ecdat_containerscanner as cnt_eng
import ecdat_apiscanner as api_eng
import ecdat_diff as diff_eng

import os
import shutil
from datetime import datetime, timezone

import ecdat_ai
from ecdat_guide_ui import render_guide_and_assistant


st.set_page_config(
    page_title="ECDAT — Enterprise Cryptographic Discovery",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for polished modern cyber aesthetic
st.markdown("""
<style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 800;
        background: linear-gradient(90deg, #00C9FF 0%, #92FE9D 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0rem;
    }
    .sub-header {
        font-size: 1.0rem;
        color: #888;
        margin-bottom: 1.5rem;
    }
    .metric-box {
        background-color: #1E222D;
        border-radius: 10px;
        padding: 15px;
        border: 1px solid #2E3440;
        text-align: center;
    }
    .stTabs [data-baseweb="tab-list"] {
       gap: 14px;
       overflow-x: auto !important;
       overflow-y: hidden;
       white-space: nowrap;
       scrollbar-width: thin;
       padding-bottom: 8px;
    }

    .stTabs [data-baseweb="tab"] {
        height: 45px;
        white-space: nowrap !important;
        min-width: 130px !important;
        width: auto !important;
        flex-shrink: 0 !important;
        border-radius: 6px;
        padding: 8px 14px !important;
    }
</style>
""", unsafe_allow_html=True)


# Sidebar Actions
st.sidebar.image(
    "https://img.icons8.com/color/96/shield-with-encryption.png", width=70)
st.sidebar.title("Pipeline Controls")


@st.cache_resource
def get_ai_pool():
    """One key pool per server process so cooldowns and disabled keys persist across reruns."""
    return ecdat_ai.KeyPool.from_env()


OFFLINE_DB_PATH = "offline_ecdat.db"


def get_cached_dataset_label(db_path):
    fallback_db = Path(db_path)
    if not fallback_db.exists():
        return "cached dataset unavailable"

    try:
        conn = sqlite3.connect(fallback_db)
        cursor = conn.cursor()
        cursor.execute("SELECT MAX(scanned_at), COUNT(*) FROM crypto_assets")
        latest_scan, asset_count = cursor.fetchone()
        conn.close()
    except sqlite3.Error:
        return "cached dataset metadata unavailable"

    if latest_scan:
        return f"cached public-host dataset, latest scan {latest_scan}, {asset_count} assets"
    return f"cached public-host dataset, scan date unavailable, {asset_count} assets"


# Mode Toggle: Live vs Cached vs Offline
mode_selection = st.sidebar.radio(
    "Data Source / Operating Mode",
    ["🟢 LIVE MODE", "🟡 CACHED MODE", "🔵 OFFLINE MODE"],
    index=0,
    help="LIVE = current ecdat.db | CACHED = pre-saved demo_fallback.db | OFFLINE = local sovereign-ready snapshot"
)

if mode_selection == "🟡 CACHED MODE":
    fallback_db = Path("demo_fallback.db")
    if fallback_db.exists():
        DB_PATH = "demo_fallback.db"
        cached_dataset_label = get_cached_dataset_label(DB_PATH)
        st.sidebar.warning(
            f"🟡 CACHED MODE ACTIVE\nUsing {cached_dataset_label}. Live database modifications are isolated.")
    else:
        DB_PATH = inv.DEFAULT_DB_PATH
        st.sidebar.error(
            "⚠️ `demo_fallback.db` not found! Falling back to live `ecdat.db`.")

elif mode_selection == "🔵 OFFLINE MODE":
    DB_PATH = OFFLINE_DB_PATH
    offline_exists = Path(OFFLINE_DB_PATH).exists()

    st.sidebar.markdown("### 🔵 OFFLINE MODE ACTIVE")
    st.sidebar.markdown(
        """
| Feature | Status |
|---|---|
| 🌐 Internet | ❌ Blocked |
| ☁️ External APIs | ❌ Blocked |
| 🔭 External TLS Scan | ❌ Blocked |
| 🔒 Local TLS Scan | ✅ Enabled |
| 📄 Local Certificates | ✅ Enabled |
| 🔍 Source Scanner | ✅ Enabled |
| 🕸️ Dependency Graph | ✅ Enabled |
| 💥 Blast Radius | ✅ Enabled |
| 🚀 PQC Simulator | ✅ Enabled |
| 📦 CBOM Export | ✅ Enabled |
| 📊 Reports | ✅ Enabled |
        """
    )

    if offline_exists:
        snapshot_time = datetime.fromtimestamp(
            os.path.getmtime(OFFLINE_DB_PATH)
        ).strftime("%Y-%m-%d %H:%M:%S")
        st.sidebar.caption(
            f"DB: `offline_ecdat.db` | Last updated: {snapshot_time}")
    else:
        st.sidebar.warning(
            "⚠️ No offline database yet — click Initialize below.")

    st.sidebar.markdown("---")
    st.sidebar.markdown("**Offline Data Controls**")

    if st.sidebar.button("🏗️ Initialize Offline Demo",
                         help="Build offline_ecdat.db from local TLS servers & cert files. Does NOT copy ecdat.db."):
        with st.sidebar:
            with st.spinner("Initializing offline demo from local sources..."):
                result = offline_eng.initialize_offline_demo(OFFLINE_DB_PATH)
        tls_ok = result['tls_scanned']
        tls_fail = result['tls_failed']
        total = result['assets_total']
        if tls_ok > 0 or result['cert_files_analyzed'] > 0:
            st.sidebar.success(
                f"✅ Offline demo ready!\n"
                f"TLS scanned: {tls_ok} | Failed: {tls_fail}\n"
                f"Cert files: {result['cert_files_analyzed']}\n"
                f"Total assets: {total}"
            )
        else:
            st.sidebar.warning(
                f"⚠️ No local TLS servers reachable (start generate_test_certs.py first).\n"
                f"Cert files parsed: {result['cert_files_analyzed']} | Assets: {total}\n"
                + (f"Errors: {'; '.join(result['errors'][:3])}" if result['errors'] else "")
            )
        st.rerun()

    if st.sidebar.button("🔄 Refresh Offline Inventory",
                         help="Re-scan local TLS endpoints, cert files, and source code."):
        with st.sidebar:
            with st.spinner("Refreshing offline inventory..."):
                result = offline_eng.refresh_offline_inventory(OFFLINE_DB_PATH)
        st.sidebar.success(
            f"✅ Inventory refreshed!\n"
            f"TLS: {result['tls_scanned']} scanned | Cert files: {result['cert_files_analyzed']}\n"
            f"Code findings: {result['code_findings']} | Assets: {result['assets_total']}"
        )
        st.rerun()

    # Never silently fall back: if still missing after this point, init_db creates empty schema
    inv.init_db(OFFLINE_DB_PATH)

else:
    DB_PATH = inv.DEFAULT_DB_PATH
    st.sidebar.success(
        "🟢 LIVE MODE ACTIVE\nConnected to live operational database (`ecdat.db`).")

st.sidebar.markdown("---")

# Ensure DB is initialized & scored on load
inv.init_db(DB_PATH)

# Title & Info Header
st.markdown('<div class="main-header">ECDAT — Enterprise Cryptographic Discovery & Analysis Tool</div>',
            unsafe_allow_html=True)
st.markdown('<div class="sub-header">SIH26164 (NTRO / Post-Quantum Cryptography & Keyfactor AgileSec Pipeline Model)</div>', unsafe_allow_html=True)

if mode_selection == "🟡 CACHED MODE" and Path("demo_fallback.db").exists():
    st.info(
        f"🟡 **CACHED DEMO MODE ACTIVE**: Dashboard is rendering {get_cached_dataset_label(DB_PATH)} from `demo_fallback.db`.")
elif mode_selection == "🔵 OFFLINE MODE":
    offline_exists = Path(OFFLINE_DB_PATH).exists()
    if offline_exists:
        snap_line = f"Last updated: {datetime.fromtimestamp(os.path.getmtime(OFFLINE_DB_PATH)).strftime('%Y-%m-%d %H:%M:%S')}"
    else:
        snap_line = "No data yet — click **🏗️ Initialize Offline Demo** in the sidebar."
    st.info(
        f"🔵 **OFFLINE MODE — Sovereign Local Analysis** | "
        f"Database: `offline_ecdat.db` | {snap_line}  \n"
        f"Internet: ❌ Blocked · External APIs: ❌ Blocked · "
        f"Local TLS: ✅ · Source Scanner: ✅ · Dependency Graph: ✅ · PQC Simulator: ✅ · CBOM: ✅"
    )
    if not offline_exists:
        st.warning(
            "⚠️ **Offline database is empty.** Use the sidebar **🏗️ Initialize Offline Demo** button "
            "to build `offline_ecdat.db` from local TLS servers and certificate files.  \n"
            "Start local TLS test servers first: `python generate_test_certs.py`"
        )
else:
    st.caption(
        "🟢 **LIVE MODE ACTIVE**: Dashboard is rendering dynamic operational database from `ecdat.db`.")

if st.sidebar.button("🔄 Refresh Data & Recalculate Scores"):
    score_eng.score_all_assets(DB_PATH)
    st.sidebar.success("Database rescored successfully!")

if st.sidebar.button("🌱 Re-Seed Demo Services"):
    inv.seed_demo_data(DB_PATH)
    score_eng.score_all_assets(DB_PATH)
    st.sidebar.success("Demo services & dependencies re-seeded!")

report_path = Path(__file__).with_name("DETAILED_TEST_REPORT.md")
if report_path.exists():
    st.sidebar.download_button(
        label="📄 Download Detailed Test Report (.md)",
        data=report_path.read_text(encoding="utf-8"),
        file_name="DETAILED_TEST_REPORT.md",
        mime="text/markdown",
    )

st.sidebar.markdown("---")
st.sidebar.info("""
**SIH Problem Statement SIH26164**
- Discover → Inventory → Prioritize → Remediate
- Mosca's Inequality Quantum Scoring (MWQRS)
- NIST FIPS 203/204/205 PQC Migration
- CycloneDX CBOM Spec 1.6 Output
""")

# AI guide status (the app works fully without keys; the guide falls back to built-in answers)
st.sidebar.markdown("---")
st.sidebar.caption(get_ai_pool().status_text())
st.sidebar.caption("New here? Open the 🧭 Guided Tour & Assistant tab.")

# Load Scored Assets
scored_assets = score_eng.score_all_assets(DB_PATH)
df = pd.DataFrame(scored_assets)


def get_risk_band(score):
    if score >= 80:
        return "Critical", "Immediate remediation recommended"
    if score >= 50:
        return "Medium", "Review and plan remediation"
    return "Low", "No urgent cryptographic issue detected"


def explain_risk_flag(flag):
    if flag == "CERT_EXPIRED":
        return "The TLS certificate is expired, so browser trust can fail and users may see a security warning."
    if flag.startswith("CERT_EXPIRING_SOON"):
        return "The TLS certificate expires soon and should be renewed before the deadline."
    if flag.startswith("WEAK_RSA_KEY_SIZE"):
        return "The RSA certificate key is smaller than recommended, which increases cryptographic risk."
    if flag.startswith("DEPRECATED_TLS_VERSION"):
        return "The site is using an outdated TLS version and should be upgraded."
    return flag


def get_scan_verdict(res, mwqrs_score):
    flags = res.get("risk_flags") or []
    if res.get("status") != "success":
        return (
            "Scan Failed",
            "ECDAT could not complete a TLS handshake with this target.",
            "Check that the host is reachable and serving HTTPS on the selected port.",
            "error",
        )
    if "CERT_EXPIRED" in flags:
        return (
            "High Attention Needed",
            "The website certificate is expired.",
            "Renew or replace the TLS certificate immediately.",
            "error",
        )
    if any(flag.startswith("WEAK_RSA_KEY_SIZE") for flag in flags):
        return (
            "High Attention Needed",
            "The website uses a weak RSA certificate key.",
            "Upgrade the certificate to at least RSA 2048-bit, preferably 3072-bit or a suitable modern alternative.",
            "error",
        )
    if any(flag.startswith("CERT_EXPIRING_SOON") for flag in flags):
        return (
            "Needs Renewal Soon",
            "The website certificate is close to expiry.",
            "Renew the TLS certificate before users start seeing trust warnings.",
            "warning",
        )
    if mwqrs_score >= 80:
        return (
            "Critical Cryptographic Risk",
            "ECDAT calculated a critical MWQRS score for this endpoint.",
            "Prioritize this endpoint in the PQC and TLS remediation plan.",
            "error",
        )
    if mwqrs_score >= 50:
        return (
            "Medium Cryptographic Risk",
            "The endpoint is functional, but its cryptographic posture should be reviewed.",
            "Track it in the migration roadmap and review certificate strength, TLS version, and expiry.",
            "warning",
        )
    return (
        "No Immediate Issue Found",
        "ECDAT did not detect a weak-key or certificate-expiry warning for this endpoint.",
        "Keep monitoring certificate expiry and include the endpoint in periodic cryptographic inventory scans.",
        "success",
    )


# Define Tabs
# Define 14 Tabs covering all capabilities
(
    tab_dash,
    tab_inv,
    tab_rem,
    tab_threat,
    tab_graph,
    tab_pqc,
    tab_code,
    tab_cnt,
    tab_api,
    tab_diff,
    tab_comp,
    tab_cbom,
    tab_tls,
    tab_tour,
) = st.tabs([
    "📊 Executive Dashboard",
    "🗄️ Crypto Asset Inventory",
    "🎯 Remediation Center",
    "⏳ Threat Timeline",
    "🕸️ Dependency Graph",
    "🚀 PQC Migration Simulator",
    "🔍 Source Code Scanner",
    "🐳 Container Scanner",
    "🌐 API Crypto Scanner",
    "⏱️ Scan History & Diff",
    "🛡️ Compliance & Readiness",
    "📜 CBOM Studio",
    "⚡ Live TLS Scanner",
    "🧭 Guided Tour & Assistant"
])


# ---------------------------------------------------------
# TAB 1: EXECUTIVE DASHBOARD
# ---------------------------------------------------------
with tab_dash:
    if df.empty:
        st.warning(
            "No crypto assets scanned yet. Run a scan from the 'Live TLS Scanner' tab or run cli.py.")
    else:
        # Top KPI Metrics
        total_scanned = len(df)
        critical_count = len(df[df["risk_score"] >= 80.0])
        medium_count = len(df[(df["risk_score"] >= 50.0)
                           & (df["risk_score"] < 80.0)])
        safe_count = len(df[df["risk_score"] < 50.0])
        avg_score = round(df["risk_score"].mean(), 1)

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Scanned Endpoints",
                  total_scanned, delta="Database Records")
        c2.metric("Critical Quantum Risk (MWQRS ≥ 80)", critical_count,
                  delta=f"{round(critical_count/total_scanned*100, 1)}%", delta_color="inverse")
        c3.metric("Medium Quantum Risk (50-79)", medium_count)
        c4.metric("Average System MWQRS", f"{avg_score} / 100")
        n_local_top = len(df[df["host"].astype(str).str.startswith("127.")])
        n_public_top = total_scanned - n_local_top
        st.caption(
            f"📌 {total_scanned} total DB records ({n_public_top} public-host scans + {n_local_top} local demo fixtures).")

        # Measured Performance Benchmark (Capability 13)
        scan_json_path = Path("scan_results.json")
        if scan_json_path.exists():
            try:
                with open(scan_json_path, "r", encoding="utf-8") as f:
                    bench_raw = json.load(f)
                bench_metrics = scanner_core.calculate_scan_benchmark(
                    bench_raw)
                st.markdown("---")
                st.markdown(
                    "### ⚡ Measured Discovery & Risk Flagging Performance")
                scan_file_mtime = datetime.fromtimestamp(
                    scan_json_path.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
                st.caption(f"📌 {bench_metrics['benchmark_label']} — Derived from genuine TLS handshake timings, not hardcoded assertions. "
                           f"Snapshot from scan_results.json (last updated {scan_file_mtime}); may differ from the live database counts above if a newer scan hasn't been re-ingested.")
                bm1, bm2, bm3, bm4, bm5 = st.columns(5)
                bm1.metric("Hosts Attempted", bench_metrics["total_attempted"])
                bm2.metric("Successful Connections",
                           bench_metrics["successful"])
                bm3.metric("Average Duration",
                           f"{bench_metrics['average_seconds']}s / host")
                bm4.metric("Median Duration",
                           f"{bench_metrics['median_seconds']}s")
                bm5.metric("Max Handshake Time",
                           f"{bench_metrics['max_seconds']}s")
            except Exception:
                pass

        st.markdown("---")

        # ---------------------------------------------------------
        # AGGREGATE PUBLIC HOST SAMPLE STATISTICS PANEL
        # ---------------------------------------------------------
        st.markdown("### 🌐 Aggregate Public Host Scan Statistics")

        # Filter real scanned hosts (excluding local loopback / demo seeds)
        real_df = df[~df["host"].str.startswith(
            "127.")].copy() if not df.empty else pd.DataFrame()
        n_attempted = len(real_df)
        n_scanned = len(real_df[real_df["status"] ==
                        "success"]) if not real_df.empty else 0
        n_unreachable = len(
            real_df[real_df["status"] == "unreachable"]) if not real_df.empty else 0

        # Quantum Vulnerable Breakdown (RSA vs ECC)
        if not real_df.empty and n_scanned > 0:
            rsa_count = len(real_df[real_df["cert_key_type"].astype(
                str).str.contains("RSA", na=False)])
            ecc_count = len(real_df[real_df["cert_key_type"].astype(
                str).str.contains("ECC", na=False)])
            qv_pct = round((rsa_count + ecc_count) / n_scanned * 100, 1)
        else:
            qv_pct = 0.0

        latest_scan = real_df["scanned_at"].max(
        ) if not real_df.empty and "scanned_at" in real_df and not real_df["scanned_at"].isnull().all() else "N/A"

        p1, p2, p3, p4, p5 = st.columns(5)
        p1.metric("Attempted Hosts", n_attempted)
        p2.metric("Successfully Scanned", n_scanned)
        p3.metric("Unreachable Hosts", n_unreachable)
        p4.metric("Quantum Vulnerable %",
                  f"{qv_pct}%", help="RSA or ECC public keys vulnerable to Shor's algorithm on a future CRQC")
        p5.metric("Sample Size (n)", n_scanned)

        col_st1, col_st2, col_st3 = st.columns(3)
        with col_st1:
            st.markdown("**TLS Version Distribution**")
            if not real_df.empty and "tls_version" in real_df:
                tls_counts = real_df["tls_version"].value_counts(
                ).reset_index()
                tls_counts.columns = ["TLS Version", "Count"]
                st.dataframe(tls_counts, use_container_width=True)
        with col_st2:
            st.markdown("**Key Algorithm Distribution**")
            if not real_df.empty and "cert_key_type" in real_df:
                algo_counts = real_df["cert_key_type"].value_counts(
                ).reset_index()
                algo_counts.columns = ["Algorithm", "Count"]
                st.dataframe(algo_counts, use_container_width=True)
        with col_st3:
            st.markdown("**MWQRS Risk Band Distribution**")
            if not real_df.empty and "risk_score" in real_df:
                real_df["Risk Band"] = pd.cut(
                    real_df["risk_score"],
                    bins=[-1, 49.9, 79.9, 100],
                    labels=["Safe (<50)", "Medium (50-79)", "Critical (≥80)"]
                )
                band_counts = real_df["Risk Band"].value_counts().reset_index()
                band_counts.columns = ["Risk Band", "Count"]
                st.dataframe(band_counts, use_container_width=True)

        st.caption(
            f"📌 **Disclaimer**: Point-in-time sample of public front pages (n={n_scanned} of {n_attempted} attempted, {n_unreachable} unreachable; scanned at {latest_scan}); not a market-wide claim. Risk classification informed by NIST SP 800-52 Rev. 2 guidelines.")
        st.markdown("---")

        col_left, col_right = st.columns(2)

        with col_left:
            st.subheader("Quantum Risk Level Distribution")
            df["Risk_Category"] = pd.cut(
                df["risk_score"],
                bins=[-1, 49.9, 79.9, 100],
                labels=["Quantum Safe / Low", "Medium Risk",
                        "Critical Risk (MWQRS ≥80)"]
            )
            risk_counts = df["Risk_Category"].value_counts().reset_index()
            risk_counts.columns = ["Category", "Count"]

            fig_donut = px.pie(
                risk_counts,
                values="Count",
                names="Category",
                hole=0.45,
                color="Category",
                color_discrete_map={
                    "Critical Risk (MWQRS ≥80)": "#EF4444",
                    "Medium Risk": "#F59E0B",
                    "Quantum Safe / Low": "#10B981"
                }
            )
            fig_donut.update_layout(margin=dict(t=20, b=20, l=20, r=20))
            st.plotly_chart(fig_donut, use_container_width=True)

        with col_right:
            st.subheader("Key Type & Bit Strength Breakdown")
            df["Key_Display"] = df.apply(
                lambda x: f"{x['cert_key_type']} {x['cert_key_size_bits']}b" if pd.notnull(
                    x['cert_key_size_bits']) else str(x['cert_key_type']),
                axis=1
            )
            key_counts = df["Key_Display"].value_counts().reset_index()
            key_counts.columns = ["Key_Type", "Count"]

            fig_bar = px.bar(
                key_counts,
                x="Key_Type",
                y="Count",
                color="Key_Type",
                text="Count",
                labels={"Key_Type": "Certificate Key Specification",
                        "Count": "Asset Count"},
                color_discrete_sequence=px.colors.qualitative.Pastel
            )
            fig_bar.update_layout(
                showlegend=False, margin=dict(t=20, b=20, l=20, r=20))
            st.plotly_chart(fig_bar, use_container_width=True)

        st.subheader("🔥 Top Vulnerable Cryptographic Assets")
        top_vuln = df.sort_values(by="risk_score", ascending=False).head(5)
        st.dataframe(
            top_vuln[["host", "port", "tls_version", "cert_key_type",
                      "cert_key_size_bits", "risk_score", "service_name", "risk_flags"]],
            use_container_width=True
        )


# ---------------------------------------------------------
# TAB 2: CRYPTO ASSET INVENTORY (Capability 1)
# ---------------------------------------------------------
with tab_inv:
    st.subheader("🗄️ Normalized Cryptographic Asset Inventory")
    st.caption("First-class cryptographic inventory backed by the SQLite operational database. Fully normalized across host, algorithm, key size, certificate validity, service criticality, and PQC readiness.")

    norm_assets = inv.get_normalized_inventory(DB_PATH)
    inv_df = pd.DataFrame(norm_assets)

    if inv_df.empty:
        st.info("No cryptographic assets currently inventoried.")
    else:
        # Multi-attribute Filter Controls
        with st.expander("🔍 Inventory Search & Filter Controls", expanded=True):
            f_col1, f_col2, f_col3, f_col4 = st.columns(4)
            with f_col1:
                search_term = st.text_input("Search Host or Service", "")
                sev_options = ["All"] + \
                    sorted(list(inv_df["severity"].dropna().unique()))
                selected_sev = st.selectbox("Filter by Severity", sev_options)
            with f_col2:
                algo_options = [
                    "All"] + sorted(list(inv_df["algorithm_category"].dropna().unique()))
                selected_algo = st.selectbox(
                    "Algorithm Category", algo_options)
                crit_options = [
                    "All"] + sorted(list(inv_df["service_criticality"].dropna().unique()))
                selected_crit = st.selectbox(
                    "Service Criticality", crit_options)
            with f_col3:
                tls_options = [
                    "All"] + sorted(list(inv_df["tls_version"].dropna().unique()))
                selected_tls = st.selectbox("TLS Version", tls_options)
                pqc_options = [
                    "All"] + sorted(list(inv_df["migration_status"].dropna().unique()))
                selected_pqc = st.selectbox("Migration Status", pqc_options)
            with f_col4:
                filter_expiring_only = st.checkbox(
                    "Show Approaching Expiry (≤90 days)", False)
                filter_vulnerable_only = st.checkbox(
                    "Show Quantum-Vulnerable Only", False)

        # Apply Filters
        filtered_inv = inv_df.copy()
        if search_term:
            filtered_inv = filtered_inv[
                filtered_inv["host"].str.contains(search_term, case=False, na=False) |
                filtered_inv["service"].str.contains(
                    search_term, case=False, na=False)
            ]
        if selected_sev != "All":
            filtered_inv = filtered_inv[filtered_inv["severity"]
                                        == selected_sev]
        if selected_algo != "All":
            filtered_inv = filtered_inv[filtered_inv["algorithm_category"]
                                        == selected_algo]
        if selected_crit != "All":
            filtered_inv = filtered_inv[filtered_inv["service_criticality"]
                                        == selected_crit]
        if selected_tls != "All":
            filtered_inv = filtered_inv[filtered_inv["tls_version"]
                                        == selected_tls]
        if selected_pqc != "All":
            filtered_inv = filtered_inv[filtered_inv["migration_status"]
                                        == selected_pqc]
        if filter_expiring_only:
            filtered_inv = filtered_inv[
                filtered_inv["days_to_expiry"].notnull() & (
                    filtered_inv["days_to_expiry"] <= 90)
            ]
        if filter_vulnerable_only:
            filtered_inv = filtered_inv[
                filtered_inv["quantum_status"].str.contains(
                    "Quantum-Vulnerable", case=False, na=False)
            ]
        st.markdown(
            f"**Showing {len(filtered_inv)} of {len(inv_df)} cryptographic assets**")
        n_local_inv = len(
            inv_df[inv_df["host"].astype(str).str.startswith("127.")])
        st.caption(f"📌 {len(inv_df)} total includes {n_local_inv} local demo fixtures + historical records; public-host-only counts are shown on the Executive Dashboard.")
        st.dataframe(
            filtered_inv[[
                "asset_id", "host", "port", "service", "service_criticality",
                "algorithm", "key_size", "tls_version", "cipher_info",
                "days_to_expiry", "mwqrs", "severity", "quantum_status",
                "recommended_pqc", "migration_status", "source"
            ]],
            use_container_width=True
        )

        # Detailed Asset Card Inspector
        st.markdown("### 🔎 Deep-Dive Asset Inspection Card")
        asset_select_list = [
            f"ID {r['asset_id']}: {r['host']}:{r['port']} ({r['service']})" for _, r in filtered_inv.iterrows()]
        if asset_select_list:
            selected_asset_label = st.selectbox(
                "Select Asset to Inspect:", asset_select_list)
            sel_id = int(selected_asset_label.split(":")
                         [0].replace("ID", "").strip())
            sel_asset = next(
                (a for a in norm_assets if a["asset_id"] == sel_id), None)

            if sel_asset:
                ai1, ai2, ai3 = st.columns([1, 1, 1])
                with ai1:
                    st.markdown(
                        f"**Target:** `{sel_asset['host']}:{sel_asset['port']}`")
                    st.markdown(
                        f"**Service:** {sel_asset['service']} ({sel_asset['service_criticality']})")
                    st.markdown(f"**Source:** {sel_asset['source']}")
                    st.markdown(
                        f"**MWQRS Score:** **{sel_asset['mwqrs']} / 100** ({sel_asset['severity']})")
                with ai2:
                    st.markdown(
                        f"**Algorithm:** `{sel_asset['algorithm']}` ({sel_asset['key_size']} bits)")
                    st.markdown(
                        f"**Category:** {sel_asset['algorithm_category']}")
                    st.markdown(f"**TLS Version:** {sel_asset['tls_version']}")
                    st.markdown(f"**Cipher:** {sel_asset['cipher_info']}")
                with ai3:
                    st.markdown(
                        f"**Days to Expiry:** {sel_asset['days_to_expiry']} days")
                    st.markdown(
                        f"**Quantum Status:** {sel_asset['quantum_status']}")
                    st.markdown(
                        f"**Recommended PQC:** `{sel_asset['recommended_pqc']}`")
                    st.markdown(f"**Status:** {sel_asset['migration_status']}")

                with st.expander("X.509 Certificate Metadata & Detected Risk Flags", expanded=False):
                    st.write(f"**Subject:** {sel_asset['cert_subject']}")
                    st.write(f"**Issuer:** {sel_asset['cert_issuer']}")
                    st.write(
                        f"**Not After (Expiry):** {sel_asset['cert_expiry']}")
                    if sel_asset['risk_flags']:
                        st.write("**Detected Risk Flags:**")
                        for f in sel_asset['risk_flags']:
                            st.write(f"- `{f}`: {explain_risk_flag(f)}")
                    else:
                        st.write(
                            "No active risk flags detected for this asset.")

        # Export Normalized Inventory
        st.markdown("---")
        csv_data = inv.export_inventory_csv(DB_PATH)
        st.download_button(
            label="📥 Download Normalized Inventory (.csv)",
            data=csv_data,
            file_name="ecdat_normalized_inventory.csv",
            mime="text/csv",
        )


# ---------------------------------------------------------
# TAB 3: REMEDIATION CENTER (Capability 2)
# ---------------------------------------------------------
with tab_rem:
    st.subheader("🎯 Cryptographic Remediation Center & Priority Sequencing")
    st.caption("Actionable sequencing prioritizing vulnerable cryptographic assets using actual MWQRS scores, service operational criticality tiers, certificate expiry urgency, and graph blast radius.")

    remediation_plan = rem_eng.generate_remediation_plan(DB_PATH)

    if not remediation_plan:
        st.info("No assets requiring remediation found.")
    else:
        # Summary counts
        crit_rem_count = sum(
            1 for item in remediation_plan if item["mwqrs"] >= 80.0)
        urgent_exp_count = sum(
            1 for item in remediation_plan if item["days_to_expiry"] is not None and item["days_to_expiry"] <= 30)
        high_blast_count = sum(1 for item in remediation_plan if len(
            item["downstream_services"]) >= 2)

        rc1, rc2, rc3, rc4 = st.columns(4)
        rc1.metric("Prioritized Action Items", len(remediation_plan))
        rc2.metric("Critical MWQRS Items", crit_rem_count)
        rc3.metric("Urgent Expiries (≤30d)", urgent_exp_count)
        rc4.metric("High Blast Radius (≥2 Svc)", high_blast_count)

        st.markdown("---")
        st.markdown("### 📋 Sequenced Remediation Queue")

        for item in remediation_plan[:10]:
            with st.container():
                rank_badge = "🔴" if item["mwqrs"] >= 80 else (
                    "🟠" if item["mwqrs"] >= 50 else "🟢")
                st.markdown(
                    f"#### {rank_badge} #{item['priority_rank']} — `{item['target']}` ({item['service']})")

                c_m1, c_m2, c_m3, c_m4 = st.columns(4)
                c_m1.markdown(
                    f"**MWQRS:** `{item['mwqrs']}/100` ({item['severity']})")
                c_m2.markdown(f"**Criticality:** `{item['criticality']}`")
                c_m3.markdown(
                    f"**Algorithm:** `{item['algorithm']}` ({item['key_size']}b)")
                c_m4.markdown(
                    f"**Expires In:** `{item['days_to_expiry']} days`")

                st.markdown(f"**Why Prioritized:** {item['why_prioritized']}")
                st.markdown(
                    f"**Migration Direction:** `{item['migration_direction']}`")
                st.markdown(
                    f"**Dependency Impact:** {item['dependency_impact']}")

                with st.expander("View Prescribed Remediation Actions"):
                    for act in item["recommended_actions"]:
                        st.markdown(f"- {act}")

                st.markdown("---")

        # Export Remediation Plan
        exp_col1, exp_col2 = st.columns(2)
        with exp_col1:
            md_plan = rem_eng.export_remediation_markdown(remediation_plan)
            st.download_button(
                label="📄 Download Remediation Plan (.md)",
                data=md_plan,
                file_name="ecdat_remediation_plan.md",
                mime="text/markdown",
            )
        with exp_col2:
            json_plan = rem_eng.export_remediation_json(remediation_plan)
            st.download_button(
                label="💾 Download Remediation Plan (.json)",
                data=json_plan,
                file_name="ecdat_remediation_plan.json",
                mime="application/json",
            )


# ---------------------------------------------------------
# TAB 4: THREAT TIMELINE & URGENCY (Capability 3)
# ---------------------------------------------------------
with tab_threat:
    st.subheader(
        "⏳ Mosca-Inspired Cryptographic Threat Timeline & Migration Urgency")
    st.info(
        "💡 **Methodology Disclaimer**: This module implements a Mosca-inspired urgency framework: "
        "`Data Shelf-Life (Y) + Migration Effort (X) > Organizational Planning Horizon (Z)`.  \n"
        "It evaluates engineering urgency under defined planning assumptions. "
        "It does **NOT** claim to predict the exact arrival date of a Cryptographically Relevant Quantum Computer (CRQC)."
    )

    norm_assets_threat = inv.get_normalized_inventory(DB_PATH)
    if norm_assets_threat:
        st.markdown("### 🧮 Interactive Migration Urgency Calculator")
        threat_options = {
            f"{a['host']}:{a['port']} ({a['service']} - {a['algorithm']})": a for a in norm_assets_threat}
        sel_threat_label = st.selectbox(
            "Select Asset to Evaluate Urgency:", list(threat_options.keys()))
        target_threat_asset = threat_options[sel_threat_label]

        tc1, tc2 = st.columns(2)
        with tc1:
            sens_choice = st.selectbox(
                "Data Sensitivity Tier:",
                list(threat_eng.DATA_SENSITIVITY_PROFILES.keys()),
                index=2 if target_threat_asset.get("service_criticality") == "P1" else (
                    3 if target_threat_asset.get("service_criticality") == "P0" else 1)
            )
            profile = threat_eng.DATA_SENSITIVITY_PROFILES[sens_choice]
            shelf_life_input = st.slider(
                "Estimated Data Security Shelf-Life (Y, years):",
                min_value=0.0, max_value=30.0,
                value=float(profile["default_shelf_life_years"]),
                step=0.5,
                help="Duration for which data encrypted with this key must remain confidential"
            )
        with tc2:
            mig_time_input = st.slider(
                "Estimated Migration Effort / Time (X, years):",
                min_value=0.5, max_value=10.0,
                value=float(profile["default_migration_time_years"]),
                step=0.5,
                help="Time required for system re-architecture, testing, and deployment"
            )
            horizon_input = st.slider(
                "Organizational Planning Assumption Horizon (Z, years):",
                min_value=3.0, max_value=25.0,
                value=10.0,
                step=1.0,
                help="Working planning assumption for post-quantum preparedness (NOT a guaranteed arrival date)"
            )

        # Calculate Urgency
        is_qv = "Quantum-Vulnerable" in target_threat_asset.get(
            "quantum_status", "")
        urgency_eval = threat_eng.calculate_migration_urgency(
            shelf_life_years=shelf_life_input,
            migration_time_years=mig_time_input,
            planning_horizon_years=horizon_input,
            data_sensitivity=sens_choice,
            asset_mwqrs=target_threat_asset.get("mwqrs", 0.0),
            is_quantum_vulnerable=is_qv,
            asset_name=f"{target_threat_asset['host']}:{target_threat_asset['port']}"
        )

        # Display Urgency Result Card
        st.markdown("---")
        u_col1, u_col2, u_col3 = st.columns(3)
        u_col1.metric("Combined Requirement (X + Y)",
                      f"{urgency_eval['combined_requirement_years']} years")
        u_col2.metric("Planning Assumption (Z)",
                      f"{urgency_eval['planning_horizon_years']} years")

        margin_label = f"{abs(urgency_eval['margin_or_deficit_years'])}y Deficit" if urgency_eval[
            'is_deficit'] else f"{urgency_eval['margin_or_deficit_years']}y Headroom"
        u_col3.metric("Timeline Margin / Deficit", margin_label)

        if urgency_eval["urgency_level"] == "CRITICAL":
            st.error(
                f"🚨 **Migration Urgency: CRITICAL**  \n{urgency_eval['summary_reason']}")
        elif urgency_eval["urgency_level"] == "HIGH":
            st.warning(
                f"⚠️ **Migration Urgency: HIGH**  \n{urgency_eval['summary_reason']}")
        elif urgency_eval["urgency_level"] == "MEDIUM":
            st.info(
                f"🟡 **Migration Urgency: MEDIUM**  \n{urgency_eval['summary_reason']}")
        else:
            st.success(
                f"✅ **Migration Urgency: LOW**  \n{urgency_eval['summary_reason']}")

        st.markdown(
            f"**Recommended Action:** {urgency_eval['recommended_action']}")

        # Full Threat Timeline Urgency Ranking Table
        st.markdown("---")
        st.markdown("### 📊 Inventory-Wide Threat Urgency Rankings")
        inventory_urgencies = threat_eng.evaluate_inventory_threat_urgency(
            DB_PATH, planning_horizon_years=horizon_input)
        u_df = pd.DataFrame(inventory_urgencies)
        st.dataframe(
            u_df[[
                "asset_name", "service", "criticality", "algorithm", "mwqrs",
                "data_sensitivity", "shelf_life_years", "migration_time_years",
                "combined_requirement_years", "margin_or_deficit_years", "urgency_level"
            ]],
            use_container_width=True
        )


# ---------------------------------------------------------
# TAB 5: DEPENDENCY GRAPH (Capability 5)
# ---------------------------------------------------------
with tab_graph:
    st.subheader("🕸️ Service Dependency Network Graph & Blast Radius Analysis")
    st.write("Visualizes services, directed dependencies, and topological blast radius calculated using NetworkX.")

    G = sim_eng.build_dependency_graph(DB_PATH)
    pos = nx.spring_layout(G, seed=42)

    # Compute node colors based on service aggregate score
    node_x = []
    node_y = []
    node_colors = []
    node_text = []

    conn = inv.get_db_connection(DB_PATH)
    cursor = conn.cursor()

    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)

        svc_agg = score_eng.score_service_aggregate(node, DB_PATH)
        max_score = svc_agg.get("max_score", 0.0)
        svc_name = G.nodes[node].get("name", f"Service-{node}")
        svc_crit = G.nodes[node].get("criticality", "P2")

        if max_score >= 80:
            color = "#EF4444"  # Red
        elif max_score >= 50:
            color = "#F59E0B"  # Orange
        else:
            color = "#10B981"  # Green

        node_colors.append(color)
        node_text.append(
            f"Service: {svc_name}<br>Criticality: {svc_crit}<br>Max MWQRS Risk: {max_score}")

    conn.close()

    # Edges
    edge_x = []
    edge_y = []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=1.5, color='#888'),
        hoverinfo='none',
        mode='lines'
    )

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        hoverinfo='text',
        text=[G.nodes[n].get("name") for n in G.nodes()],
        textposition="top center",
        hovertext=node_text,
        marker=dict(
            size=28,
            color=node_colors,
            line_width=2,
            line_color='#FFFFFF'
        )
    )

    fig_net = go.Figure(data=[edge_trace, node_trace],
                        layout=go.Layout(
        showlegend=False,
        hovermode='closest',
        margin=dict(b=20, l=5, r=5, t=20),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
    ))

    st.plotly_chart(fig_net, use_container_width=True)
    st.info("🟢 Safe (MWQRS < 50) | 🟠 Medium (50-79) | 🔴 Critical Risk (MWQRS ≥ 80)")

    # Interactive Service Blast Radius Drill-Down
    st.markdown("---")
    st.markdown("### 💥 Interactive Service Blast Radius Inspection")
    service_names_list = [G.nodes[n].get("name") for n in G.nodes()]
    if service_names_list:
        sel_svc_name = st.selectbox(
            "Select Service to Calculate Downstream Blast Radius:", service_names_list)
        sel_node_id = next(
            (n for n in G.nodes() if G.nodes[n].get("name") == sel_svc_name), None)

        if sel_node_id is not None:
            # Direct dependencies (services this service depends on)
            direct_deps = [G.nodes[v].get("name")
                           for _, v in G.out_edges(sel_node_id)]
            # Downstream dependents (services that depend on this service)
            downstream_deps = sim_eng.get_affected_dependents(sel_node_id, G)
            total_blast = len(downstream_deps) + 1

            br_col1, br_col2, br_col3 = st.columns(3)
            br_col1.metric("Direct Dependencies", len(direct_deps))
            br_col2.metric("Downstream Dependent Services",
                           len(downstream_deps))
            br_col3.metric("Calculated Blast Radius",
                           f"{total_blast} Services")

            if downstream_deps:
                st.warning(
                    f"⚠️ If **{sel_svc_name}** is migrated or interrupted, the following **{len(downstream_deps)}** downstream services are impacted: {', '.join(downstream_deps)}")
            else:
                st.success(
                    f"✅ **{sel_svc_name}** is self-contained or at the edge of the architecture (0 downstream dependencies).")


# ---------------------------------------------------------
# TAB 6: PQC MIGRATION SIMULATOR (Capability 4 & 9)
# ---------------------------------------------------------
with tab_pqc:
    st.subheader("🚀 Post-Quantum Cryptography (PQC) Migration Simulator")
    st.caption("Architectural migration simulator modeling transition from legacy classical cryptography to NIST FIPS 203/204/205 standards.")

    if not df.empty:
        sim_options = {
            f"{r['host']}:{r['port']} (ID: {r['id']} - MWQRS: {r['risk_score']})": r['id'] for _, r in df.iterrows()}
        selected_sim_label = st.selectbox("Select Target Cryptographic Asset to Migrate:", list(
            sim_options.keys()), key="pqc_sim_select")
        selected_sim_id = sim_options[selected_sim_label]

        # Strategy selector
        strat_key = st.selectbox(
            "Select Cryptographic Migration Strategy:",
            list(sim_eng.MIGRATION_STRATEGIES.keys()),
            format_func=lambda k: sim_eng.MIGRATION_STRATEGIES[k]["name"],
            key="pqc_sim_strategy"
        )
        st.info(
            f"**Strategy Details:** {sim_eng.MIGRATION_STRATEGIES[strat_key]['description']} (Ref: {sim_eng.MIGRATION_STRATEGIES[strat_key]['standard_reference']})")

        if st.button("🚀 Run Migration Impact Simulation", key="btn_run_sim"):
            sim_res = sim_eng.simulate_migration(
                selected_sim_id, DB_PATH, strategy=strat_key)

            st.markdown(f"> [!NOTE]\n> {sim_res['simulation_label']}")

            # Top Simulation Metrics
            sc1, sc2, sc3 = st.columns(3)
            sc1.metric("Current Algorithm", sim_res["current_algorithm"])
            sc2.metric("Migration Complexity", sim_res["migration_complexity"])
            sc3.metric("Blast Radius Count",
                       f"{sim_res['blast_radius_count']} Services")

            st.markdown("---")

            # BEFORE vs AFTER State Comparison View
            st.markdown("### 🔄 Before vs. After Migration State Comparison")
            col_b, col_a = st.columns(2)
            with col_b:
                st.markdown("#### 🔴 Before Migration (Current State)")
                b = sim_res["before_state"]
                st.write(f"**Algorithm:** `{b['algorithm']}`")
                st.write(f"**Key Size:** `{b['key_size']} bits`")
                st.write(f"**MWQRS Risk Score:** `{b['mwqrs_score']} / 100`")
                st.write(
                    f"**Quantum Vulnerability Status:** {b['quantum_status']}")
                st.write(f"**TLS Protocol:** `{b['tls_version']}`")

            with col_a:
                st.markdown("#### 🟢 After Migration (Simulated State)")
                a = sim_res["after_state"]
                st.write(f"**Algorithm:** `{a['algorithm']}`")
                st.write(f"**Key Specification:** `{a['key_size']}`")
                st.write(
                    f"**Simulated MWQRS Score:** `{a['simulated_mwqrs_score']} / 100` (Risk Reduction: **-{a['risk_reduction']} pts**)")
                st.write(f"**Simulated Status:** {a['quantum_status']}")
                st.write(f"**TLS Protocol:** `{a['tls_version']}`")

            st.markdown("---")

            # Granular PQC Direction & Affected Services
            col_sim1, col_sim2 = st.columns(2)
            with col_sim1:
                st.markdown("#### 🔒 Recommended NIST PQC Replacement")
                st.success(
                    f"**Target Direction**: {sim_res['recommended_replacement']}")
                st.write(
                    f"**Key Establishment (KEM)**: `{sim_res['kem_replacement']}`")
                st.write(
                    f"**Digital Signatures**: `{sim_res['signature_replacement']}`")
                st.write(
                    f"**Hybrid Architecture**: `{sim_res['hybrid_modeling']}`")
                st.write(
                    f"**NIST Standards**: {', '.join(sim_res['standards'])}")
                st.info(
                    f"**Implementation Guidance**: {sim_res['migration_notes']}")

                if st.button("⚡ Apply PQC Migration Remediation to Asset", key="btn_apply_pqc"):
                    sim_eng.apply_pqc_remediation(selected_sim_id, DB_PATH)
                    st.success(
                        "Asset successfully updated with NIST PQC record in database! Recalculating system MWQRS.")
                    st.rerun()

            with col_sim2:
                st.markdown(
                    "#### 💥 Downstream Services Affected (Blast Radius)")
                deps = sim_res["affected_dependent_services"]
                if deps:
                    for d in deps:
                        st.warning(
                            f"⚠️ **{d}** (Depends on this service — requires certificate rollover coordination)")
                else:
                    st.success("No downstream dependent services affected.")

        st.markdown("---")
        st.subheader("📋 Recommended Topological Migration Sequence")
        st.write(
            "Prioritized by MWQRS Risk Score (Highest first) and low blast radius as tie-breaker.")

        roadmap = sim_eng.recommend_migration_order(DB_PATH)
        st.dataframe(pd.DataFrame(roadmap), use_container_width=True)


# ---------------------------------------------------------
# TAB 7: SOURCE CODE SCANNER (Capability 6)
# ---------------------------------------------------------
with tab_code:
    st.subheader("🔍 Source Code Cryptographic Scanner")
    st.caption("Scans repository source code across languages (.py, .js, .java, .c, .go, .env, .pem) for hardcoded keys, weak hashes, deprecated block ciphers, and key references.")
    st.info("📌 **Note**: Source-code scanning is distinct from TLS network scanning; it inspects repository files directly for cryptographic implementation patterns.")

    code_path_input = st.text_input(
        "Source Directory to Scan", ".", key="code_scan_path_input")
    if st.button("🔍 Run Codebase Cryptographic Scan", key="btn_run_code_scan"):
        with st.spinner("Scanning source files with AST and regex rule engines..."):
            findings = code_eng.scan_source_directory(code_path_input, DB_PATH)
            st.success(
                f"Code scan finished. Discovered {len(findings)} cryptographic findings.")

    conn = inv.get_db_connection(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM code_findings ORDER BY id DESC")
    code_df = pd.DataFrame([dict(r) for r in cursor.fetchall()])
    conn.close()

    if not code_df.empty:
        st.dataframe(
            code_df[["id", "file_path", "line_number", "severity",
                     "finding_type", "code_snippet", "scanned_at"]],
            use_container_width=True
        )
    else:
        st.info(
            "No code findings recorded yet. Click 'Run Codebase Cryptographic Scan' above.")


# ---------------------------------------------------------
# TAB 8: CONTAINER SCANNER (Capability 7)
# ---------------------------------------------------------
with tab_cnt:
    st.subheader("🐳 Container & Dockerfile Cryptographic Scanner")
    st.caption("Prototype-level container cryptographic analyzer inspecting Dockerfiles and build context metadata for base OS crypto stacks, crypto packages, embedded private keys, and insecure configuration.")

    cnt_col1, cnt_col2 = st.columns(2)
    with cnt_col1:
        fixture_choice = st.selectbox(
            "Select Container Target / Fixture:",
            [
                "samples/container_fixtures/Dockerfile.legacy_service (Controlled Test Fixture — Weak/Legacy)",
                "samples/container_fixtures/Dockerfile.pqc_ready (Controlled Test Fixture — Modern PQC)",
                "Custom Path"
            ],
            key="cnt_fixture_choice"
        )
    with cnt_col2:
        if "Custom Path" in fixture_choice:
            target_container_path = st.text_input(
                "Enter Dockerfile or container directory path:", ".", key="cnt_custom_path")
        else:
            target_container_path = fixture_choice.split(" ")[0]

    if st.button("⚡ Execute Container Cryptographic Inspection", key="btn_run_cnt_scan"):
        with st.spinner(f"Analyzing container target {target_container_path}..."):
            try:
                cnt_findings = cnt_eng.scan_container_target(
                    target_container_path, DB_PATH)
                st.success(
                    f"Container inspection complete. Identified {len(cnt_findings)} cryptographic findings.")
            except Exception as e:
                st.error(f"Container scan error: {str(e)}")

    # Display Container Findings
    db_cnt_findings = cnt_eng.get_container_findings(DB_PATH)
    if db_cnt_findings:
        st.markdown("### 📋 Container Cryptographic Findings")
        cnt_df = pd.DataFrame(db_cnt_findings)
        st.dataframe(
            cnt_df[["id", "target_path", "finding_type", "severity",
                    "component", "evidence", "recommendation"]],
            use_container_width=True
        )
    else:
        st.info(
            "No container findings recorded yet. Click 'Execute Container Cryptographic Inspection' above.")


# ---------------------------------------------------------
# TAB 9: API CRYPTO SCANNER (Capability 8)
# ---------------------------------------------------------
with tab_api:
    st.subheader("🌐 API Cryptographic & Security Scanner")
    st.caption("Inspects API endpoints and API response tokens for TLS parameters, cryptographic security headers (HSTS), and JWT signature algorithms (RS256 vs ES256 vs PQC).")

    api_mode = st.radio(
        "API Inspection Source:",
        ["Controlled Test Fixture (Offline)", "Live API Endpoint URL"],
        horizontal=True,
        key="api_inspection_mode"
    )

    if api_mode == "Controlled Test Fixture (Offline)":
        api_fixture_choice = st.selectbox(
            "Select Controlled API Test Fixture:",
            [
                "samples/api_fixtures/api_jwt_rs256.json (Legacy RSA-2048 Signed JWT)",
                "samples/api_fixtures/api_jwt_es256.json (ECDSA P-384 Signed JWT + HSTS)",
                "samples/api_fixtures/api_jwt_pqc_mock.json (NIST FIPS 204 ML-DSA-65 PQC Token)",
            ],
            key="api_fixture_select"
        )
        fixture_file = api_fixture_choice.split(" ")[0]

        if st.button("⚡ Inspect API Cryptographic Posture", key="btn_inspect_api_fixture"):
            with st.spinner("Parsing API fixture and decoding JWT header..."):
                rep = api_eng.inspect_api_fixture(fixture_file, DB_PATH)
                st.success(
                    f"Inspection complete for {rep['url']}. Overall Cryptographic Risk: **{rep['overall_risk']}**")

                a_c1, a_c2, a_c3 = st.columns(3)
                a_c1.metric("API Endpoint", rep["endpoint"])
                a_c2.metric("Overall Cryptographic Risk", rep["overall_risk"])
                jwt_alg = rep["jwt_analysis"]["classification"]["algorithm"] if rep["jwt_analysis"] else "None"
                a_c3.metric("JWT Signature Algorithm", jwt_alg)

                if rep["jwt_analysis"]:
                    jwt_c = rep["jwt_analysis"]["classification"]
                    st.markdown("#### 🔑 JWT Signature Algorithm Analysis")
                    st.write(
                        f"- **Algorithm:** `{jwt_c['algorithm']}` ({jwt_c['type']})")
                    st.write(
                        f"- **Quantum Vulnerability Status:** {jwt_c['quantum_status']}")
                    st.write(
                        f"- **Recommendation:** {jwt_c['recommendation']}")

                if rep["tls_info"]:
                    st.markdown("#### 🔒 Transport Layer Security (TLS)")
                    t_info = rep["tls_info"]
                    st.write(
                        f"- **TLS Version:** `{t_info.get('version')}` | **Cipher:** `{t_info.get('cipher_suite')}`")
                    st.write(
                        f"- **Certificate Key:** `{t_info.get('cert_key_type')}` ({t_info.get('cert_key_size_bits')} bits)")

                if rep["findings"]:
                    st.markdown("#### ⚠️ Noteworthy Findings")
                    for f in rep["findings"]:
                        st.write(f"- {f}")

    else:  # Live API Endpoint URL
        if mode_selection == "🔵 OFFLINE MODE":
            st.warning("⚠️ OFFLINE MODE is active. Public API endpoints are blocked. Enter a local endpoint (e.g. https://127.0.0.1:8443) or use the Controlled Test Fixtures above.")

        live_api_url = st.text_input(
            "Enter API Endpoint URL (e.g. https://127.0.0.1:8443/api/v1/auth):", "https://127.0.0.1:8443", key="live_api_input")
        sample_jwt_input = st.text_area(
            "Optional Bearer JWT Token to Analyze (or leave blank):", "", key="sample_jwt_area")

        if st.button("⚡ Scan Live API Endpoint", key="btn_scan_live_api"):
            parsed_u = urllib.parse.urlparse(live_api_url)
            host_u = parsed_u.hostname or "127.0.0.1"
            if mode_selection == "🔵 OFFLINE MODE" and offline_eng.is_blocked_in_offline_mode(host_u):
                st.error(
                    f"❌ Host `{host_u}` blocked: External network scanning is prohibited in Sovereign Offline Mode.")
            else:
                with st.spinner(f"Connecting to API endpoint {live_api_url}..."):
                    rep = api_eng.inspect_api_endpoint(
                        live_api_url, sample_jwt=sample_jwt_input or None, db_path=DB_PATH)
                    st.success(
                        f"API Scan Complete. Cryptographic Risk: **{rep['overall_risk']}**")
                    st.json(rep)


# ---------------------------------------------------------
# TAB 10: SCAN HISTORY & DIFF ALERTING (Capability 10)
# ---------------------------------------------------------
with tab_diff:
    st.subheader("⏱️ 24-Hour Rescan Cadence & Diff-Based Alerting")
    st.caption("Snapshot versioning and structural diff engine tracking changes across periodic scans: added/removed assets, algorithm modifications, key length changes, expiry shifts, and MWQRS deltas.")

    # Snapshot Management
    st.markdown("### 📸 Scan Snapshots")
    snap_col1, snap_col2 = st.columns([3, 1])
    with snap_col1:
        snap_name_input = st.text_input(
            "Snapshot Name / Label:", f"Scan Snapshot {datetime.now().strftime('%Y-%m-%d %H:%M')}", key="snap_name_input")
    with snap_col2:
        st.write("")  # vertical spacing
        st.write("")
        if st.button("📸 Take Snapshot of Current State", key="btn_save_snapshot"):
            sid = inv.save_scan_snapshot(snap_name_input, DB_PATH)
            st.success(
                f"Snapshot #{sid} ('{snap_name_input}') saved successfully.")
            st.rerun()

    snapshots = inv.get_scan_snapshots(DB_PATH)
    if snapshots:
        snap_df = pd.DataFrame(snapshots)
        st.dataframe(
            snap_df[["id", "name", "created_at", "asset_count",
                     "avg_risk", "critical_count", "medium_count", "safe_count"]],
            use_container_width=True
        )

        st.markdown("---")
        st.markdown("### 🔍 Compare Scan Snapshots (Diff Engine)")
        if len(snapshots) >= 2:
            snap_options = {
                f"#{s['id']} — {s['name']} ({s['created_at']})": s['id'] for s in snapshots}
            c_s1, c_s2 = st.columns(2)
            with c_s1:
                baseline_label = st.selectbox("Baseline Snapshot (Old):", list(
                    snap_options.keys()), index=len(snap_options)-1, key="baseline_snap_sel")
                old_id = snap_options[baseline_label]
            with c_s2:
                comp_label = st.selectbox("Comparison Snapshot (New):", list(
                    snap_options.keys()), index=0, key="comp_snap_sel")
                new_id = snap_options[comp_label]

            if st.button("⚡ Run Cryptographic Diff Comparison", key="btn_run_diff"):
                diff_res = diff_eng.compare_snapshots(old_id, new_id, DB_PATH)
                st.markdown("#### 📊 Diff Summary Metrics")
                s = diff_res["summary"]
                d1, d2, d3, d4, d5 = st.columns(5)
                d1.metric("Assets Added", f"+{s['assets_added']}")
                d2.metric("Assets Removed", f"-{s['assets_removed']}")
                d3.metric("Assets Modified", s["assets_modified"])
                d4.metric("Risk Increased",
                          f"+{s['risk_increased_count']}", delta_color="inverse")
                d5.metric(
                    "Avg MWQRS Delta", f"{'+' if s['avg_risk_delta'] > 0 else ''}{s['avg_risk_delta']}")

                st.markdown("#### 🚨 Detected Change Alerts")
                if diff_res["alerts"]:
                    for a in diff_res["alerts"]:
                        st.warning(a)
                else:
                    st.success(
                        "No cryptographic regressions or structural changes detected between snapshots.")

                # Download Diff Report
                diff_md = diff_eng.export_diff_markdown(diff_res)
                st.download_button(
                    label="📄 Download Diff Report (.md)",
                    data=diff_md,
                    file_name=f"ecdat_scan_diff_{old_id}_vs_{new_id}.md",
                    mime="text/markdown",
                    key="btn_download_diff_md"
                )
        else:
            st.info("At least 2 snapshots are required to compare scans. Click 'Take Snapshot of Current State' above to create another snapshot.")

    # 24-Hour Rescan Cadence Configuration Card
    st.markdown("---")
    st.markdown("### ⏲️ Periodic Rescan Cadence Configuration")
    cad1, cad2 = st.columns(2)
    with cad1:
        rescan_interval = st.selectbox("Configured Rescan Cadence:", [
                                       "Every 24 Hours (Default)", "Every 12 Hours", "Every 6 Hours", "Continuous (On-Demand)"], index=0)
    with cad2:
        st.write("")
        st.caption("📌 **Execution Policy**: Automated cron or pipeline scheduler executes `python cli.py pipeline` at the configured interval. ECDAT captures snapshot versions and generates diff alerts on drift.")


# ---------------------------------------------------------
# TAB 11: COMPLIANCE & READINESS DASHBOARD (Capability 11)
# ---------------------------------------------------------
with tab_comp:
    st.subheader("🛡️ Cryptographic Compliance & PQC Readiness Dashboard")
    st.info(
        "📌 **Scope & Technical Control Status**: This dashboard evaluates technical control status "
        "and post-quantum preparedness against NIST SP 800-52 Rev. 2 guidelines and NIST FIPS 203/204/205 standards. "
        "It provides engineering readiness visibility; it does not certify formal legal compliance."
    )

    norm_comp = inv.get_normalized_inventory(DB_PATH)
    total_c = len(norm_comp)
    qv_c = 0
    pqc_c = 0
    mig_req_c = 0

    if total_c > 0:
        qv_c = sum(
            1 for a in norm_comp if "Quantum-Vulnerable" in a.get("quantum_status", ""))
        pqc_c = sum(
            1 for a in norm_comp if "Quantum-Resistant" in a.get("quantum_status", ""))
        mig_req_c = sum(1 for a in norm_comp if a.get(
            "migration_status") == "Migration Required")
        unknown_c = total_c - (qv_c + pqc_c)

        cp1, cp2, cp3, cp4, cp5 = st.columns(5)
        cp1.metric("Total Cryptographic Assets", total_c)
        cp2.metric("Quantum-Vulnerable", qv_c,
                   delta=f"{round(qv_c/total_c*100, 1)}%", delta_color="inverse")
        cp3.metric("PQC-Ready / Migrated", pqc_c)
        cp4.metric("Migration Required", mig_req_c)
        cp5.metric("Unknown / Under Review", unknown_c)

        n_local_c = sum(1 for a in norm_comp if str(
            a.get("host", "")).startswith("127."))
        st.caption(
            f"📌 {total_c} total includes {n_local_c} local demo fixtures + historical records; public-host-only counts are shown on the Executive Dashboard.")

        st.markdown("---")
        st.markdown("### 📋 Technical Control Status Checklist")

        col_chk1, col_chk2 = st.columns(2)
        with col_chk1:
            st.markdown("#### Implemented Prototype Controls")
            st.success(
                "✅ **Crypto Inventory Available**: Normalized cryptographic asset database operational")
            st.success(
                "✅ **Algorithm Identified**: TLS ciphers, key specifications, and signature algorithms parsed")
            st.success(
                "✅ **Key Size Tracked**: Bit strengths catalogued against NIST SP 800-52 Rev. 2 minimums")
            st.success(
                "✅ **Certificate Expiry Tracked**: X.509 validity periods and renewal windows monitored")
            st.success(
                "✅ **Quantum Risk Score Calculated**: MWQRS composite index calculated for all endpoints")
            st.success(
                "✅ **Dependency Mapping Available**: Service inter-dependencies mapped in NetworkX")
            st.success(
                "✅ **PQC Recommendation Available**: NIST FIPS 203/204/205 replacement guidance generated")
            st.success(
                "✅ **CBOM Generated**: CycloneDX v1.6 specification compliant export ready")

        with col_chk2:
            st.markdown("#### Controls in Progress & Roadmap Items")
            st.warning(
                "⚠️ **Assets Requiring PQC Migration**: Active classical public keys require hybrid or PQC transition")
            st.info(
                "ℹ️ **Hardware Security Modules (HSM) Cataloguing**: [Prototype limitation / roadmap]")
            st.info(
                "ℹ️ **Cloud KMS Key Inventory Integration**: [Prototype limitation / roadmap]")
            st.info(
                "ℹ️ **Compiled Binary (.so/ELF) Inspection**: [Prototype limitation / roadmap]")
            st.info(
                "ℹ️ **Production Distributed Agent Architecture**: [Prototype limitation / roadmap]")

    # Download Compliance Report
    st.markdown("---")
    comp_report_lines = [
        "# ECDAT Cryptographic Compliance & Readiness Assessment",
        "",
        f"**Assessment Timestamp:** {datetime.now(timezone.utc).isoformat()}  ",
        f"**Database:** `{DB_PATH}`  ",
        "",
        "## Readiness Metrics",
        f"- **Total Assets:** {total_c}",
        f"- **Quantum-Vulnerable:** {qv_c}",
        f"- **PQC-Ready:** {pqc_c}",
        f"- **Migration Required:** {mig_req_c}",
        "",
        "## Standards Alignment",
        "- **NIST SP 800-52 Rev. 2**: Guidelines for TLS Implementations",
        "- **NIST FIPS 203**: Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)",
        "- **NIST FIPS 204**: Module-Lattice-Based Digital Signature Algorithm (ML-DSA)",
        "- **NIST FIPS 205**: Stateless Hash-Based Digital Signature Algorithm (SLH-DSA)",
        "- **CycloneDX CBOM Specification 1.6**: Cryptographic Bill of Materials",
    ]
    st.download_button(
        label="📄 Download Compliance & Readiness Report (.md)",
        data="\n".join(comp_report_lines),
        file_name="ecdat_compliance_readiness_report.md",
        mime="text/markdown",
        key="btn_download_comp_md"
    )


# ---------------------------------------------------------
# TAB 12: CBOM STUDIO (Capability 12)
# ---------------------------------------------------------
with tab_cbom:
    st.subheader("📜 Cryptographic Bill of Materials (CBOM) Studio")
    st.caption(
        "Exports cryptographic inventory strictly formatted in CycloneDX CBOM Specification 1.6 JSON standard.")

    cbom_json = inv.export_cbom(DB_PATH)
    try:
        parsed_cbom = json.loads(cbom_json)
        valid_json = True
        comp_count = len(parsed_cbom.get("components", []))
    except Exception:
        valid_json = False
        comp_count = 0
        parsed_cbom = {}

    cb1, cb2, cb3, cb4 = st.columns(4)
    cb1.metric("BOM Format", "CycloneDX")
    cb2.metric("Spec Version", "1.6")
    cb3.metric("Crypto Components", comp_count)
    cb4.metric("JSON Syntax", "✅ Valid JSON" if valid_json else "❌ Error")

    st.markdown("---")
    st.markdown("### 📄 CycloneDX JSON Document Preview")

    if valid_json:
        MAX_PREVIEW_COMPONENTS = 5
        # shallow copy, don't mutate the real object
        preview_obj = dict(parsed_cbom)
        full_components = preview_obj.get("components", [])
        if len(full_components) > MAX_PREVIEW_COMPONENTS:
            preview_obj["components"] = full_components[:MAX_PREVIEW_COMPONENTS]
            preview_obj["_preview_note"] = (
                f"Showing {MAX_PREVIEW_COMPONENTS} of {len(full_components)} components. "
                "Download the full file below for the complete document."
            )
        # pass a real dict — st.json handles serialization itself
        st.json(preview_obj)
    else:
        st.error("CBOM document failed JSON validation — cannot preview.")
        st.code(cbom_json[:1500], language="text")

    st.download_button(
        label="💾 Download Full CycloneDX CBOM (.json)",
        data=cbom_json,
        file_name="ecdat_cbom_cyclonedx_1.6.json",
        mime="application/json",
        key="btn_download_cbom_full"
    )

# ---------------------------------------------------------
# TAB 13: LIVE TLS SCANNER
# ---------------------------------------------------------
with tab_tls:
    st.subheader("Run Real-Time Cryptographic Discovery Scan")

    if mode_selection == "🔵 OFFLINE MODE":
        # ---------------------------------------------------------------
        # OFFLINE MODE — Local TLS Scanner + Cert File Analyser
        # ---------------------------------------------------------------
        st.info(
            "🔵 **OFFLINE MODE**: External network scanning is disabled.  \n"
            "Local TLS endpoints (127.0.0.1 / localhost) and imported certificate "
            "files are available for analysis."
        )

        st.markdown("### 🔒 Local TLS Endpoint Scanner")
        st.caption(
            "Scan local TLS servers running on this machine. "
            "Start test servers with: `python generate_test_certs.py`"
        )

        if "offline_scan_target" not in st.session_state:
            st.session_state.offline_scan_target = "127.0.0.1:8443"

        # Quick-select preset buttons
        preset_col1, preset_col2, preset_col3 = st.columns(3)
        if preset_col1.button("⚠️ Weak :8443 (RSA-1024)", key="offline_preset_8443"):
            st.session_state.offline_scan_target = "127.0.0.1:8443"
        if preset_col2.button("✅ Strong :8444 (RSA-3072)", key="offline_preset_8444"):
            st.session_state.offline_scan_target = "127.0.0.1:8444"
        if preset_col3.button("🟡 Medium :8445 (RSA-2048)", key="offline_preset_8445"):
            st.session_state.offline_scan_target = "127.0.0.1:8445"

        scan_target_input = st.text_input(
            "Enter Local Target (e.g., 127.0.0.1:8443 or 192.168.1.10:443)",
            key="offline_scan_target"
        )

        if st.button("⚡ Scan Local TLS Endpoint", key="offline_tls_scan_btn"):
            parsed = scanner_core.parse_target(scan_target_input)
            if not parsed:
                st.error("Invalid target format. Use host:port or host.")
            else:
                host, port = parsed
                # ── NETWORK SAFETY GUARD ──────────────────────────────────
                if offline_eng.is_blocked_in_offline_mode(host):
                    st.error(
                        f"❌ **OFFLINE MODE — External Host Blocked**  \n"
                        f"Target `{host}` is an external/public host and cannot be reached "
                        f"in Offline Mode.  \n"
                        f"Only `127.0.0.1`, `localhost`, and RFC 1918 private addresses are allowed."
                    )
                else:
                    # ── LOCAL SCAN ────────────────────────────────────────
                    with st.spinner(f"Connecting to local TLS endpoint {host}:{port}..."):
                        res = scanner_core.scan_host(host, port)
                        status = res.get("status")
                        scan_ok = status == "success"
                        if scan_ok:
                            linked_crit = score_eng.get_linked_criticality(
                                host, port, DB_PATH)
                            mwqrs_score = score_eng.calculate_mwqrs(
                                res, service_criticality=linked_crit)
                        else:
                            mwqrs_score = 0.0
                        risk_band, risk_band_help = get_risk_band(mwqrs_score)
                        verdict, reason, recommendation, verdict_style = get_scan_verdict(
                            res, mwqrs_score)

                    if scan_ok:
                        risk_flags = res.get("risk_flags") or []
                        cert_key_type = res.get("cert_key_type") or "Unknown"
                        key_size = res.get("cert_key_size_bits") or "Unknown"
                        tls_version = res.get("tls_version") or "Unknown"
                        days_to_expiry = res.get("days_to_expiry")

                        if verdict_style == "error":
                            st.error(f"Final verdict: {verdict}")
                        elif verdict_style == "warning":
                            st.warning(f"Final verdict: {verdict}")
                        else:
                            st.success(f"Final verdict: {verdict}")

                        st.write(f"**Reason:** {reason}")
                        st.write(f"**Recommended action:** {recommendation}")

                        c1, c2, c3, c4 = st.columns(4)
                        c1.metric("Target", f"{host}:{port}")
                        c2.metric("MWQRS score", f"{mwqrs_score} / 100")
                        c3.metric("Risk band", risk_band)
                        c4.metric("TLS version", tls_version)
                        st.caption(risk_band_help)
                        st.metric("Certificate key",
                                  f"{cert_key_type} {key_size}b")

                        if days_to_expiry is not None:
                            st.info(
                                f"Certificate expires in {days_to_expiry} day(s).")

                        with st.expander("Plain-English explanation", expanded=True):
                            st.write(
                                f"ECDAT connected to **{host}:{port}** (local endpoint) and checked its TLS configuration.")
                            st.write(
                                f"The server is using **{tls_version}** with a **{cert_key_type} {key_size}-bit** certificate key.")
                            st.write(
                                f"The certificate is issued to **{res.get('cert_subject', 'Unknown')}**.")
                            if risk_flags:
                                st.write("What needs attention:")
                                for flag in risk_flags:
                                    st.write(f"- {explain_risk_flag(flag)}")
                            else:
                                st.write(
                                    "No scanner warnings found for this local endpoint.")

                        with st.expander("Technical JSON details"):
                            st.json(res)

                        # Save to offline_ecdat.db
                        offline_eng._ingest_results_direct([res], DB_PATH)
                        inv.seed_offline_demo_data(DB_PATH)
                        score_eng.score_all_assets(DB_PATH)
                        st.success(
                            f"✅ Local scan of {host}:{port} complete and saved to "
                            f"`offline_ecdat.db`."
                        )
                    else:
                        st.error(f"Final verdict: {verdict}")
                        st.write(f"**Reason:** {reason}")
                        st.write(f"**Recommended action:** {recommendation}")
                        st.write(
                            res.get("error") or
                            "The local TLS server may not be running. "
                            "Start it with: `python generate_test_certs.py`"
                        )
                        with st.expander("Technical JSON details"):
                            st.json(res)
                        if status == "unreachable":
                            st.warning(
                                f"⚠️ Local server unreachable — is `generate_test_certs.py` running? "
                                f"({res.get('error', 'no details')})"
                            )

        # ── Scan All Local Test Servers ───────────────────────────────────
        st.markdown("---")
        if st.button("🔄 Scan All Local Test Servers (8443, 8444, 8445)", key="offline_scan_all_btn"):
            with st.spinner("Scanning all local test servers..."):
                scan_summary_rows = []
                for local_host, local_port in offline_eng.LOCAL_TEST_SERVERS:
                    r = scanner_core.scan_host(local_host, local_port)
                    sc = score_eng.calculate_mwqrs(
                        r) if r["status"] == "success" else 0.0
                    scan_summary_rows.append({
                        "Target": f"{local_host}:{local_port}",
                        "Status": r["status"],
                        "TLS": r.get("tls_version", "—"),
                        "Key": f"{r.get('cert_key_type', '?')} {r.get('cert_key_size_bits', '?')}b",
                        "Days to Expiry": r.get("days_to_expiry", "—"),
                        "MWQRS": sc,
                        "Flags": ", ".join(r.get("risk_flags") or []) or "OK",
                    })
                    if r["status"] == "success":
                        offline_eng._ingest_results_direct([r], DB_PATH)

            inv.seed_offline_demo_data(DB_PATH)
            score_eng.score_all_assets(DB_PATH)
            import pandas as pd
            st.dataframe(pd.DataFrame(scan_summary_rows),
                         use_container_width=True)
            success_count = sum(
                1 for row in scan_summary_rows if row["Status"] == "success")
            fail_count = len(scan_summary_rows) - success_count
            if success_count > 0:
                st.success(
                    f"✅ Scanned {success_count} local endpoint(s) successfully. Inventory updated.")
            if fail_count > 0:
                st.warning(
                    f"⚠️ {fail_count} local server(s) unreachable. "
                    "Run `python generate_test_certs.py` in a separate terminal."
                )

        # ── Certificate File Analyser ─────────────────────────────────────
        st.markdown("---")
        st.markdown("### 📄 Local Certificate File Analyser")
        st.caption(
            "Upload a certificate file (.pem, .crt, .cer) for offline X.509 analysis. "
            "No network connection required."
        )

        uploaded_cert = st.file_uploader(
            "Upload Certificate File",
            type=["pem", "crt", "cer", "der"],
            key="offline_cert_uploader"
        )

        if uploaded_cert is not None:
            # Write to a temp path for analysis
            import tempfile
            with tempfile.NamedTemporaryFile(
                suffix=Path(uploaded_cert.name).suffix, delete=False
            ) as tmp:
                tmp.write(uploaded_cert.read())
                tmp_path = Path(tmp.name)

            cr = offline_eng.analyze_cert_file(tmp_path)
            cr["host"] = cr.get("host") or Path(uploaded_cert.name).stem
            try:
                tmp_path.unlink()
            except Exception:
                pass

            if cr["status"] == "success":
                cert_mwqrs = score_eng.calculate_mwqrs(cr)
                st.success(
                    f"✅ Certificate parsed successfully — MWQRS: **{cert_mwqrs}/100**")

                cc1, cc2, cc3 = st.columns(3)
                cc1.metric("Key Type", cr.get("cert_key_type", "?"))
                cc2.metric(
                    "Key Size", f"{cr.get('cert_key_size_bits', '?')} bits")
                cc3.metric("Days to Expiry", cr.get("days_to_expiry", "?"))

                with st.expander("Certificate Details", expanded=True):
                    st.write(f"**Subject:** {cr.get('cert_subject', 'N/A')}")
                    st.write(f"**Issuer:** {cr.get('cert_issuer', 'N/A')}")
                    st.write(
                        f"**Signature Algorithm:** {cr.get('cert_signature_algorithm', 'N/A')}")
                    st.write(
                        f"**Not After:** {cr.get('cert_not_after', 'N/A')}")
                    flags = cr.get("risk_flags") or []
                    if flags:
                        st.write("**Risk Flags:**")
                        for flag in flags:
                            st.write(f"  - {explain_risk_flag(flag)}")
                    else:
                        st.write("**Risk Flags:** None")

                if st.button("💾 Add Certificate to Offline Inventory", key="offline_add_cert_btn"):
                    offline_eng._ingest_results_direct([cr], DB_PATH)
                    score_eng.score_all_assets(DB_PATH)
                    st.success(
                        f"Certificate '{cr['host']}' added to "
                        f"`offline_ecdat.db` inventory."
                    )
                    st.rerun()
            else:
                st.error(
                    f"❌ Could not parse certificate file: {cr.get('error', 'unknown error')}  \n"
                    "Ensure the file is a valid DER or PEM encoded X.509 certificate."
                )

        # ── Auto-discovered local cert files ──────────────────────────────
        local_certs = offline_eng.find_local_cert_files(".")
        if local_certs:
            st.markdown("---")
            st.markdown("### 📁 Auto-Discovered Local Certificate Files")
            st.caption(
                "Certificate files found in the project directory (generated by `generate_test_certs.py`).")
            for cp in local_certs:
                cr = offline_eng.analyze_cert_file(cp)
                if cr["status"] == "success":
                    cert_mwqrs = score_eng.calculate_mwqrs(cr)
                    risk_color = "🔴" if cert_mwqrs >= 80 else (
                        "🟠" if cert_mwqrs >= 50 else "🟢")
                    st.write(
                        f"{risk_color} **{cp.name}** — "
                        f"{cr.get('cert_key_type')} {cr.get('cert_key_size_bits')}b | "
                        f"Expires: {cr.get('days_to_expiry')}d | "
                        f"MWQRS: {cert_mwqrs}"
                    )
                else:
                    st.write(
                        f"⚠️ **{cp.name}** — Parse error: {cr.get('error')}")

    else:  # LIVE MODE or CACHED MODE scanner
        st.caption("ECDAT checks TLS, certificates, and cryptographic posture. It does not replace full web vulnerability scanners such as OWASP ZAP or Burp Suite.")

        if "live_scan_target" not in st.session_state:
            st.session_state.live_scan_target = "127.0.0.1:8443"

        demo_c1, demo_c2, demo_c3 = st.columns(3)
        if demo_c1.button("Safe Example"):
            st.session_state.live_scan_target = "owasp.org:443"
        if demo_c2.button("Expired Certificate"):
            st.session_state.live_scan_target = "expired.badssl.com:443"
        if demo_c3.button("Weak Local RSA"):
            st.session_state.live_scan_target = "127.0.0.1:8443"

        scan_target_input = st.text_input(
            "Enter Target Host (e.g., example.com:443 or 127.0.0.1:8443)",
            key="live_scan_target"
        )

        if st.button("⚡ Execute Live TLS Handshake & Scan"):
            with st.spinner(f"Connecting over TLS to {scan_target_input}..."):
                parsed = scanner_core.parse_target(scan_target_input)
                if not parsed:
                    st.error("Invalid target format.")
                else:
                    host, port = parsed
                    res = scanner_core.scan_host(host, port)
                    status = res.get("status")
                    scan_ok = status == "success"
                    if scan_ok:
                        linked_crit = score_eng.get_linked_criticality(
                            host, port, DB_PATH)
                        mwqrs_score = score_eng.calculate_mwqrs(
                            res, service_criticality=linked_crit)
                    else:
                        mwqrs_score = 0.0
                    risk_band, risk_band_help = get_risk_band(mwqrs_score)
                    verdict, reason, recommendation, verdict_style = get_scan_verdict(
                        res, mwqrs_score)

                    if scan_ok:
                        risk_flags = res.get("risk_flags") or []
                        cert_key_type = res.get("cert_key_type") or "Unknown"
                        key_size = res.get("cert_key_size_bits") or "Unknown"
                        tls_version = res.get("tls_version") or "Unknown"
                        days_to_expiry = res.get("days_to_expiry")

                        if verdict_style == "error":
                            st.error(f"Final verdict: {verdict}")
                        elif verdict_style == "warning":
                            st.warning(f"Final verdict: {verdict}")
                        else:
                            st.success(f"Final verdict: {verdict}")

                        st.write(f"**Reason:** {reason}")
                        st.write(f"**Recommended action:** {recommendation}")

                        c1, c2, c3, c4 = st.columns(4)
                        c1.metric("Website checked", f"{host}:{port}")
                        c2.metric("MWQRS score", f"{mwqrs_score} / 100")
                        c3.metric("Risk band", risk_band)
                        c4.metric("TLS version", tls_version)
                        st.caption(risk_band_help)

                        st.metric("Certificate key",
                                  f"{cert_key_type} {key_size}b")

                        if days_to_expiry is not None:
                            st.info(
                                f"Certificate expires in {days_to_expiry} day(s).")

                        with st.expander("Plain-English explanation", expanded=True):
                            st.write(
                                f"ECDAT connected to **{host}:{port}** and checked how the website protects encrypted traffic.")
                            st.write(
                                f"The site is using **{tls_version}** with a **{cert_key_type} {key_size}-bit** certificate key.")
                            st.write(
                                f"The certificate is issued to **{res.get('cert_subject', 'Unknown')}**.")
                            if risk_flags:
                                st.write("What needs attention:")
                                for flag in risk_flags:
                                    st.write(f"- {explain_risk_flag(flag)}")
                            else:
                                st.write(
                                    "No scanner warnings were found for this target.")

                        with st.expander("Technical JSON details"):
                            st.json(res)

                        # Save to the inventory only in LIVE mode, so the cached demo dataset stays unchanged
                        if mode_selection == "🟡 CACHED MODE":
                            st.info(
                                "Cached mode: this scan is shown but not saved, so the cached demo dataset stays unchanged.")
                        else:
                            with open("temp_scan.json", "w") as f:
                                json.dump([res], f)
                            inv.ingest_scan_results("temp_scan.json", DB_PATH)
                            score_eng.score_all_assets(DB_PATH)
                            st.success(
                                f"✅ Scanned {host}:{port} successfully and ingested into database inventory!")
                    else:
                        st.error(f"Final verdict: {verdict}")
                        st.write(f"**Reason:** {reason}")
                        st.write(f"**Recommended action:** {recommendation}")
                        st.write(res.get(
                            "error") or "The target may be unreachable, blocked, or not serving TLS on this port.")
                        with st.expander("Technical JSON details"):
                            st.json(res)
                        if status == "unreachable":
                            st.warning(
                                f"⚠️ Target unreachable — no result ingested. ({res.get('error', 'no details')})")
                        else:
                            st.error(
                                f"❌ Scan error — no result ingested. Status: {status}. ({res.get('error', 'no details')})")


# ---------------------------------------------------------
# TAB 14: GUIDED TOUR & ASSISTANT (works offline; AI optional)
# ---------------------------------------------------------
with tab_tour:
    def _band_counts(scores):
        return {
            "critical_80_plus": int((scores >= 80).sum()),
            "medium_50_to_79": int(((scores >= 50) & (scores < 80)).sum()),
            "low_below_50": int((scores < 50).sum()),
        }

    ai_summary = {"data_source": mode_selection,
                  "asset_rows_in_current_database": int(len(df))}
    if not df.empty and "risk_score" in df.columns:
        _scores = pd.to_numeric(df["risk_score"], errors="coerce").dropna()
        if len(_scores):
            ai_summary.update(_band_counts(_scores))
            ai_summary["highest_risk_score"] = round(float(_scores.max()), 1)
            ai_summary["average_risk_score"] = round(float(_scores.mean()), 1)
    render_guide_and_assistant(get_ai_pool(), ai_summary)
