"""
ECDAT - Stage 5: Executive Dashboard & Interactive Visualizer
--------------------------------------------------------------
Streamlit visual web application showcasing real-time inventory, MWQRS quantum risk scoring,
CycloneDX CBOM exports, dependency graph visualization, PQC migration simulation, and live scanner runner.
"""

import json
import sqlite3
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

import os
import shutil
from datetime import datetime

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
        gap: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        height: 45px;
        white-space: pre-wrap;
        border-radius: 6px;
        padding-left: 16px;
        padding-right: 16px;
    }
</style>
""", unsafe_allow_html=True)


# Sidebar Actions
st.sidebar.image("https://img.icons8.com/color/96/shield-with-encryption.png", width=70)
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
        st.sidebar.warning(f"🟡 CACHED MODE ACTIVE\nUsing {cached_dataset_label}. Live database modifications are isolated.")
    else:
        DB_PATH = inv.DEFAULT_DB_PATH
        st.sidebar.error("⚠️ `demo_fallback.db` not found! Falling back to live `ecdat.db`.")

elif mode_selection == "🔵 OFFLINE MODE":
    DB_PATH = OFFLINE_DB_PATH
    offline_exists = Path(OFFLINE_DB_PATH).exists()

    if offline_exists:
        snapshot_time = datetime.fromtimestamp(os.path.getmtime(OFFLINE_DB_PATH)).strftime("%Y-%m-%d %H:%M:%S")
        st.sidebar.info(f"🔵 OFFLINE MODE ACTIVE\nRunning locally using offline ECDAT data.\nNo external cloud dependency.\n\nSnapshot created: {snapshot_time}")
    else:
        st.sidebar.warning("🔵 OFFLINE MODE — no offline database found yet.")

    if st.sidebar.button("📥 Initialize / Refresh Offline Data"):
        if Path(inv.DEFAULT_DB_PATH).exists():
            shutil.copy(inv.DEFAULT_DB_PATH, OFFLINE_DB_PATH)
            st.sidebar.success(f"Offline snapshot created from ecdat.db at {datetime.now().strftime('%H:%M:%S')}.")
        else:
            inv.init_db(OFFLINE_DB_PATH)
            st.sidebar.success("Empty offline database initialized (no live data existed to snapshot).")
        st.rerun()

    # Never silently fall back: if still missing after this point, init_db creates an empty schema so the app doesn't crash
    inv.init_db(OFFLINE_DB_PATH)

else:
    DB_PATH = inv.DEFAULT_DB_PATH
    st.sidebar.success("🟢 LIVE MODE ACTIVE\nConnected to live operational database (`ecdat.db`).")

st.sidebar.markdown("---")

# Ensure DB is initialized & scored on load
inv.init_db(DB_PATH)

# Title & Info Header
st.markdown('<div class="main-header">ECDAT — Enterprise Cryptographic Discovery & Analysis Tool</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">SIH26164 (NTRO / Post-Quantum Cryptography & Keyfactor AgileSec Pipeline Model)</div>', unsafe_allow_html=True)

if mode_selection == "🟡 CACHED MODE" and Path("demo_fallback.db").exists():
    st.info(f"🟡 **CACHED DEMO MODE ACTIVE**: Dashboard is rendering {get_cached_dataset_label(DB_PATH)} from `demo_fallback.db`.")
elif mode_selection == "🔵 OFFLINE MODE":
    offline_exists = Path(OFFLINE_DB_PATH).exists()
    snap_line = f"Snapshot created: {datetime.fromtimestamp(os.path.getmtime(OFFLINE_DB_PATH)).strftime('%Y-%m-%d %H:%M:%S')}" if offline_exists else "No snapshot yet — use the sidebar button to initialize."
    st.warning(f"🔵 **OFFLINE MODE ACTIVE** — Local sovereign-ready operation. No external cloud dependency for core analysis.\n\nDatabase: `offline_ecdat.db` | Data source: Local ECDAT snapshot | {snap_line}")
else:
    st.caption("🟢 **LIVE MODE ACTIVE**: Dashboard is rendering dynamic operational database from `ecdat.db`.")

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
tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8 = st.tabs([
    "📊 Executive Dashboard",
    "📋 Requirement Coverage",
    "📜 CBOM Inventory",
    "🕸️ Service Dependency Graph",
    "🚀 PQC Migration Simulator",
    "🔍 Source Code Scanner",
    "⚡ Live TLS Scanner",
    "🧭 Guided Tour & Assistant"
])


# ---------------------------------------------------------
# TAB 1: EXECUTIVE DASHBOARD
# ---------------------------------------------------------
with tab1:
    if df.empty:
        st.warning("No crypto assets scanned yet. Run a scan from the 'Live TLS Scanner' tab or run cli.py.")
    else:
        # Top KPI Metrics
        total_scanned = len(df)
        critical_count = len(df[df["risk_score"] >= 80.0])
        medium_count = len(df[(df["risk_score"] >= 50.0) & (df["risk_score"] < 80.0)])
        safe_count = len(df[df["risk_score"] < 50.0])
        avg_score = round(df["risk_score"].mean(), 1)

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Scanned Endpoints", total_scanned, delta="Live Sensors")
        c2.metric("Critical Quantum Risk (MWQRS ≥ 80)", critical_count, delta=f"{round(critical_count/total_scanned*100,1)}%", delta_color="inverse")
        c3.metric("Medium Quantum Risk (50-79)", medium_count)
        c4.metric("Average System MWQRS Risk", f"{avg_score} / 100")

        st.markdown("---")

        # ---------------------------------------------------------
        # AGGREGATE PUBLIC HOST SAMPLE STATISTICS PANEL
        # ---------------------------------------------------------
        st.markdown("### 🌐 Aggregate Public Host Scan Statistics")
        
        # Filter real scanned hosts (excluding local loopback / demo seeds)
        real_df = df[~df["host"].str.startswith("127.")].copy() if not df.empty else pd.DataFrame()
        n_attempted = len(real_df)
        n_scanned = len(real_df[real_df["status"] == "success"]) if not real_df.empty else 0
        n_unreachable = len(real_df[real_df["status"] == "unreachable"]) if not real_df.empty else 0
        
        # Quantum Vulnerable Breakdown (RSA vs ECC)
        if not real_df.empty and n_scanned > 0:
            rsa_count = len(real_df[real_df["cert_key_type"].astype(str).str.contains("RSA", na=False)])
            ecc_count = len(real_df[real_df["cert_key_type"].astype(str).str.contains("ECC", na=False)])
            qv_pct = round((rsa_count + ecc_count) / n_scanned * 100, 1)
        else:
            qv_pct = 0.0
        
        latest_scan = real_df["scanned_at"].max() if not real_df.empty and "scanned_at" in real_df and not real_df["scanned_at"].isnull().all() else "N/A"
        
        p1, p2, p3, p4, p5 = st.columns(5)
        p1.metric("Attempted Hosts", n_attempted)
        p2.metric("Successfully Scanned", n_scanned)
        p3.metric("Unreachable Hosts", n_unreachable)
        p4.metric("Quantum Vulnerable %", f"{qv_pct}%", help="RSA or ECC public keys (vulnerable to Shor's algorithm)")
        p5.metric("Sample Size (n)", n_scanned)

        col_st1, col_st2, col_st3 = st.columns(3)
        with col_st1:
            st.markdown("**TLS Version Distribution**")
            if not real_df.empty and "tls_version" in real_df:
                tls_counts = real_df["tls_version"].value_counts().reset_index()
                tls_counts.columns = ["TLS Version", "Count"]
                st.dataframe(tls_counts, use_container_width=True)
        with col_st2:
            st.markdown("**Key Algorithm Distribution**")
            if not real_df.empty and "cert_key_type" in real_df:
                algo_counts = real_df["cert_key_type"].value_counts().reset_index()
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

        st.caption(f"📌 **Disclaimer**: Point-in-time sample of public front pages (n={n_scanned}, scanned at {latest_scan}); not a market-wide claim. Risk classification informed by NIST SP 800-52 Rev. 2 guidelines. Excludes mock seeded service records.")
        st.markdown("---")

        col_left, col_right = st.columns(2)

        with col_left:
            st.subheader("Quantum Risk Level Distribution")
            df["Risk_Category"] = pd.cut(
                df["risk_score"],
                bins=[-1, 49.9, 79.9, 100],
                labels=["Quantum Safe / Low", "Medium Risk", "Critical Risk (MWQRS ≥80)"]
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
                lambda x: f"{x['cert_key_type']} {x['cert_key_size_bits']}b" if pd.notnull(x['cert_key_size_bits']) else str(x['cert_key_type']),
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
                labels={"Key_Type": "Certificate Key Specification", "Count": "Asset Count"},
                color_discrete_sequence=px.colors.qualitative.Pastel
            )
            fig_bar.update_layout(showlegend=False, margin=dict(t=20, b=20, l=20, r=20))
            st.plotly_chart(fig_bar, use_container_width=True)

        st.subheader("🔥 Top Vulnerable Cryptographic Assets")
        top_vuln = df.sort_values(by="risk_score", ascending=False).head(5)
        st.dataframe(
            top_vuln[["host", "port", "tls_version", "cert_key_type", "cert_key_size_bits", "risk_score", "service_name", "risk_flags"]],
            use_container_width=True
        )


# ---------------------------------------------------------
# TAB 2: REQUIREMENT COVERAGE (SIH26164)
# ---------------------------------------------------------
with tab2:
    st.subheader("📋 SIH26164 Problem Statement Requirement Coverage")
    st.markdown("""
    <div style="background-color: #1E222D; border: 1px solid #2E3440; border-radius: 8px; padding: 16px; margin-bottom: 20px;">
        <h4 style="margin-top:0; color: #00C9FF;">⚡ Executive 5-Line Slide Summary</h4>
        <ol style="margin-bottom:0; color: #D8DEE9; line-height: 1.6;">
            <li><b>Discovery & Inventory</b>: Pure-Python TLS endpoint scanner + CycloneDX v1.6 CBOM exporter (<b>Implemented</b> for TLS endpoints; <b>Partial</b> for source code; HSMs/Cloud KMS <b>Planned</b>).</li>
            <li><b>Quantum Risk Scoring</b>: Implements Mosca-Weighted Quantum Risk Score (MWQRS, 0–100 scale) combining algorithm vulnerability (35%), key length (20%), TLS version (15%), cert expiry (10%), and service criticality (20%) (<b>Partial</b> — Mosca-inspired composite index, not direct evaluation of X+Y>Z).</li>
            <li><b>PQC Migration Roadmap</b>: Maps classical algorithms (RSA/ECC/DSA) to NIST FIPS 203 (ML-KEM-768) & FIPS 204 (ML-DSA-65) with hybrid transition modes and NetworkX dependency blast-radius sequence (<b>Implemented</b>).</li>
            <li><b>Interactive Dashboard & CLI</b>: Streamlit executive web application with Plotly analytics, network dependency graphs, CBOM exporter, and unified master CLI (<code>python cli.py pipeline</code>) (<b>Implemented</b>).</li>
            <li><b>Gaps & Roadmap</b>: Binary (.so/ELF) scanning, container image inspection, HSM/KMS discovery, and PQC latency/cost estimation are identified as <b>Planned</b> enhancements.</li>
        </ol>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("### Ground-Truth Requirement Implementation Table")

    req_data = [
        {
            "Requirement": "(i) Catalogue Cryptographic Artefacts (Algorithms, keys, certificates, protocols, libraries, HSMs, Cloud KMS)",
            "Status": "Partial",
            "Implemented By": "ecdat_scanner.py (scan_host), ecdat_inventory.py (ingest_scan_results), ecdat_codescanner.py (scan_file_content)",
            "30-Second Demo": "Run python cli.py scan --host google.com:443 -> view extracted TLS, cipher, key size, sig algo, and code findings.",
            "Identified Gap / Limitation": "HSMs and Cloud KMS not catalogued. Libraries scanned via source AST/regex; native compiled binaries (.so/.dll) not inspected."
        },
        {
            "Requirement": "(ii) Classify by Type, Lifetime & Criticality (Categorization & business impact assessment)",
            "Status": "Partial",
            "Implemented By": "ecdat_inventory.py (init_db, seed_demo_data), ecdat_scoring.py (CRITICALITY_MULTIPLIERS)",
            "30-Second Demo": "Launch streamlit run app.py -> filter assets by criticality tier (P0-P3) and certificate days to expiry (days_to_expiry).",
            "Identified Gap / Limitation": "Cert expiry lifetime is tracked, but system operational lifetime (Z) is static. Service dependency graph is mock/seeded (seed_demo_data), not automatically discovered from network traffic. (Note: The baseline '10 assets' breakdown is not verified — no documentary evidence exists for this breakdown)."
        },
        {
            "Requirement": "(iii) Quantum Risk Assessment (Mosca-inspired framework & weighted risk scoring)",
            "Status": "Partial",
            "Implemented By": "ecdat_scoring.py (calculate_mwqrs, score_all_assets)",
            "30-Second Demo": "Run python cli.py score -> view MWQRS scores (0-100 scale) calculated per asset based on 5 weighted parameters.",
            "Identified Gap / Limitation": "The scoring model (MWQRS) is Mosca-inspired rather than a direct mathematical evaluation of Mosca's inequality (X + Y > Z). Data security shelf-life (Y) and migration time (X) are statically weighted rather than dynamically modeled from business retention policies."
        },
        {
            "Requirement": "(iv) Recommend PQC/Hybrid Alternatives (NIST standards, latency, cost & migration sequence)",
            "Status": "Partial",
            "Implemented By": "ecdat_simulator.py (PQC_MIGRATION_MAP, simulate_migration, recommend_migration_order)",
            "30-Second Demo": "Run python cli.py simulate -> view recommended NIST FIPS 203/204/205 replacements (ML-KEM-768, ML-DSA-65), hybrid mode, and sequence.",
            "Identified Gap / Limitation": "Latency overhead impact and migration cost estimates are absent/not computed."
        },
        {
            "Requirement": "(v) Deliverable: CBOM Analytics Tool (Source code, binaries, libraries, container images, report, GUI)",
            "Status": "Partial",
            "Implemented By": "ecdat_inventory.py (export_cbom), ecdat_codescanner.py (scan_source_directory), app.py, cli.py (cbom)",
            "30-Second Demo": "Run python cli.py cbom --out cbom.json for CycloneDX v1.6 CBOM; launch streamlit run app.py for executive GUI.",
            "Identified Gap / Limitation": "Source code scanned across multiple languages (.py, .js, .java); compiled binaries (.so/.dll/ELF) and container images (Docker/OCI) are not scanned."
        }
    ]

    st.dataframe(pd.DataFrame(req_data), use_container_width=True)
    st.caption("Status Legend: **Implemented** (Fully operational in code) | **Partial** (Operational for core scope; secondary features absent or using inspired composite model) | **Planned** (Architecturally identified, not yet coded)")


# ---------------------------------------------------------
# TAB 3: CBOM INVENTORY TABLE
# ---------------------------------------------------------
with tab3:
    st.subheader("Cryptographic Bill of Materials (CBOM) Inventory")

    if not df.empty:
        col_f1, col_f2 = st.columns(2)
        with col_f1:
            search_query = st.text_input("Search Host", "")
        with col_f2:
            filter_risk_only = st.checkbox("Show Only Vulnerable Assets (MWQRS ≥ 50)")

        filtered_df = df.copy()
        if search_query:
            filtered_df = filtered_df[filtered_df["host"].str.contains(search_query, case=False, na=False)]
        if filter_risk_only:
            filtered_df = filtered_df[filtered_df["risk_score"] >= 50.0]

        st.dataframe(
            filtered_df[[
                "id", "host", "port", "tls_version", "cipher_suite",
                "cert_key_type", "cert_key_size_bits", "cert_signature_algorithm",
                "days_to_expiry", "risk_score", "service_name", "risk_flags"
            ]],
            use_container_width=True
        )

        st.markdown("### Export CBOM Document")
        st.write("Download inventory formatted in **CycloneDX CBOM Specification 1.6** JSON standard.")

        cbom_json = inv.export_cbom(DB_PATH)
        st.download_button(
            label="💾 Download CycloneDX CBOM (.json)",
            data=cbom_json,
            file_name="ecdat_cbom_cyclonedx.json",
            mime="application/json"
        )


# ---------------------------------------------------------
# TAB 4: DEPENDENCY GRAPH
# ---------------------------------------------------------
with tab4:
    st.subheader("Service Dependency Network Graph & Quantum Risk propagation")
    st.write("Visualizes services, inter-dependencies, and aggregate cryptographic risk scores.")

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
        node_text.append(f"Service: {svc_name}<br>Criticality: {svc_crit}<br>Max MWQRS Risk: {max_score}")

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
                margin=dict(b=20,l=5,r=5,t=20),
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
            ))

    st.plotly_chart(fig_net, use_container_width=True)

    st.info("🟢 Safe (MWQRS < 50) | 🟠 Medium (50-79) | 🔴 Critical Risk (MWQRS ≥ 80)")


# ---------------------------------------------------------
# TAB 5: PQC MIGRATION SIMULATOR
# ---------------------------------------------------------
with tab5:
    st.subheader("Post-Quantum Cryptography (PQC) Migration Simulator")
    st.write("ECDAT Differentiation Feature: Simulates replacing legacy cryptographic algorithms with NIST PQC standards and computes blast radius across dependent services.")

    if not df.empty:
        asset_options = {f"{r['host']}:{r['port']} (ID: {r['id']} - MWQRS: {r['risk_score']})": r['id'] for _, r in df.iterrows()}
        selected_label = st.selectbox("Select Target Cryptographic Asset to Migrate:", list(asset_options.keys()))
        selected_id = asset_options[selected_label]

        if st.button("🚀 Run Migration Impact Simulation"):
            sim_res = sim_eng.simulate_migration(selected_id, DB_PATH)

            sc1, sc2, sc3 = st.columns(3)
            sc1.metric("Current Algorithm", sim_res["current_algorithm"])
            sc2.metric("Migration Complexity", sim_res["migration_complexity"])
            sc3.metric("Blast Radius Count", f"{sim_res['blast_radius_count']} Services")

            st.markdown("---")

            col_sim1, col_sim2 = st.columns(2)
            with col_sim1:
                st.markdown("#### 🔒 Recommended NIST PQC Replacement")
                st.success(f"**Target Algorithm**: {sim_res['recommended_replacement']}")
                st.write(f"**NIST Standards**: {', '.join(sim_res['standards'])}")
                st.write(f"**Hybrid Mode Enabled**: {'Yes (Classical + PQC dual cert)' if sim_res['hybrid_mode'] else 'No'}")
                st.info(f"**Guidance**: {sim_res['migration_notes']}")

                if st.button("⚡ Apply PQC Migration Remediation to Asset"):
                    sim_eng.apply_pqc_remediation(selected_id, DB_PATH)
                    st.success("Asset successfully upgraded to NIST PQC (ML-KEM-768)! System MWQRS risk score updated.")
                    st.rerun()

            with col_sim2:
                st.markdown("#### 💥 Affected Dependent Services (Blast Radius)")
                deps = sim_res["affected_dependent_services"]
                if deps:
                    for d in deps:
                        st.warning(f"⚠️ **{d}** (Depends directly/indirectly on this service)")
                else:
                    st.success("No downstream dependent services affected.")

        st.markdown("---")
        st.subheader("📋 Recommended Topological Migration Sequence")
        st.write("Optimal sequence ordering prioritized by MWQRS Risk Score (Highest first) and Blast Radius.")

        roadmap = sim_eng.recommend_migration_order(DB_PATH)
        st.dataframe(pd.DataFrame(roadmap), use_container_width=True)


# ---------------------------------------------------------
# TAB 6: SOURCE CODE SCANNER
# ---------------------------------------------------------
with tab6:
    st.subheader("Source Code Cryptographic Security Scanner")
    st.write("Scans codebase repositories for hardcoded RSA keys, weak hashing (MD5/SHA1), deprecated ciphers (DES), and exposed secret keys.")

    code_path_input = st.text_input("Source Directory to Scan", ".")
    if st.button("🔍 Run Codebase Scan"):
        with st.spinner("Scanning source files..."):
            findings = code_eng.scan_source_directory(code_path_input, DB_PATH)
            st.success(f"Code scan finished. Discovered {len(findings)} cryptographic issues.")

    conn = inv.get_db_connection(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM code_findings ORDER BY id DESC")
    code_df = pd.DataFrame([dict(r) for r in cursor.fetchall()])
    conn.close()

    if not code_df.empty:
        st.dataframe(
            code_df[["id", "file_path", "line_number", "severity", "finding_type", "code_snippet", "scanned_at"]],
            use_container_width=True
        )
    else:
        st.info("No code findings recorded yet. Click 'Run Codebase Scan' above.")


# ---------------------------------------------------------
# TAB 7: LIVE TLS SCANNER
# ---------------------------------------------------------
with tab7:
    st.subheader("Run Real-Time Cryptographic Discovery Scan")

    if mode_selection == "🔵 OFFLINE MODE":
        st.warning("🔵 OFFLINE MODE\nLive TLS scanning requires network connectivity and is disabled in Offline Mode.")
    else:
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
                    mwqrs_score = score_eng.calculate_mwqrs(res) if scan_ok else 0.0
                    risk_band, risk_band_help = get_risk_band(mwqrs_score)
                    verdict, reason, recommendation, verdict_style = get_scan_verdict(res, mwqrs_score)

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

                        st.metric("Certificate key", f"{cert_key_type} {key_size}b")

                        if days_to_expiry is not None:
                            st.info(f"Certificate expires in {days_to_expiry} day(s).")

                        with st.expander("Plain-English explanation", expanded=True):
                            st.write(f"ECDAT connected to **{host}:{port}** and checked how the website protects encrypted traffic.")
                            st.write(f"The site is using **{tls_version}** with a **{cert_key_type} {key_size}-bit** certificate key.")
                            st.write(f"The certificate is issued to **{res.get('cert_subject', 'Unknown')}**.")
                            if risk_flags:
                                st.write("What needs attention:")
                                for flag in risk_flags:
                                    st.write(f"- {explain_risk_flag(flag)}")
                            else:
                                st.write("No scanner warnings were found for this target.")

                        with st.expander("Technical JSON details"):
                            st.json(res)

                        # Save to the inventory only in LIVE mode, so the cached demo dataset stays unchanged
                        if mode_selection == "🟡 CACHED MODE":
                            st.info("Cached mode: this scan is shown but not saved, so the cached demo dataset stays unchanged.")
                        else:
                            with open("temp_scan.json", "w") as f:
                                json.dump([res], f)
                            inv.ingest_scan_results("temp_scan.json", DB_PATH)
                            score_eng.score_all_assets(DB_PATH)
                            st.success(f"✅ Scanned {host}:{port} successfully and ingested into database inventory!")
                    else:
                        st.error(f"Final verdict: {verdict}")
                        st.write(f"**Reason:** {reason}")
                        st.write(f"**Recommended action:** {recommendation}")
                        st.write(res.get("error") or "The target may be unreachable, blocked, or not serving TLS on this port.")
                        with st.expander("Technical JSON details"):
                            st.json(res)
                        if status == "unreachable":
                            st.warning(f"⚠️ Target unreachable — no result ingested. ({res.get('error', 'no details')})")
                        else:
                            st.error(f"❌ Scan error — no result ingested. Status: {status}. ({res.get('error', 'no details')})")


# ---------------------------------------------------------
# TAB 8: GUIDED TOUR & ASSISTANT (works offline; AI optional)
# ---------------------------------------------------------
with tab8:
    def _band_counts(scores):
        return {
            "critical_80_plus": int((scores >= 80).sum()),
            "medium_50_to_79": int(((scores >= 50) & (scores < 80)).sum()),
            "low_below_50": int((scores < 50).sum()),
        }

    ai_summary = {"data_source": mode_selection, "asset_rows_in_current_database": int(len(df))}
    if not df.empty and "risk_score" in df.columns:
        _scores = pd.to_numeric(df["risk_score"], errors="coerce").dropna()
        if len(_scores):
            ai_summary.update(_band_counts(_scores))
            ai_summary["highest_risk_score"] = round(float(_scores.max()), 1)
            ai_summary["average_risk_score"] = round(float(_scores.mean()), 1)
    render_guide_and_assistant(get_ai_pool(), ai_summary)