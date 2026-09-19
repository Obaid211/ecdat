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


DB_PATH = inv.DEFAULT_DB_PATH

# Ensure DB is initialized & scored on load
inv.init_db(DB_PATH)

# Title & Info Header
st.markdown('<div class="main-header">ECDAT — Enterprise Cryptographic Discovery & Analysis Tool</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">SIH26164 (NTRO / Post-Quantum Cryptography & Keyfactor AgileSec Pipeline Model)</div>', unsafe_allow_html=True)

# Sidebar Actions
st.sidebar.image("https://img.icons8.com/color/96/shield-with-encryption.png", width=70)
st.sidebar.title("Pipeline Controls")
st.sidebar.markdown("---")

if st.sidebar.button("🔄 Refresh Data & Recalculate Scores"):
    score_eng.score_all_assets(DB_PATH)
    st.sidebar.success("Database rescored successfully!")

if st.sidebar.button("🌱 Re-Seed Demo Services"):
    inv.seed_demo_data(DB_PATH)
    score_eng.score_all_assets(DB_PATH)
    st.sidebar.success("Demo services & dependencies re-seeded!")

st.sidebar.markdown("---")
st.sidebar.info("""
**SIH Problem Statement SIH26164**
- Discover → Inventory → Prioritize → Remediate
- Mosca's Inequality Quantum Scoring (MWQRS)
- NIST FIPS 203/204/205 PQC Migration
- CycloneDX CBOM Spec 1.6 Output
""")

# Load Scored Assets
scored_assets = score_eng.score_all_assets(DB_PATH)
df = pd.DataFrame(scored_assets)

# Define Tabs
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "📊 Executive Dashboard",
    "📜 CBOM Inventory",
    "🕸️ Service Dependency Graph",
    "🚀 PQC Migration Simulator",
    "🔍 Source Code Scanner",
    "⚡ Live TLS Scanner"
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
# TAB 2: CBOM INVENTORY TABLE
# ---------------------------------------------------------
with tab2:
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
# TAB 3: DEPENDENCY GRAPH
# ---------------------------------------------------------
with tab3:
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
# TAB 4: PQC MIGRATION SIMULATOR
# ---------------------------------------------------------
with tab4:
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
# TAB 5: SOURCE CODE SCANNER
# ---------------------------------------------------------
with tab5:
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
# TAB 6: LIVE TLS SCANNER
# ---------------------------------------------------------
with tab6:
    st.subheader("Run Real-Time Cryptographic Discovery Scan")

    scan_target_input = st.text_input("Enter Target Host (e.g., example.com:443 or 127.0.0.1:8443)", "127.0.0.1:8443")

    if st.button("⚡ Execute Live TLS Handshake & Scan"):
        with st.spinner(f"Connecting over TLS to {scan_target_input}..."):
            parsed = scanner_core.parse_target(scan_target_input)
            if parsed:
                host, port = parsed
                res = scanner_core.scan_host(host, port)

                st.json(res)

                # Auto-ingest into DB
                with open("temp_scan.json", "w") as f:
                    json.dump([res], f)
                inv.ingest_scan_results("temp_scan.json", DB_PATH)
                score_eng.score_all_assets(DB_PATH)
                st.success(f"Scanned {host}:{port} and ingested into database inventory!")
            else:
                st.error("Invalid target format.")
