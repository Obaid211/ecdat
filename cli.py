"""
ECDAT - Master Command Line Interface (CLI)
--------------------------------------------
Executes all ECDAT stages (1 through 6 + Code Scanner) individually or as a single
end-to-end automated discovery & analysis pipeline.

Usage:
    python cli.py pipeline --hosts hosts.txt
    python cli.py scan --hosts hosts.txt --out scan_results.json
    python cli.py ingest --file scan_results.json
    python cli.py score
    python cli.py simulate --asset 1
    python cli.py scan-code --dir .
    python cli.py cbom --out cbom.json
"""

import argparse
import json
import sys
from pathlib import Path

import ecdat_scanner as scanner_core
import ecdat_inventory as inv
import ecdat_scoring as score_eng
import ecdat_simulator as sim_eng
import ecdat_codescanner as code_eng
import ecdat_remediation as rem_eng
import ecdat_threat_timeline as threat_eng
import ecdat_containerscanner as cnt_eng
import ecdat_apiscanner as api_eng
import ecdat_diff as diff_eng


def main():
    parser = argparse.ArgumentParser(
        description="ECDAT — Enterprise Cryptographic Discovery & Analysis Tool CLI"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Command: pipeline
    pipe_p = subparsers.add_parser("pipeline", help="Run full end-to-end discovery & analysis pipeline")
    pipe_p.add_argument("--hosts", default="hosts.txt", help="Path to hosts file")
    pipe_p.add_argument("--code-dir", default=".", help="Directory to scan for code crypto issues")
    pipe_p.add_argument("--out-scan", default="scan_results.json", help="Output scan JSON path")
    pipe_p.add_argument("--out-cbom", default="ecdat_cbom.json", help="Output CycloneDX CBOM path")
    pipe_p.add_argument("--skip-scan", action="store_true", help="Skip live scanning and reuse cached scan results")

    # Command: scan
    scan_p = subparsers.add_parser("scan", help="Stage 1 & 2: TLS & Cert Discovery Scan")
    scan_p.add_argument("--host", help="Single host, e.g. example.com:443")
    scan_p.add_argument("--hosts", help="Path to hosts file")
    scan_p.add_argument("--out", default="scan_results.json", help="Output scan JSON path")

    # Command: ingest
    ingest_p = subparsers.add_parser("ingest", help="Stage 3: Ingest scan JSON into SQLite DB")
    ingest_p.add_argument("--file", required=True, help="JSON scan file path")

    # Command: score
    score_p = subparsers.add_parser("score", help="Stage 4: Calculate MWQRS Quantum Risk Scores")

    # Command: simulate
    sim_p = subparsers.add_parser("simulate", help="Stage 6: Simulate PQC Migration")
    sim_p.add_argument("--asset", type=int, help="Asset ID to simulate migration for")

    # Command: scan-code
    code_p = subparsers.add_parser("scan-code", help="Bonus: Source Code Cryptographic Scanner")
    code_p.add_argument("--dir", default=".", help="Directory to scan")

    # Command: cbom
    cbom_p = subparsers.add_parser("cbom", help="Export CycloneDX 1.6 CBOM document")
    cbom_p.add_argument("--out", default="ecdat_cbom.json", help="Output path")

    # Command: remediation
    rem_p = subparsers.add_parser("remediation", help="Capability 2: Priority-Based Cryptographic Remediation Sequencing")
    rem_p.add_argument("--limit", type=int, default=5, help="Number of items to display (default 5)")
    rem_p.add_argument("--out", help="Optional output path (.md or .json)")

    # Command: threat-timeline
    threat_p = subparsers.add_parser("threat-timeline", help="Capability 3: Threat-Timeline & Mosca Urgency Evaluation")
    threat_p.add_argument("--horizon", type=float, default=10.0, help="Planning horizon assumption in years (default 10.0)")
    threat_p.add_argument("--limit", type=int, default=5, help="Number of items to display (default 5)")

    # Command: scan-container
    cnt_p = subparsers.add_parser("scan-container", help="Capability 7: Container & Dockerfile Cryptographic Scanner")
    cnt_p.add_argument("--target", default="samples/container_fixtures/Dockerfile.legacy_service", help="Path to Dockerfile or container directory")

    # Command: scan-api
    api_p = subparsers.add_parser("scan-api", help="Capability 8: API Cryptographic Scanner")
    api_p.add_argument("--url", help="Live API URL to inspect")
    api_p.add_argument("--fixture", default="samples/api_fixtures/api_jwt_rs256.json", help="Path to controlled API fixture JSON")
    api_p.add_argument("--jwt", help="Optional sample JWT token to analyze")

    # Command: snapshot
    snap_p = subparsers.add_parser("snapshot", help="Capability 10: Save current scan snapshot for diff tracking")
    snap_p.add_argument("--name", default="Manual Scan Snapshot", help="Label for this snapshot")

    # Command: diff
    diff_p = subparsers.add_parser("diff", help="Capability 10: Compare two scan snapshots and generate diff alerts")
    diff_p.add_argument("--old", type=int, required=True, help="Baseline snapshot ID")
    diff_p.add_argument("--new", type=int, required=True, help="Comparison snapshot ID")
    diff_p.add_argument("--out", help="Optional markdown report output path")

    args = parser.parse_args()

    if not args.command or args.command == "pipeline":
        hosts_file = getattr(args, "hosts", "hosts.txt")
        scan_out = getattr(args, "out_scan", "scan_results.json")
        cbom_out = getattr(args, "out_cbom", "ecdat_cbom.json")
        code_dir = getattr(args, "code_dir", ".")

        print("==========================================================================")
        print("  ECDAT — Enterprise Cryptographic Discovery & Analysis Pipeline  ")
        print("==========================================================================")

        # Step 1: Scan TLS Endpoints
        skip_scan = getattr(args, "skip_scan", False)
        if skip_scan and Path(scan_out).exists():
            print(f"\n[Stage 1 & 2] Skipping live network scan (--skip-scan); reusing cached '{scan_out}'...")
        else:
            targets = []
            if Path(hosts_file).exists():
                with open(hosts_file) as f:
                    for line in f:
                        t = scanner_core.parse_target(line)
                        if t:
                            targets.append(t)

            if targets:
                print(f"\n[Stage 1 & 2] Scanning {len(targets)} host target(s)...")
                results = scanner_core.scan_targets(targets)
                with open(scan_out, "w") as f:
                    json.dump(results, f, indent=2, default=str)
                scanner_core.print_summary(results)
            else:
                print(f"\n[Stage 1 & 2] No targets found in {hosts_file}. Skipping scan execution.")

        # Step 2: Stage 3 Ingestion & Seeding
        print("\n[Stage 3] Ingesting results into SQLite database (ecdat.db)...")
        inv.init_db()
        if Path(scan_out).exists():
            inv.ingest_scan_results(scan_out)
        inv.seed_demo_data()

        # Step 3: Stage 4 MWQRS Scoring
        print("\n[Stage 4] Calculating Mosca-Weighted Quantum Risk Scores (MWQRS)...")
        scored = score_eng.score_all_assets()
        print(f"-> Scored {len(scored)} assets. Highest risk score: {scored[0]['risk_score']} ({scored[0]['host']})")

        # Step 4: Bonus Code Scanner
        print(f"\n[Bonus Code Scanner] Scanning source code in '{code_dir}'...")
        code_findings = code_eng.scan_source_directory(code_dir)
        print(f"-> Discovered {len(code_findings)} code-level cryptographic findings.")

        # Step 5: Stage 6 PQC Simulator Roadmap
        print("\n[Stage 6] Computing Topological PQC Migration Sequence Roadmap...")
        roadmap = sim_eng.recommend_migration_order()
        print("-" * 80)
        print(f"{'SEQ':4} {'HOST':24} {'MWQRS':8} {'CURRENT ALGO':20} {'RECOMMENDED NIST PQC'}")
        print("-" * 80)
        for r in roadmap[:5]:
            print(f"#{r['sequence_position']:<3} {r['host']:24} {r['risk_score']:<8} {r['current_algo']:20} {r['target_pqc']}")
        print("-" * 80)

        # Step 6: Export CBOM
        print(f"\n[Stage 3 CBOM] Exporting CycloneDX CBOM 1.6 document to '{cbom_out}'...")
        cbom_content = inv.export_cbom()
        with open(cbom_out, "w", encoding="utf-8") as f:
            f.write(cbom_content)
        print(f"-> CBOM document successfully written to {cbom_out}")

        # Step 7: Record Scan Snapshot for 24-Hour Rescan Diff Tracking
        snap_id = inv.save_scan_snapshot("Pipeline Automated Run")
        print(f"\n[Capability 10 Diff Engine] Scan snapshot recorded: #{snap_id} ('Pipeline Automated Run')")

        # Step 8: Priority Remediation Plan Preview
        plan = rem_eng.generate_remediation_plan()
        if plan:
            top = plan[0]
            print(f"\n[Capability 2 Remediation Center] #1 Priority Asset: {top['target']} ({top['service']})")
            print(f"  -> Why Prioritized: {top['why_prioritized']}")
            print(f"  -> Recommended Action: {top['recommended_actions'][0] if top['recommended_actions'] else 'Review'}")

        print("\n==========================================================================")
        print("  Pipeline Execution Complete! Launch Dashboard: streamlit run app.py")
        print("==========================================================================")

    elif args.command == "scan":
        targets = []
        if args.host:
            t = scanner_core.parse_target(args.host)
            if t:
                targets.append(t)
        if args.hosts and Path(args.hosts).exists():
            with open(args.hosts) as f:
                for line in f:
                    t = scanner_core.parse_target(line)
                    if t:
                        targets.append(t)

        print(f"Scanning {len(targets)} target(s)...")
        results = scanner_core.scan_targets(targets)
        with open(args.out, "w") as f:
            json.dump(results, f, indent=2, default=str)
        scanner_core.print_summary(results)
        bench = scanner_core.calculate_scan_benchmark(results)
        print(f"\n[Measured Performance Benchmark] {bench['successful']}/{bench['total_attempted']} successful | Avg: {bench['average_seconds']}s/host | Median: {bench['median_seconds']}s | Max: {bench['max_seconds']}s")

    elif args.command == "ingest":
        count = inv.ingest_scan_results(args.file)
        print(f"Successfully ingested {count} assets into ecdat.db.")

    elif args.command == "score":
        scored = score_eng.score_all_assets()
        print(f"Calculated MWQRS risk scores for {len(scored)} assets.")

    elif args.command == "simulate":
        if args.asset:
            res = sim_eng.simulate_migration(args.asset)
            print(json.dumps(res, indent=2))
        else:
            roadmap = sim_eng.recommend_migration_order()
            print(json.dumps(roadmap, indent=2))

    elif args.command == "scan-code":
        findings = code_eng.scan_source_directory(args.dir)
        print(f"Found {len(findings)} findings in source code.")

    elif args.command == "cbom":
        content = inv.export_cbom()
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"CycloneDX CBOM exported to {args.out}")

    elif args.command == "remediation":
        plan = rem_eng.generate_remediation_plan()
        print(f"Generated remediation plan for {len(plan)} assets:")
        for item in plan[:args.limit]:
            print(f"#{item['priority_rank']} {item['target']} ({item['service']}) | MWQRS: {item['mwqrs']} | {item['why_prioritized']}")
        if args.out:
            if args.out.endswith(".json"):
                Path(args.out).write_text(rem_eng.export_remediation_json(plan), encoding="utf-8")
            else:
                Path(args.out).write_text(rem_eng.export_remediation_markdown(plan), encoding="utf-8")
            print(f"Remediation plan exported to {args.out}")

    elif args.command == "threat-timeline":
        res = threat_eng.evaluate_inventory_threat_urgency(planning_horizon_years=args.horizon)
        print(f"Mosca-Inspired Threat Timeline Evaluations (Horizon: {args.horizon}y, Total: {len(res)}):")
        for item in res[:args.limit]:
            print(f"[{item['urgency_level']}] {item['asset_name']} | Requirement: {item['combined_requirement_years']}y | {item['summary_reason'][:80]}...")

    elif args.command == "scan-container":
        findings = cnt_eng.scan_container_target(args.target)
        print(f"Container Scan of '{args.target}' Complete. Discovered {len(findings)} findings:")
        for f in findings:
            print(f" - [{f['severity']}] {f['finding_type']} -> {f['evidence'][:60]}")

    elif args.command == "scan-api":
        if args.url:
            rep = api_eng.inspect_api_endpoint(args.url, sample_jwt=args.jwt)
            print(f"API Scan of '{args.url}' Complete. Risk Level: {rep['overall_risk']}")
            print(json.dumps(rep, indent=2))
        else:
            rep = api_eng.inspect_api_fixture(args.fixture)
            print(f"API Fixture Scan of '{args.fixture}' Complete. Risk Level: {rep['overall_risk']}")
            print(json.dumps(rep, indent=2))

    elif args.command == "snapshot":
        snap_id = inv.save_scan_snapshot(args.name)
        print(f"Created scan snapshot #{snap_id} ('{args.name}').")

    elif args.command == "diff":
        d = diff_eng.compare_snapshots(args.old, args.new)
        print("Diff Summary:")
        print(json.dumps(d.get("summary", {}), indent=2))
        print("\nAlerts:")
        for a in d.get("alerts", []):
            print(f"  * {a}")
        if args.out:
            Path(args.out).write_text(diff_eng.export_diff_markdown(d), encoding="utf-8")
            print(f"\nDiff report written to {args.out}")


if __name__ == "__main__":
    main()
