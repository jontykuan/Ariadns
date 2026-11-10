"""Ariadns Command Line Interface (CLI)."""

import argparse
import sys
from pathlib import Path
from typing import Optional
from ariadns.models.config import AppConfig
from ariadns.modules.m5_orchestrator import Orchestrator
from ariadns.modules.m6_reporting import ReportingEngine, render_evidence_artifacts
from ariadns.modules.m7_manual_oob import trigger_manual_oob
from ariadns.modules.m8_recommender import NextStepRecommender
from ariadns.storage.db import DatabaseManager
from ariadns.storage.forensic_verifier import verify_case_artifacts
from ariadns.storage.graph_store import PropertyGraphStore
from ariadns.utils.tool_runner import check_environment
from ariadns.utils.warninglist_sync import WarninglistSynchronizer

def build_parser() -> argparse.ArgumentParser:
    epilog_text = (
        "API Configuration (config.yaml):\n"
        "  Ariadns is 100% functional keyless by default using Team Cymru BGP/ASN, crt.sh, and local probers.\n"
        "  To enable optional historical passive DNS and extended pivoting, run 'ariadns init' and fill in config.yaml:\n"
        "    - virustotal (Free tier: 4 req/min, 500 req/day)\n"
        "    - alienvault_otx (Free API key for historical pDNS)\n"
        "    - securitytrails, whoisxml, viewdns, hackertarget, publicwww (Optional)\n"
    )
    parser = argparse.ArgumentParser(
        prog="ariadns",
        description="Ariadns: Automated Domain OSINT & Pivoting Engine",
        epilog=epilog_text,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: run (one-shot investigation)
    run_parser = subparsers.add_parser("run", help="Run full domain investigation")
    run_parser.add_argument("-d", "--domain", required=True, help="Target L1 domain")
    run_parser.add_argument("--depth", type=int, default=1, choices=[1, 2], help="Recursion depth (default: 1)")
    run_parser.add_argument("--output-dir", default="./reports", help="Directory to save reports")
    run_parser.add_argument("--no-portscan", action="store_true", help="Skip port scanning")

    # Command: step (stepwise module execution)
    step_parser = subparsers.add_parser("step", help="Run a single module stepwise against a case session")
    step_parser.add_argument("-d", "--domain", required=True, help="Case session domain")
    step_parser.add_argument("-m", "--module", required=True, choices=["m1", "m2", "m3", "m4", "m7", "trace"], help="Module to execute")
    step_parser.add_argument("--target", help="Specific target entity (defaults to session domain)")

    # Command: trace (active route hop tracer)
    trace_parser = subparsers.add_parser("trace", help="Run active route hop tracer (Requires --ack-risk)")
    trace_parser.add_argument("-d", "--domain", required=True, help="Case session domain")
    trace_parser.add_argument("--target", help="Target IP or domain to trace (defaults to session domain)")
    trace_parser.add_argument("--resolve-dns", action="store_true", help="Disable -d flag and allow OS reverse DNS during trace")
    trace_parser.add_argument("-H", "--max-hops", type=int, default=20, help="Maximum hops (-h, default: 20)")
    trace_parser.add_argument("-w", "--timeout", type=int, default=500, help="Timeout per hop in ms (-w, default: 500)")
    trace_parser.add_argument("--tail-hops", type=int, default=3, help="Number of last responsive hops to retain (default: 3)")
    trace_parser.add_argument("--ack-risk", action="store_true", help="Acknowledge OPSEC active probing risk")

    # Command: recommend (next-step recommendations)
    rec_parser = subparsers.add_parser("recommend", help="Get rule-based next-step investigation recommendations")
    rec_parser.add_argument("-d", "--domain", required=True, help="Case session domain")

    # Command: render-graph (deterministic static graph & manifest)
    render_parser = subparsers.add_parser("render-graph", help="Render static SVG/PNG evidence DAG and forensic manifest")
    render_parser.add_argument("-d", "--domain", required=True, help="Case session domain")
    render_parser.add_argument("--output-dir", default="./reports", help="Output directory")
    render_parser.add_argument("--select", help="Comma-separated proposition IDs to include in the render")

    # Command: show-graph (display structured propositions)
    show_parser = subparsers.add_parser("show-graph", help="Display structured propositions and audit logs for a case session")
    show_parser.add_argument("-d", "--domain", required=True, help="Case session domain")

    # Command: verify (forensic integrity verification)
    ver_parser = subparsers.add_parser("verify", help="Verify cryptographic integrity of case directory artifacts")
    ver_parser.add_argument("--case-dir", required=True, help="Directory containing case artifacts and manifest")
    ver_parser.add_argument("--db-path", help="Optional path to SQLite database for payload recomputation")

    # Command: sync-lists (warninglist sync)
    sync_parser = subparsers.add_parser("sync-lists", help="Synchronize false-positive warninglists into local SQLite")
    sync_parser.add_argument("--force", action="store_true", help="Force immediate re-synchronization")

    # Command: manual-oob (isolated OOB probe)
    oob_parser = subparsers.add_parser("manual-oob", help="Trigger manual OOB callback probe (Requires risk ack)")
    oob_parser.add_argument("-t", "--target-url", required=True, help="Target endpoint URL (e.g. https://target.com/preview)")
    oob_parser.add_argument("-c", "--callback-url", required=True, help="Your listener / canary callback URL")
    oob_parser.add_argument("-p", "--param", default="url", help="Parameter name to inject callback URL into")
    oob_parser.add_argument("-m", "--method", default="GET", choices=["GET", "POST"], help="HTTP method")
    oob_parser.add_argument("--ack-risk", action="store_true", help="Acknowledge OPSEC risk to proceed with probe")

    # Command: ui (local web UI forensic workbench)
    ui_parser = subparsers.add_parser("ui", help="Start local web UI forensic workbench")
    ui_parser.add_argument("--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
    ui_parser.add_argument("--port", type=int, default=8000, help="Port to bind (default: 8000)")
    ui_parser.add_argument("--db-path", help="Optional path to SQLite database")
    ui_parser.add_argument("--output-dir", default="./reports", help="Output directory")
    ui_parser.add_argument("--open-browser", action="store_true", help="Open browser automatically")

    # Command: repl (interactive console)
    repl_parser = subparsers.add_parser("repl", help="Start interactive REPL console")
    repl_parser.add_argument("-d", "--domain", help="Initial target domain (optional)")

    # Command: doctor (environment check)
    subparsers.add_parser("doctor", help="Check system dependencies and tools")

    # Command: init (generate default config)
    subparsers.add_parser("init", help="Initialize local config.yaml from template")

    # Legacy CLI arguments for SRS 5.1 compatibility (e.g. recon.py -d ...)
    parser.add_argument("-d", "--domain", help="Target L1 domain (shortcut for 'run')")
    parser.add_argument("--depth", type=int, default=1, choices=[1, 2], help="Recursion depth")
    parser.add_argument("--output-dir", default="./reports", help="Output directory")
    parser.add_argument("--no-portscan", action="store_true", help="Skip port scanning")

    return parser

def execute_run(domain: str, depth: int, output_dir: str, no_portscan: bool) -> int:
    print(f"[*] Starting Ariadns investigation on: {domain} (Depth: {depth})")
    orchestrator = Orchestrator()
    result = orchestrator.run_investigation(
        domain=domain,
        depth=depth,
        run_portscan=not no_portscan
    )
    graph_store = PropertyGraphStore(orchestrator.db, session_id=domain)
    reporter = ReportingEngine(output_dir=output_dir)
    paths = reporter.export_all(result, graph_store=graph_store)

    print("[+] Investigation complete!")
    print(f"    - JSON Result:     {paths['result_json']}")
    print(f"    - Evidence Chain:  {paths['evidence_chain_json']}")
    print(f"    - Topology:        {paths['topology_json']}")
    print(f"    - Report:          {paths['report_md']}")
    return 0

def execute_step(domain: str, module_name: str, target: Optional[str]) -> int:
    orchestrator = Orchestrator()
    step_target = target or domain
    print(f"[*] Executing step {module_name} on target: {step_target} (Session: {domain})")
    entry = orchestrator.run_step(domain, module_name, step_target)
    print(f"[+] Step {entry.step_seq} completed successfully!")
    print(f"    - Module:      {entry.module_name}")
    print(f"    - Target:      {entry.target}")
    print(f"    - Added Facts: {entry.added_fact_ids}")
    print(f"    - State Hash:  {entry.artifact_sha256}")
    return 0

def execute_recommend(domain: str) -> int:
    orchestrator = Orchestrator()
    recommender = NextStepRecommender(orchestrator.db, orchestrator.config)
    recs = recommender.recommend(domain)
    print(f"[*] Next-Step Recommendations for session: {domain}")
    if not recs:
        print("    - No immediate recommendations; evidence convergence reached.")
        return 0
    for r in recs:
        print(f"\n[{r.rec_id}] Recommend Module: {r.recommended_module.upper()} on Target: {r.recommended_target}")
        print(f"     Rationale: {r.rationale}")
        print(f"     Expected:  {r.expected_evidence}")
        print(f"     CLI:       {r.cli_command}")
    return 0

def execute_render_graph(domain: str, output_dir: str, select_str: Optional[str]) -> int:
    orchestrator = Orchestrator()
    selected_ids = [x.strip() for x in select_str.split(",") if x.strip()] if select_str else None
    svg, png, md, manifest = render_evidence_artifacts(
        session_id=domain,
        db=orchestrator.db,
        output_dir=output_dir,
        selected_prop_ids=selected_ids
    )
    print(f"[+] Static evidence graph and manifest rendered successfully!")
    print(f"    - SVG:          {svg}")
    print(f"    - PNG:          {png}")
    print(f"    - Report:       {md}")
    print(f"    - Payload Hash: {manifest.payload_sha256}")
    return 0

def execute_show_graph(domain: str) -> int:
    orchestrator = Orchestrator()
    props = orchestrator.db.get_normalized_propositions(domain, rendered_only=False)
    logs = orchestrator.db.get_audit_logs(domain)
    print(f"[*] Case Session Evidence Graph: {domain}")
    print(f"\n--- Propositions ({len(props)}) ---")
    for p in props:
        rend = "[RENDERED]" if p.is_rendered else "[EXCLUDED]"
        print(f"  {p.prop_id:<12} (Rank {p.rank}) {rend} {p.node_kind}: {p.statement}")
    print(f"\n--- Audit Logs ({len(logs)}) ---")
    for l in logs:
        print(f"  Step {l.step_seq}: [{l.timestamp}] {l.module_name} on {l.target} -> Added: {l.added_fact_ids}")
    return 0

def execute_verify(case_dir: str, db_path: Optional[str]) -> int:
    db = DatabaseManager(db_path) if db_path else None
    res = verify_case_artifacts(case_dir, db=db)
    status_str = "TRUE" if res["verified"] else "FALSE"
    print(f"[*] Forensic Verification Result: VERIFIED: {status_str}")
    print(f"    - Session ID:   {res['session_id']}")
    print(f"    - Payload Hash: {res['payload_sha256']}")
    if res["mismatches"]:
        print("[-] Mismatches detected:")
        for m in res["mismatches"]:
            print(f"    ! {m}")
        return 1
    print("[+] All artifact files and evidence DAG payload verified bit-for-bit!")
    return 0

def execute_sync_lists(force: bool) -> int:
    orchestrator = Orchestrator()
    syncer = WarninglistSynchronizer(orchestrator.db, orchestrator.http_client, orchestrator.config)
    status = syncer.ensure_warninglists_synced(force=force)
    last_synced = orchestrator.db.get_warninglist_last_synced()
    print(f"[*] Warninglist synchronization status: {status.value}")
    print(f"    - Last Synced Epoch: {last_synced}")
    return 0

def execute_manual_oob(target_url: str, callback_url: str, param: str, method: str, ack_risk: bool) -> int:
    res = trigger_manual_oob(
        target_endpoint_url=target_url,
        callback_url=callback_url,
        param_name=param,
        http_method=method,
        acknowledge_opsec_risk=ack_risk,
    )
    if not res.get("callback_sent"):
        print(f"[-] {res.get('warning', 'OOB Probe Failed')}")
        if res.get("error"):
            print(f"    Reason: {res['error']}")
        return 1
    print(f"[+] OOB trigger sent to {target_url} via {method} with callback {callback_url}.")
    print(f"    HTTP Status: {res.get('target_status_code')}")
    print(f"    Note: {res.get('note')}")
    return 0

def execute_trace(
    domain: str,
    target: Optional[str],
    no_rdns: bool,
    max_hops: int,
    timeout_ms: int,
    tail_hops: int,
    ack_risk: bool,
) -> int:
    from ariadns.modules.m9_traceroute import TRACE_OPSEC_WARNING
    if not ack_risk:
        print(f"[-] {TRACE_OPSEC_WARNING}")
        return 1
    orchestrator = Orchestrator()
    step_target = target or domain
    entry = orchestrator.run_step(
        session_id=domain,
        module_name="trace",
        target=step_target,
        params={
            "no_rdns": no_rdns,
            "max_hops": max_hops,
            "timeout_ms": timeout_ms,
            "tail_hops": tail_hops,
            "ack_opsec": True,
        },
    )
    print(f"[+] Route hop trace completed on {step_target} (Session: {domain})")
    print(f"    - Added Facts: {entry.added_fact_ids}")
    print(f"    - State Hash:  {entry.artifact_sha256}")
    return 0

def execute_ui(host: str, port: int, db_path: Optional[str], output_dir: str, open_browser: bool) -> int:
    from ariadns.interfaces.web_ui import start_web_ui
    server = start_web_ui(host=host, port=port, db_path=db_path, output_dir=output_dir, open_browser=open_browser)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Web UI stopped.")
    finally:
        server.server_close()
    return 0

def execute_doctor() -> int:
    print("[*] Ariadns System Dependency Check:")
    tools = check_environment()
    for name, info in tools.items():
        status = "[INSTALLED]" if info["installed"] else "[MISSING -> FALLBACK TO NATIVE]"
        print(f"    - {name:<12}: {status} (Path: {info['path']})")
    from ariadns.modules.m6_reporting import HAS_PIL
    pil_status = "[INSTALLED]" if HAS_PIL else "[MISSING -> FALLBACK TO SVG ONLY (pip install pillow)]"
    print(f"    - {'pillow':<12}: {pil_status}")
    return 0

def execute_init() -> int:
    cfg_file = Path("config.yaml")
    example_file = Path("config.yaml.example")
    if cfg_file.exists():
        print("[!] config.yaml already exists.")
        return 0
    if example_file.exists():
        cfg_file.write_text(example_file.read_text(encoding="utf-8"), encoding="utf-8")
        print("[+] Initialized config.yaml from config.yaml.example.")
        print("[*] Note: Ariadns is fully operational keyless. Add optional VirusTotal/OTX API keys to config.yaml if available.")
        return 0
    print("[-] config.yaml.example not found.")
    return 1

def main(args: list[str] | None = None) -> int:
    parser = build_parser()
    effective_args = sys.argv[1:] if args is None else list(args)
    if not effective_args or any(a.lower() in ("help", "/h", "-h", "--help", "?") for a in effective_args):
        parser.print_help()
        return 0

    parsed = parser.parse_args(effective_args)

    if parsed.command == "run" or (getattr(parsed, "domain", None) and not parsed.command):
        target = parsed.domain
        return execute_run(
            domain=target,
            depth=parsed.depth,
            output_dir=parsed.output_dir,
            no_portscan=parsed.no_portscan,
        )
    elif parsed.command == "step":
        return execute_step(parsed.domain, parsed.module, parsed.target)
    elif parsed.command == "recommend":
        return execute_recommend(parsed.domain)
    elif parsed.command == "render-graph":
        return execute_render_graph(parsed.domain, parsed.output_dir, parsed.select)
    elif parsed.command == "show-graph":
        return execute_show_graph(parsed.domain)
    elif parsed.command == "verify":
        return execute_verify(parsed.case_dir, parsed.db_path)
    elif parsed.command == "sync-lists":
        return execute_sync_lists(parsed.force)
    elif parsed.command == "manual-oob":
        return execute_manual_oob(
            target_url=parsed.target_url,
            callback_url=parsed.callback_url,
            param=parsed.param,
            method=parsed.method,
            ack_risk=parsed.ack_risk,
        )
    elif parsed.command == "trace":
        return execute_trace(
            domain=parsed.domain,
            target=parsed.target,
            no_rdns=not parsed.resolve_dns,
            max_hops=parsed.max_hops,
            timeout_ms=parsed.timeout,
            tail_hops=parsed.tail_hops,
            ack_risk=parsed.ack_risk,
        )
    elif parsed.command == "doctor":
        return execute_doctor()
    elif parsed.command == "init":
        return execute_init()
    elif parsed.command == "ui":
        return execute_ui(
            host=parsed.host,
            port=parsed.port,
            db_path=parsed.db_path,
            output_dir=parsed.output_dir,
            open_browser=parsed.open_browser,
        )
    elif parsed.command == "repl":
        from ariadns.interfaces.repl import start_repl
        return start_repl(parsed.domain)
    else:
        parser.print_help()
        return 0

if __name__ == "__main__":
    sys.exit(main())
