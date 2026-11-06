import argparse
import sys
from pathlib import Path
from ariadns.models.config import AppConfig
from ariadns.modules.m5_orchestrator import Orchestrator
from ariadns.modules.m6_reporting import ReportingEngine
from ariadns.storage.db import DatabaseManager
from ariadns.storage.graph_store import PropertyGraphStore
from ariadns.utils.tool_runner import check_environment

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ariadns",
        description="Ariadns: Automated Domain OSINT & Pivoting Engine"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: run (one-shot investigation)
    run_parser = subparsers.add_parser("run", help="Run full domain investigation")
    run_parser.add_argument("-d", "--domain", required=True, help="Target L1 domain")
    run_parser.add_argument("--depth", type=int, default=1, choices=[1, 2], help="Recursion depth (default: 1)")
    run_parser.add_argument("--output-dir", default="./reports", help="Directory to save reports")
    run_parser.add_argument("--no-portscan", action="store_true", help="Skip port scanning")

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
    print(f"    - JSON Result: {paths['result_json']}")
    print(f"    - Topology:    {paths['topology_json']}")
    print(f"    - Report:      {paths['report_md']}")
    return 0

def execute_doctor() -> int:
    print("[*] Ariadns System Dependency Check:")
    tools = check_environment()
    for name, info in tools.items():
        status = "[INSTALLED]" if info["installed"] else "[MISSING -> FALLBACK TO NATIVE]"
        print(f"    - {name:<12}: {status} (Path: {info['path']})")
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
        return 0
    print("[-] config.yaml.example not found.")
    return 1

def main(args: list[str] | None = None) -> int:
    parser = build_parser()
    parsed = parser.parse_args(args)

    if parsed.command == "run" or (parsed.domain and not parsed.command):
        target = parsed.domain
        return execute_run(
            domain=target,
            depth=parsed.depth,
            output_dir=parsed.output_dir,
            no_portscan=parsed.no_portscan,
        )
    elif parsed.command == "doctor":
        return execute_doctor()
    elif parsed.command == "init":
        return execute_init()
    elif parsed.command == "repl":
        from ariadns.interfaces.repl import start_repl
        return start_repl(parsed.domain)
    else:
        parser.print_help()
        return 0

if __name__ == "__main__":
    sys.exit(main())
