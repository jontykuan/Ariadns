import sys
from typing import Optional
from ariadns.models.config import AppConfig
from ariadns.models.enums import NodeType
from ariadns.modules.m5_orchestrator import Orchestrator
from ariadns.storage.db import DatabaseManager
from ariadns.storage.graph_store import PropertyGraphStore

def start_repl(initial_domain: Optional[str] = None) -> int:
    config = AppConfig.load()
    db = DatabaseManager(config.db_path)
    orchestrator = Orchestrator(config=config, db=db)
    current_domain = initial_domain

    print("=" * 60)
    print("  Ariadns Interactive REPL Console")
    print("  Type 'help' for commands, 'exit' to quit.")
    print("=" * 60)

    while True:
        try:
            prompt = f"ariadns({current_domain or 'none'})> "
            cmd_line = input(prompt).strip()
            if not cmd_line:
                continue

            parts = cmd_line.split()
            cmd = parts[0].lower()

            if cmd in ("exit", "quit", "q"):
                print("[*] Exiting REPL.")
                break
            elif cmd == "help":
                print("Commands:")
                print("  target <domain>    Set active domain")
                print("  scan [depth]       Run investigation (depth 1 or 2)")
                print("  nodes              List discovered graph nodes")
                print("  l2                 List L2 candidate domains")
                print("  expand <domain>    Deep probe a specific L2 domain")
                print("  exit               Quit console")
            elif cmd == "target":
                if len(parts) > 1:
                    current_domain = parts[1].strip()
                    print(f"[*] Active domain set to: {current_domain}")
                else:
                    print("Usage: target <domain>")
            elif cmd == "scan":
                if not current_domain:
                    print("[-] Please set target domain first with: target <domain>")
                    continue
                d = int(parts[1]) if len(parts) > 1 else 1
                print(f"[*] Scanning {current_domain} at depth {d}...")
                orchestrator.run_investigation(current_domain, depth=d)
                print("[+] Scan complete.")
            elif cmd == "nodes":
                if not current_domain:
                    print("[-] No active domain.")
                    continue
                store = PropertyGraphStore(db, session_id=current_domain)
                nodes = list(store.graph.nodes(data=True))
                print(f"[*] Total Nodes in Session: {len(nodes)}")
                for n_id, data in nodes[:20]:
                    print(f"    - [{data.get('node_type')}] {data.get('label')}")
            elif cmd == "l2":
                if not current_domain:
                    print("[-] No active domain.")
                    continue
                store = PropertyGraphStore(db, session_id=current_domain)
                l2_nodes = [
                    (n, d) for n, d in store.graph.nodes(data=True)
                    if d.get("node_type") == NodeType.DOMAIN_L2.value
                ]
                print(f"[*] L2 Domains Found: {len(l2_nodes)}")
                for idx, (n_id, data) in enumerate(l2_nodes, 1):
                    d_name = data.get("label")
                    score, conf = store.score_l2_domain(current_domain, d_name)
                    print(f"    {idx}. {d_name} (Confidence: {conf}, Score: {score:.2f})")
            elif cmd == "expand":
                if len(parts) < 2:
                    print("Usage: expand <l2_domain>")
                    continue
                target_l2 = parts[1].strip()
                print(f"[*] Deep probing L2 domain: {target_l2}...")
                orchestrator.run_investigation(target_l2, depth=1)
                print(f"[+] L2 domain {target_l2} expanded.")
            else:
                print(f"[-] Unknown command: '{cmd}'. Type 'help' for command list.")
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Exiting REPL.")
            break
        except Exception as e:
            print(f"[-] Error: {e}")

    return 0
