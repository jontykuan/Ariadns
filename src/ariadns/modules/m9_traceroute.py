"""Module 9: Active Route Hop Tracer (tracert / traceroute) with Open-Source ASN & PTR Enrichment."""

import ipaddress
import platform
import re
import subprocess
from typing import Any
import dns.resolver
import dns.reversename
from ariadns.models.enums import ModuleStatus
from ariadns.utils.asn_cdn import resolve_ip_asn_details

TRACE_OPSEC_WARNING = (
    "[OPSEC WARNING] Active route tracing (tracert/traceroute) sends live ICMP/UDP packets toward the target "
    "and intermediate routers. You MUST acknowledge OPSEC risk (ack_opsec=True) to proceed."
)

IP_EXTRACT_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def resolve_ptr(ip: str) -> str:
    """Resolve reverse DNS PTR record for an IP address with a short timeout."""
    try:
        rev_name = dns.reversename.from_address(ip)
        resolver = dns.resolver.Resolver()
        resolver.timeout = 1.5
        resolver.lifetime = 1.5
        ans = resolver.resolve(rev_name, "PTR")
        for rdata in ans:
            return str(rdata.target).rstrip(".")
    except Exception:
        pass
    return ""

def build_tracert_command(
    target: str,
    no_rdns: bool = True,
    max_hops: int = 20,
    timeout_ms: int = 500,
) -> list[str]:
    """Construct OS-appropriate traceroute command with explicit flags (-d -h 20 -w 500 on Windows)."""
    is_win = platform.system().lower().startswith("win")
    if is_win:
        cmd = ["tracert"]
        if no_rdns:
            cmd.append("-d")
        cmd.extend(["-h", str(int(max_hops)), "-w", str(int(timeout_ms)), target])
        return cmd
    else:
        cmd = ["traceroute"]
        if no_rdns:
            cmd.append("-n")
        wait_sec = max(1, int(round(timeout_ms / 1000.0)))
        cmd.extend(["-m", str(int(max_hops)), "-w", str(wait_sec), target])
        return cmd

def parse_tracert_output(raw_output: str, target: str) -> list[dict[str, Any]]:
    """Parse raw tracert/traceroute output into ordered responsive hop records."""
    hops: list[dict[str, Any]] = []
    for line in raw_output.splitlines():
        line_str = line.strip()
        if not line_str:
            continue
        m_hop = re.match(r"^(\d+)\s+(.*)$", line_str)
        if not m_hop:
            continue
        hop_num = int(m_hop.group(1))
        rest = m_hop.group(2)
        ips = IP_EXTRACT_RE.findall(rest)
        if not ips:
            continue
        hop_ip = ips[-1]
        try:
            ip_obj = ipaddress.ip_address(hop_ip)
            if ip_obj.is_private or ip_obj.is_loopback:
                continue
        except ValueError:
            continue
        hops.append({"hop": hop_num, "ip": hop_ip})
    return hops

def run_active_trace(
    target: str,
    no_rdns: bool = True,
    max_hops: int = 20,
    timeout_ms: int = 500,
    tail_hops: int = 3,
    ack_opsec: bool = False,
) -> dict[str, Any]:
    """Execute active route trace and enrich the last N responsive hops with ASN & PTR data."""
    if not ack_opsec:
        return {
            "status": ModuleStatus.SKIPPED_BLACKLIST.value,
            "warning": TRACE_OPSEC_WARNING,
            "executed": False,
            "target": target,
            "error": "OPSEC authorization required (ack_opsec=True).",
        }

    cmd = build_tracert_command(target, no_rdns=no_rdns, max_hops=max_hops, timeout_ms=timeout_ms)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=max(10, int(max_hops * (timeout_ms / 1000.0) * 3) + 5)
        )
        raw_out = proc.stdout or ""
    except Exception as exc:
        return {
            "status": ModuleStatus.TIMEOUT_UNVERIFIED.value,
            "executed": False,
            "target": target,
            "command": " ".join(cmd),
            "error": str(exc),
        }

    all_hops = parse_tracert_output(raw_out, target)
    retained = all_hops[-max(1, int(tail_hops)):] if all_hops else []

    enriched_hops: list[dict[str, Any]] = []
    for h in retained:
        hop_ip = h["ip"]
        asn_info = resolve_ip_asn_details(hop_ip)
        ptr = resolve_ptr(hop_ip)
        enriched_hops.append({
            "hop": h["hop"],
            "ip": hop_ip,
            "ptr": ptr,
            "asn": asn_info.get("asn", ""),
            "asn_org_name": asn_info.get("asn_org_name", ""),
            "country": asn_info.get("country", ""),
        })

    return {
        "status": ModuleStatus.OK.value,
        "executed": True,
        "target": target,
        "command": " ".join(cmd),
        "total_responsive_hops": len(all_hops),
        "tail_hops": enriched_hops,
    }
