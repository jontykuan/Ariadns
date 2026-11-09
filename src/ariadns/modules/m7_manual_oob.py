"""Module 7: Isolated Manual-Only OOB Callback Verifier.

Mandatory Invariant: Never called during automatic runs.
Requires explicit OPSEC risk confirmation before sending any external requests.
"""

from typing import Any
import httpx
from ariadns.models.enums import ModuleStatus

OPSEC_WARNING_TEXT = (
    "[OPSEC WARNING] Active Out-Of-Band (OOB) probing sends a real HTTP request to the target server, "
    "which triggers the target's backend to reach out to your callback destination. "
    "This leaves access logs on the target server containing your callback URL and timestamp. "
    "You MUST pass acknowledge_opsec_risk=True to confirm authorization and proceed."
)

def trigger_manual_oob(
    target_endpoint_url: str,
    callback_url: str,
    param_name: str = "url",
    http_method: str = "GET",
    acknowledge_opsec_risk: bool = False,
    timeout_seconds: float = 5.0,
) -> dict[str, Any]:
    """Manually test if a target web application's preview/webhook endpoint initiates a backend callback."""
    if not acknowledge_opsec_risk:
        return {
            "status": ModuleStatus.SKIPPED_BLACKLIST.value,
            "warning": OPSEC_WARNING_TEXT,
            "callback_sent": False,
            "target_endpoint": target_endpoint_url,
            "error": "OPSEC risk not acknowledged. Request aborted.",
        }

    target_method = http_method.upper().strip()
    headers = {"User-Agent": "Ariadns-Manual-Prober/1.0"}

    try:
        with httpx.Client(timeout=timeout_seconds, verify=False, follow_redirects=True) as client:
            if target_method == "POST":
                resp = client.post(target_endpoint_url, data={param_name: callback_url}, headers=headers)
            else:
                resp = client.get(target_endpoint_url, params={param_name: callback_url}, headers=headers)

            return {
                "status": ModuleStatus.OK.value,
                "callback_sent": True,
                "target_endpoint": target_endpoint_url,
                "callback_url": callback_url,
                "target_status_code": resp.status_code,
                "note": "Trigger request delivered. Check your external canary/listener for incoming backend callbacks.",
            }
    except Exception as e:
        return {
            "status": ModuleStatus.TIMEOUT_UNVERIFIED.value,
            "callback_sent": False,
            "target_endpoint": target_endpoint_url,
            "error": str(e),
        }
