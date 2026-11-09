from ariadns.models.enums import ModuleStatus
from ariadns.modules.m7_manual_oob import trigger_manual_oob

def test_manual_oob_risk_gate():
    # Without acknowledgment -> must abort with warning
    res = trigger_manual_oob(
        target_endpoint_url="https://target.local/api/preview",
        callback_url="https://canary.local/token123",
        acknowledge_opsec_risk=False
    )
    assert res["callback_sent"] is False
    assert "OPSEC WARNING" in res["warning"]
    assert res["status"] == ModuleStatus.SKIPPED_BLACKLIST.value

def test_manual_oob_timeout_handling():
    # With acknowledgment -> attempts connection and handles timeout safely within 0.1s
    res = trigger_manual_oob(
        target_endpoint_url="http://192.0.2.1/webhook",
        callback_url="http://canary.local/token123",
        acknowledge_opsec_risk=True,
        timeout_seconds=0.1
    )
    assert res["status"] == ModuleStatus.TIMEOUT_UNVERIFIED.value
    assert res["callback_sent"] is False
