from ariadns.models.enums import ModuleStatus
from ariadns.utils.asn_cdn import detect_cdn
from ariadns.utils.tool_runner import check_environment, run_command_safely

def test_detect_cdn_cidr():
    # Cloudflare IP in known CIDR
    is_cdn, provider, asn = detect_cdn("104.21.23.45")
    assert is_cdn is True
    assert provider == "Cloudflare"
    assert asn == "AS13335"

    # Non-CDN IP
    is_cdn_local, provider_local, asn_local = detect_cdn("127.0.0.1")
    assert is_cdn_local is False
    assert provider_local is None

def test_tool_runner_environment_check():
    env = check_environment()
    assert "subfinder" in env
    assert "httpx" in env
    assert "nmap" in env
    for k, v in env.items():
        assert v["status"] in (ModuleStatus.OK.value, ModuleStatus.FALLBACK_NATIVE.value)

def test_run_command_safely_missing():
    code, stdout, stderr = run_command_safely(["non_existent_binary_xyz_123"])
    assert code == -1
    assert "not found" in stderr
