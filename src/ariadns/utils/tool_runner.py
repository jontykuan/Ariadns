import shutil
import subprocess
from typing import Any
from ariadns.models.enums import ModuleStatus

KNOWN_EXTERNAL_BINARIES = ["subfinder", "httpx", "nmap"]

def check_binary_available(binary_name: str) -> bool:
    return shutil.which(binary_name) is not None

def check_environment() -> dict[str, Any]:
    status = {}
    for b in KNOWN_EXTERNAL_BINARIES:
        found = check_binary_available(b)
        status[b] = {
            "installed": found,
            "path": shutil.which(b) if found else None,
            "status": ModuleStatus.OK.value if found else ModuleStatus.FALLBACK_NATIVE.value,
        }
    return status

def run_command_safely(cmd: list[str], timeout_seconds: float = 5.0) -> tuple[int, str, str]:
    binary = cmd[0]
    if not check_binary_available(binary):
        return -1, "", f"Binary '{binary}' not found in PATH"
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -2, "", f"Command '{' '.join(cmd)}' timed out after {timeout_seconds}s"
    except Exception as e:
        return -3, "", str(e)
