#!/usr/bin/env bash
# Ariadns external tools installer (Linux / macOS / WSL)
set -e

echo "[*] Installing Ariadns recommended OSINT tools..."

if command -v go &> /dev/null; then
    echo "[+] Installing subfinder and httpx via Go..."
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
else
    echo "[!] Go not found. Please install Go or download binaries directly from GitHub releases:"
    echo "    - https://github.com/projectdiscovery/subfinder/releases"
    echo "    - https://github.com/projectdiscovery/httpx/releases"
fi

if command -v apt-get &> /dev/null; then
    echo "[+] Installing nmap via apt..."
    sudo apt-get update && sudo apt-get install -y nmap
elif command -v brew &> /dev/null; then
    echo "[+] Installing nmap via brew..."
    brew install nmap
fi

echo "[+] Done. Run 'ariadns doctor' to verify."
