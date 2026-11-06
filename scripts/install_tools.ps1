# Ariadns external tools installer (Windows PowerShell)
Write-Host "[*] Checking Ariadns external OSINT tools..." -ForegroundColor Cyan

if (Get-Command winget -ErrorAction SilentlyContinue) {
    Write-Host "[+] Installing nmap via winget..." -ForegroundColor Green
    winget install -e --id Insecure.Nmap --accept-source-agreements --accept-package-agreements
}

if (Get-Command scoop -ErrorAction SilentlyContinue) {
    Write-Host "[+] Installing subfinder and httpx via Scoop..." -ForegroundColor Green
    scoop install subfinder httpx
} elseif (Get-Command go -ErrorAction SilentlyContinue) {
    Write-Host "[+] Installing subfinder and httpx via Go..." -ForegroundColor Green
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
} else {
    Write-Host "[!] Scoop or Go not detected. You can download precompiled binaries from:" -ForegroundColor Yellow
    Write-Host "    https://github.com/projectdiscovery/subfinder/releases"
    Write-Host "    https://github.com/projectdiscovery/httpx/releases"
}

Write-Host "[+] Done. Run 'ariadns doctor' to verify." -ForegroundColor Cyan
