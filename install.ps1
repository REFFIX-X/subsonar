<#
.SYNOPSIS
    Bootstrap subsonar on Windows and launch the web dashboard.

.DESCRIPTION
    Finds Python 3.11+, creates a local .venv (if missing), installs
    requirements.txt, then starts `python main.py web` and opens the Streamlit
    dashboard in your browser at http://localhost:8501.

    Run it from anywhere; it always resolves the repo root from its own path.

.PARAMETER Port
    Port for the dashboard (default 8501).

.PARAMETER Reinstall
    Recreate .venv from scratch instead of reusing an existing one.

.PARAMETER NoBrowser
    Do not auto-open the browser (passes --headless to the dashboard).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\install.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\install.ps1 -Port 8502 -NoBrowser

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\install.ps1 -Reinstall
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 65535)]
    [int]$Port = 8501,

    [switch]$Reinstall,

    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

function Write-Step([string]$Message) {
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Find-Python {
    # Returns the first Python 3.11+ command as an argument array, or $null.
    $bases = New-Object System.Collections.Generic.List[object]
    if (Get-Command py -ErrorAction SilentlyContinue) {
        foreach ($tag in @("-3.12", "-3.11", "-3")) { $bases.Add(@("py", $tag)) }
    }
    foreach ($name in @("python", "python3")) {
        if (Get-Command $name -ErrorAction SilentlyContinue) { $bases.Add(@($name)) }
    }
    foreach ($base in $bases) {
        try {
            $probe = & $base -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>&1
        } catch { continue }
        if ($LASTEXITCODE -eq 0 -and $probe -match "^3\.(\d+)\s*$") {
            if ([int]$Matches[1] -ge 11) { return $base }
        }
    }
    return $null
}

Write-Step "Looking for Python 3.11+ ..."
$python = Find-Python
if (-not $python) {
    Write-Host ""
    Write-Host "Python 3.11+ was not found." -ForegroundColor Red
    Write-Host "Install it from https://www.python.org/downloads/ and tick" -ForegroundColor Red
    Write-Host "'Add python.exe to PATH' during setup, then re-run this script." -ForegroundColor Red
    exit 1
}
Write-Host "Using: $($python -join ' ')"

$venvDir = Join-Path $PSScriptRoot ".venv"
$venvPy = Join-Path $venvDir "Scripts\python.exe"

if ((Test-Path -LiteralPath $venvPy) -and -not $Reinstall) {
    Write-Step "Reusing existing .venv ..."
} else {
    if ($Reinstall -and (Test-Path -LiteralPath $venvDir)) {
        Write-Step "Recreating .venv ..."
        Remove-Item -LiteralPath $venvDir -Recurse -Force
    }
    Write-Step "Creating virtual environment (.venv) ..."
    & $python -m venv $venvDir
    if ($LASTEXITCODE -ne 0) { throw "venv creation failed" }

    # Prefer IPv4 for this venv's sockets: some Windows/VPN networks resolve
    # PyPI to IPv6 (AAAA) addresses with no working IPv6 route, which makes pip
    # hang.  A sitecustomize shim reorders getaddrinfo so IPv4 wins first.
    Write-Step "Pinning IPv4 preference (works around broken IPv6 networks) ..."
    $sitePackages = Join-Path $venvDir "Lib\site-packages"
    if (-not (Test-Path -LiteralPath $sitePackages)) {
        New-Item -ItemType Directory -Force $sitePackages | Out-Null
    }
    @'
import socket
_orig = socket.getaddrinfo
def _prefer_ipv4(*args, **kwargs):
    return sorted(_orig(*args, **kwargs), key=lambda r: (r[0] != socket.AF_INET, r))
socket.getaddrinfo = _prefer_ipv4
'@ | Set-Content -Path (Join-Path $sitePackages "sitecustomize.py") -Encoding UTF8

    Write-Step "Installing dependencies (this can take a few minutes) ..."
    & $venvPy -m pip install --upgrade pip
    if ($LASTEXITCODE -ne 0) { throw "pip upgrade failed" }
    & $venvPy -m pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) { throw "pip install -r requirements.txt failed" }
}

Write-Host ""
Write-Host "Launching the web dashboard at http://localhost:$Port" -ForegroundColor Green
Write-Host "If the browser does not open, visit:  http://localhost:$Port" -ForegroundColor Green
Write-Host "(press Ctrl+C here to stop the server)" -ForegroundColor DarkGray

$webArgs = @("main.py", "web", "--port", "$Port")
if ($NoBrowser) { $webArgs += "--headless" }

& $venvPy @webArgs
exit $LASTEXITCODE
