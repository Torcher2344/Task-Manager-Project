Param(
    [string]$ProjectRoot = (Get-Location).Path
)

Write-Host "[setup] Initializing Bug Bounty Swarm on Windows"
Set-Location $ProjectRoot

if (!(Test-Path ".venv")) {
    python -m venv .venv
}

.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

if (!(Test-Path "config\.env")) {
    Copy-Item "config\.env.example" "config\.env"
    Write-Host "[setup] Created config\.env from template"
}

$dirs = @("loot", "loot\sessions", "reports", "tools", "knowledge", "recon")
foreach ($dir in $dirs) {
    if (!(Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
    }
}

Write-Host "[setup] Done. Activate with .\.venv\Scripts\Activate.ps1"
