# =============================================================================
# CodeGuard - instalador v1
# Instala el agente completo para el usuario actual (sin admin - hardening 13):
#   binarios -> %LOCALAPPDATA%\CodeGuard\bin
#   motores  -> %LOCALAPPDATA%\CodeGuard\engines  (hashes registrados)
#   PATH de usuario, arranque del daemon con la sesion, plantilla org
# Uso:  powershell -ExecutionPolicy Bypass -File install.ps1 [-ApiKey "..."]
# =============================================================================
param(
    [string]$ApiKey = "",
    [switch]$SkipTrivy   # trivy pesa ~60 MB; opcional en la primera ola
)
$ErrorActionPreference = "Stop"

$Root    = Join-Path $env:LOCALAPPDATA "CodeGuard"
$Bin     = Join-Path $Root "bin"
$Engines = Join-Path $Root "engines"
$Src     = $PSScriptRoot

# versiones pinneadas de los motores descargables
$GitleaksVer = "8.30.0"
$TrivyVer    = "0.71.0"

function Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Ok($msg)   { Write-Host "    $msg" -ForegroundColor Green }

# ── 1. binarios y assets ─────────────────────────────────────────────────────
Step "Instalando binarios en $Bin"
New-Item -ItemType Directory -Force $Bin, $Engines | Out-Null
foreach ($f in @("codeguard.exe", "codeguard-daemon.exe", "org-llm.yaml")) {
    Copy-Item (Join-Path $Src $f) $Bin -Force
}
if (Test-Path (Join-Path $Src "rulepacks")) {
    Copy-Item (Join-Path $Src "rulepacks") $Root -Recurse -Force
    # el binario busca rulepacks junto a si mismo:
    Copy-Item (Join-Path $Src "rulepacks") $Bin -Recurse -Force
}
Ok "binarios y rulepack copiados"

# ── 2. motores descargables (gitleaks, trivy) con hash registrado ────────────
$hashes = @{}
$hashFile = Join-Path $Engines "hashes.json"
if (Test-Path $hashFile) {
    (Get-Content $hashFile -Raw | ConvertFrom-Json).psobject.Properties |
        ForEach-Object { $hashes[$_.Name] = $_.Value }
}

function Install-FromZip($name, $url, $exeInZip) {
    $exe = Join-Path $Engines "$name.exe"
    if (Test-Path $exe) { Ok "$name ya presente"; return }
    Step "Descargando $name"
    $tmp = Join-Path $env:TEMP "cg-$name.zip"
    Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing
    $dir = Join-Path $env:TEMP "cg-$name"
    Expand-Archive $tmp $dir -Force
    $found = Get-ChildItem $dir -Recurse -Filter $exeInZip | Select-Object -First 1
    if (-not $found) { throw "$exeInZip no venia en el zip de $name" }
    Copy-Item $found.FullName $exe -Force
    Remove-Item $tmp, $dir -Recurse -Force -Confirm:$false
    # hardening 11: hash registrado en la primera instalacion; codeguard repair
    # lo verificara en cada arranque. Pinnear en este script cuando se bendiga.
    $h = (Get-FileHash $exe -Algorithm SHA256).Hash
    $script:hashes[$name] = $h
    Ok "$name $((Get-Item $exe).Length / 1MB -as [int]) MB - sha256 $($h.Substring(0,16))..."
}

Install-FromZip "gitleaks" "https://github.com/gitleaks/gitleaks/releases/download/v$GitleaksVer/gitleaks_${GitleaksVer}_windows_x64.zip" "gitleaks.exe"
if (-not $SkipTrivy) {
    Install-FromZip "trivy" "https://github.com/aquasecurity/trivy/releases/download/v$TrivyVer/trivy_${TrivyVer}_windows-64bit.zip" "trivy.exe"
}
$hashes | ConvertTo-Json | Set-Content $hashFile

# ── 3. motores Python (semgrep, squawk, ruff) ────────────────────────────────
Step "Motores Python (semgrep, squawk, ruff)"
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) {
    Step "Python no encontrado - instalando via winget"
    winget install -e --id Python.Python.3.13 --silent --accept-package-agreements --accept-source-agreements
    $env:PATH = [Environment]::GetEnvironmentVariable("PATH", "User") + ";" + [Environment]::GetEnvironmentVariable("PATH", "Machine")
}
python -m pip install --user --quiet --upgrade semgrep squawk-cli ruff
$pyScripts = python -c "import sysconfig; print(sysconfig.get_path('scripts', 'nt_user'))"
Ok "instalados en $pyScripts"

# ── 4. PATH de usuario ───────────────────────────────────────────────────────
Step "Registrando PATH de usuario"
$userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
foreach ($p in @($Bin, $Engines, $pyScripts)) {
    if ($userPath -notlike "*$p*") { $userPath = "$p;$userPath" }
}
[Environment]::SetEnvironmentVariable("PATH", $userPath, "User")
Ok "PATH actualizado (abre una terminal nueva para heredarlo)"

# ── 5. API key del modelo (variable de usuario) ──────────────────────────────
if ($ApiKey) {
    [Environment]::SetEnvironmentVariable("FOUNDRY_API_KEY", $ApiKey, "User")
    Ok "FOUNDRY_API_KEY registrada para tu usuario"
} else {
    Write-Host "    (sin -ApiKey: la capa LLM quedara apagada hasta definir FOUNDRY_API_KEY)" -ForegroundColor Yellow
}

# ── 6. daemon con la sesion de Windows ───────────────────────────────────────
Step "Arranque automatico del daemon"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
    -Name "CodeGuard" -Value "`"$Bin\codeguard-daemon.exe`""
Get-Process codeguard-daemon -ErrorAction SilentlyContinue | Stop-Process -Force -Confirm:$false
$env:PATH = "$Bin;$Engines;$pyScripts;$env:PATH"
Start-Process "$Bin\codeguard-daemon.exe"
Ok "daemon corriendo (el orbe vive abajo a la derecha)"

# ── 7. verificacion final ────────────────────────────────────────────────────
Step "Verificacion (codeguard repair)"
& "$Bin\codeguard.exe" repair
Write-Host ""
Write-Host "LISTO. Siguiente paso por repo: cd al proyecto y 'codeguard init'" -ForegroundColor Green
