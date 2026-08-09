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

# ── 2-3. motores (gitleaks, trivy, semgrep, squawk, ruff) ────────────────────
# La descarga con hash fijado y los motores Python viven en engines.ps1,
# compartido con el setup de Inno. Los hashes salen de motores.json (copiada
# por build-dist desde internal/engines/identidad/motores.json).
& (Join-Path $Src "engines.ps1") -EnginesDir $Engines -SkipTrivy:$SkipTrivy

# ── 4. PATH de usuario ───────────────────────────────────────────────────────
Step "Registrando PATH de usuario"
$userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
foreach ($p in @($Bin, $Engines)) {
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
$env:PATH = [Environment]::GetEnvironmentVariable("PATH", "User") + ";" + $env:PATH
Start-Process "$Bin\codeguard-daemon.exe"
Ok "daemon corriendo (el orbe vive abajo a la derecha)"

# ── 7. verificacion final ────────────────────────────────────────────────────
Step "Verificacion (codeguard repair)"
& "$Bin\codeguard.exe" repair
Write-Host ""
Write-Host "LISTO. Siguiente paso por repo: cd al proyecto y 'codeguard init'" -ForegroundColor Green
