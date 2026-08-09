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

# ── 2. motores descargables (gitleaks, trivy) con hash FIJADO ────────────────
# Los hashes salen de los checksums.txt que publican los propios proyectos en
# sus releases, no de la primera descarga que le toco a esta maquina. Un
# binario alterado en transito o en el espejo no llega a instalarse: se
# verifica el zip ANTES de extraerlo y se aborta.
#
# Fuente de verdad compartida con el agente:
#   internal/engines/identidad/motores.json
# Al subir de version hay que actualizar los dos.
$PinZip = @{
    "gitleaks" = "54fe94f644b832dd08e8c3a5915efb3bfa862386d59fb27ca0792cb687a83573"
    "trivy"    = "382250158fb9431ff9b87904205027b066a544234b8952b2dd764bd712d55387"
}
$PinExe = @{
    "gitleaks" = "9d08e3f5cfb35a98f230b97bcda24f8d3fc66363c91868ffc98dac0afebdcb72"
    "trivy"    = "e4a8c8414258c22cd532b73470d544087208bace64bc2ad9c44afa4a94bb33d1"
}

function Install-FromZip($name, $url, $exeInZip) {
    $exe = Join-Path $Engines "$name.exe"
    if (Test-Path $exe) {
        # Presente no basta: tiene que ser el binario publicado.
        $h = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()
        if ($h -eq $PinExe[$name]) { Ok "$name ya presente y verificado"; return }
        Write-Host "    $name presente pero NO coincide con el binario publicado" -ForegroundColor Yellow
        Write-Host "    se reemplaza por la version verificada" -ForegroundColor Yellow
        Remove-Item -LiteralPath $exe -Force
    }
    Step "Descargando $name"
    $tmp = Join-Path $env:TEMP "cg-$name.zip"
    Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing

    # Verificar ANTES de extraer: un zip manipulado no se descomprime siquiera.
    $zh = (Get-FileHash $tmp -Algorithm SHA256).Hash.ToLower()
    if ($zh -ne $PinZip[$name]) {
        Remove-Item -LiteralPath $tmp -Force
        throw @"
$name no coincide con el checksum publicado por sus autores.
  descargado: $zh
  esperado:   $($PinZip[$name])
La descarga se descarto sin abrir. Puede ser una version distinta a la que
fijamos, un espejo alterado o una red que modifica el trafico. No se instala
nada hasta aclararlo.
"@
    }
    Ok "${name}: checksum del publicador verificado"

    $dir = Join-Path $env:TEMP "cg-$name"
    Expand-Archive $tmp $dir -Force
    $found = Get-ChildItem $dir -Recurse -Filter $exeInZip | Select-Object -First 1
    if (-not $found) { throw "$exeInZip no venia en el zip de $name" }
    Copy-Item $found.FullName $exe -Force
    Remove-Item $tmp, $dir -Recurse -Force -Confirm:$false

    $h = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()
    if ($h -ne $PinExe[$name]) {
        Remove-Item -LiteralPath $exe -Force
        throw "${name}: el zip era correcto pero el .exe extraido no coincide ($h)"
    }
    Ok "$name $((Get-Item $exe).Length / 1MB -as [int]) MB - verificado"
}

Install-FromZip "gitleaks" "https://github.com/gitleaks/gitleaks/releases/download/v$GitleaksVer/gitleaks_${GitleaksVer}_windows_x64.zip" "gitleaks.exe"
if (-not $SkipTrivy) {
    Install-FromZip "trivy" "https://github.com/aquasecurity/trivy/releases/download/v$TrivyVer/trivy_${TrivyVer}_windows-64bit.zip" "trivy.exe"
}

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
