# =============================================================================
# CodeGuard - instalacion de motores (compartido por install.ps1 y el setup)
# Descarga gitleaks/trivy verificando cada zip y cada .exe contra el SHA-256
# publicado por sus autores, e instala los motores Python (semgrep, squawk,
# ruff). La fuente de verdad de versiones y hashes es motores.json - la misma
# que embebe el agente (internal/engines/identidad/motores.json); build-dist
# la copia aqui para que nunca diverjan.
# Uso:  powershell -ExecutionPolicy Bypass -File engines.ps1 [-SkipTrivy]
# =============================================================================
param(
    [string]$EnginesDir = (Join-Path $env:LOCALAPPDATA "CodeGuard\engines"),
    [string]$MotoresJson = (Join-Path $PSScriptRoot "motores.json"),
    [switch]$SkipTrivy   # trivy pesa ~60 MB; opcional en la primera ola
)
$ErrorActionPreference = "Stop"

function Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Ok($msg)   { Write-Host "    $msg" -ForegroundColor Green }

New-Item -ItemType Directory -Force $EnginesDir | Out-Null
$catalogo = (Get-Content $MotoresJson -Raw | ConvertFrom-Json).motores

# ── motores descargables (gitleaks, trivy) con hash FIJADO ───────────────────
# Se verifica el zip ANTES de extraerlo y se aborta si no coincide: un binario
# alterado en transito o en el espejo no llega a instalarse.
function Install-Motor($name) {
    $v = $catalogo.$name.versiones | Select-Object -Last 1
    $exe = Join-Path $EnginesDir "$name.exe"
    if (Test-Path $exe) {
        # Presente no basta: tiene que ser el binario publicado. Si coincide,
        # una actualizacion no vuelve a descargar nada.
        $h = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()
        if ($h -eq $v.sha256_exe) { Ok "$name $($v.version) ya presente y verificado"; return }
        Write-Host "    $name presente pero NO coincide con el binario publicado" -ForegroundColor Yellow
        Write-Host "    se reemplazara por la version verificada" -ForegroundColor Yellow
        # OJO: no se borra todavia — el reemplazo se instala solo cuando la
        # descarga nueva ya esta verificada. Un fallo a medias no deja hueco.
    }
    Step "Descargando $name $($v.version)"
    $tmp = Join-Path $env:TEMP "cg-$name.zip"
    $intento = 0
    while ($true) {
        try { Invoke-WebRequest -Uri $v.url -OutFile $tmp -UseBasicParsing; break }
        catch {
            $intento++
            if ($intento -ge 3) { throw }
            Write-Host "    la descarga fallo ($($_.Exception.Message)); reintento $intento de 2..." -ForegroundColor Yellow
            Start-Sleep 4
        }
    }

    $zh = (Get-FileHash $tmp -Algorithm SHA256).Hash.ToLower()
    if ($zh -ne $v.sha256_zip) {
        Remove-Item -LiteralPath $tmp -Force
        throw @"
$name no coincide con el checksum publicado por sus autores.
  descargado: $zh
  esperado:   $($v.sha256_zip)
La descarga se descarto sin abrir. Puede ser una version distinta a la que
fijamos, un espejo alterado o una red que modifica el trafico. No se instala
nada hasta aclararlo.
"@
    }
    Ok "${name}: checksum del publicador verificado"

    $dir = Join-Path $env:TEMP "cg-$name"
    Expand-Archive $tmp $dir -Force
    $found = Get-ChildItem $dir -Recurse -Filter "$name.exe" | Select-Object -First 1
    if (-not $found) { throw "$name.exe no venia en el zip" }

    # Verificar el extraido ANTES de tocar el destino: el motor viejo (si lo
    # habia) sigue sano hasta que el nuevo este probado.
    $h = (Get-FileHash $found.FullName -Algorithm SHA256).Hash.ToLower()
    if ($h -ne $v.sha256_exe) {
        Remove-Item $tmp, $dir -Recurse -Force -Confirm:$false
        throw "${name}: el zip era correcto pero el .exe extraido no coincide ($h)"
    }
    Copy-Item $found.FullName $exe -Force
    Remove-Item $tmp, $dir -Recurse -Force -Confirm:$false
    Ok "$name $((Get-Item $exe).Length / 1MB -as [int]) MB - verificado"
}

Install-Motor "gitleaks"
if (-not $SkipTrivy) { Install-Motor "trivy" }

# ── motores Python (semgrep, squawk, ruff) ───────────────────────────────────
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

# Los scripts de Python van al PATH aqui mismo: es el unico paso que conoce
# la ruta (depende de la version de Python del usuario).
$userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($userPath -notlike "*$pyScripts*") {
    [Environment]::SetEnvironmentVariable("PATH", "$pyScripts;$userPath", "User")
    Ok "PATH de usuario: + $pyScripts"
}
