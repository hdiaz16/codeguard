# =============================================================================
# CodeGuard - instalador v1
# Instala el agente completo para el usuario actual (sin admin - hardening 13):
#   binarios -> %LOCALAPPDATA%\CodeGuard\bin
#   motores  -> %LOCALAPPDATA%\CodeGuard\engines  (hashes registrados)
#   PATH de usuario, arranque del daemon con la sesion, plantilla org
# Uso:  powershell -ExecutionPolicy Bypass -File install.ps1 [-SkipTrivy]
# =============================================================================
param(
    [switch]$SkipTrivy   # trivy pesa ~60 MB; opcional en la primera ola
)
$ErrorActionPreference = "Stop"

$Root    = Join-Path $env:LOCALAPPDATA "CodeGuard"
$Bin     = Join-Path $Root "bin"
$Engines = Join-Path $Root "engines"
$Src     = $PSScriptRoot

function Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Ok($msg)   { Write-Host "    $msg" -ForegroundColor Green }

$DaemonSeDetuvo = $false
trap {
    $fallo = $_
    # Una actualización que falle después de detener el agente no deja al
    # usuario sin vigilancia: se arranca la versión que haya quedado restaurada
    # o instalada antes de devolver el error al sistema de despliegue.
    if ($DaemonSeDetuvo -and (Test-Path (Join-Path $Bin "codeguard-daemon.exe")) -and
        -not (Get-Process codeguard-daemon -ErrorAction SilentlyContinue)) {
        Start-Process (Join-Path $Bin "codeguard-daemon.exe") -WorkingDirectory $Bin
    }
    Write-Error $fallo
    exit 1
}

function Wait-CodeGuardDaemonExit([int]$TimeoutMs) {
    $limite = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    do {
        if (-not (Get-Process codeguard-daemon -ErrorAction SilentlyContinue)) { return $true }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $limite)
    return $false
}

function Stop-CodeGuardDaemon {
    $vivos = Get-Process codeguard-daemon -ErrorAction SilentlyContinue
    if (-not $vivos) { return }

    Step "Deteniendo la versión anterior del daemon"
    $cliAnterior = Join-Path $Bin "codeguard.exe"
    if (Test-Path $cliAnterior) {
        & $cliAnterior daemon-stop *> $null
        if (Wait-CodeGuardDaemonExit 5000) {
            $script:DaemonSeDetuvo = $true
            Ok "daemon anterior detenido por IPC"
            return
        }
    }

    # Compatibilidad con daemons anteriores al comando daemon-stop o colgados.
    Get-Process codeguard-daemon -ErrorAction SilentlyContinue |
        Stop-Process -Force -Confirm:$false -ErrorAction SilentlyContinue
    if (-not (Wait-CodeGuardDaemonExit 5000)) {
        throw "no se pudo detener el daemon anterior; no se reemplazó ningún archivo"
    }
    Start-Sleep -Milliseconds 300 # deja que Windows libere el mapeo del .exe
    $script:DaemonSeDetuvo = $true
    Ok "daemon anterior detenido"
}

# ── 1. binarios y assets: transacción de actualización ───────────────────────
Step "Preparando actualización transaccional"
New-Item -ItemType Directory -Force $Root | Out-Null
$Tx = Join-Path $Root (".install-" + [Guid]::NewGuid().ToString("N"))
$Stage = Join-Path $Tx "stage"
$Backup = Join-Path $Tx "backup"
New-Item -ItemType Directory -Force $Stage, $Backup | Out-Null

$payload = @("codeguard.exe", "codeguard-daemon.exe", "org-llm.yaml")
foreach ($f in $payload) {
    $origen = Join-Path $Src $f
    if (-not (Test-Path $origen -PathType Leaf)) { throw "el paquete está incompleto: falta $f" }
    Copy-Item -LiteralPath $origen -Destination (Join-Path $Stage $f)
}
if (Test-Path (Join-Path $Src "rulepacks")) {
    Copy-Item -LiteralPath (Join-Path $Src "rulepacks") -Destination $Stage -Recurse
}

# Nada bajo bin se toca hasta que TODO el payload está legible y el daemon
# anterior ha soltado el ejecutable.
Stop-CodeGuardDaemon
New-Item -ItemType Directory -Force $Bin, $Engines | Out-Null
$cambios = [System.Collections.Generic.List[object]]::new()
try {
    foreach ($f in $payload) {
        $destino = Join-Path $Bin $f
        $respaldo = Join-Path $Backup ("bin-" + $f)
        $cambio = [pscustomobject]@{ Target = $destino; Backup = $respaldo }
        $cambios.Add($cambio)
        if (Test-Path $destino) { Move-Item -LiteralPath $destino -Destination $respaldo }
        Move-Item -LiteralPath (Join-Path $Stage $f) -Destination $destino
    }

    if (Test-Path (Join-Path $Stage "rulepacks")) {
        $n = 0
        foreach ($ver in Get-ChildItem (Join-Path $Stage "rulepacks") -Directory) {
            foreach ($base in @($Root, $Bin)) {
                $n++
                $carpeta = Join-Path $base "rulepacks"
                New-Item -ItemType Directory -Force $carpeta | Out-Null
                $destino = Join-Path $carpeta $ver.Name
                $entrante = Join-Path $Tx ("incoming-rulepack-" + $n)
                $respaldo = Join-Path $Backup ("rulepack-" + $n)
                Copy-Item -LiteralPath $ver.FullName -Destination $entrante -Recurse
                $cambio = [pscustomobject]@{ Target = $destino; Backup = $respaldo }
                $cambios.Add($cambio)
                if (Test-Path $destino) { Move-Item -LiteralPath $destino -Destination $respaldo }
                Move-Item -LiteralPath $entrante -Destination $destino
            }
        }
    }
} catch {
    # Rollback en orden inverso: nunca se deja una mezcla old/new.
    for ($i = $cambios.Count - 1; $i -ge 0; $i--) {
        $c = $cambios[$i]
        if (Test-Path $c.Target) { Remove-Item -LiteralPath $c.Target -Recurse -Force }
        if (Test-Path $c.Backup) { Move-Item -LiteralPath $c.Backup -Destination $c.Target }
    }
    throw
} finally {
    if (Test-Path $Tx) { Remove-Item -LiteralPath $Tx -Recurse -Force }
}
Ok "binarios y rulepacks reemplazados como una sola versión"

# ── 2-3. motores ─────────────────────────────────────────────────────────────
# gitleaks, trivy, semgrep, squawk, ruff, mypy, y -si hay JDK- google-java-
# format y PMD. La descarga con hash fijado y los motores de cada cadena de
# herramientas viven en engines.ps1, compartido con el setup de Inno. Los
# hashes salen de motores.json (copiada por build-dist desde
# internal/engines/identidad/motores.json).
& (Join-Path $Src "engines.ps1") -EnginesDir $Engines -SkipTrivy:$SkipTrivy

# ── 4. Integracion de terminal (perfil de PowerShell, sin tocar registro) ────
Step "Configurando acceso en terminal"
$perfiles = @($PROFILE.CurrentUserAllHosts, $PROFILE.CurrentUserCurrentHost) | Select-Object -Unique
$bloquePerfil = "`n# >>> CodeGuard >>>`nif (`$env:PATH -notlike `"*$Bin*`") { `$env:PATH = `"$Bin;$Engines;`$env:PATH`" }`n# <<< CodeGuard <<<`n"
foreach ($p in $perfiles) {
    if ($p) {
        $dirP = Split-Path $p
        if (-not (Test-Path $dirP)) { New-Item -ItemType Directory -Force -Path $dirP | Out-Null }
        $actual = if (Test-Path $p) { Get-Content $p -Raw } else { "" }
        if ($actual -notmatch '# >>> CodeGuard >>>') {
            Add-Content -Path $p -Value $bloquePerfil -Encoding UTF8
        }
    }
}
$env:PATH = "$Bin;$Engines;$env:PATH"
Ok "acceso configurado en perfil de PowerShell (cero modificaciones al registro)"

# ── 5. Credenciales del modelo ────────────────────────────────────────────────
# El instalador no recibe secretos: pasarlos como argumentos los expone en el
# historial de PowerShell y, mientras el proceso vive, en su linea de comandos.
Write-Host "    Configura FOUNDRY_API_KEY despues con 'codeguard config'." -ForegroundColor Yellow

# ── 6. daemon con la sesion de Windows (Startup folder, sin registro) ────────
Step "Configurando arranque automatico del daemon (carpeta Inicio)"
# Limpieza preventiva de residuo legacy en registro de versiones previas
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "CodeGuard" -ErrorAction SilentlyContinue

$startupDir = [Environment]::GetFolderPath("Startup")
$lnkPath    = Join-Path $startupDir "CodeGuard.lnk"
$ws = $null
try {
    $ws  = New-Object -ComObject WScript.Shell
    $lnk = $ws.CreateShortcut($lnkPath)
    $lnk.TargetPath = "$Bin\codeguard-daemon.exe"
    $lnk.WorkingDirectory = "$Bin"
    $lnk.IconLocation = "$Bin\codeguard-daemon.exe,0"
    $lnk.Save()
    Ok "acceso directo creado en Inicio ($lnkPath)"
} catch {
    Write-Host "    Aviso: no se pudo crear el acceso directo en Inicio: $_" -ForegroundColor Yellow
} finally {
    if ($ws) { [Runtime.InteropServices.Marshal]::ReleaseComObject($ws) | Out-Null }
}

Start-Process "$Bin\codeguard-daemon.exe" -WorkingDirectory $Bin
# «daemon corriendo» se AFIRMA solo tras comprobarlo (W2 del plan): un
# Start-Process sin verificación dejaba el mensaje en verde aunque el proceso
# muriera a los 200 ms. doctor --global pregunta por el pipe de verdad.
$daemonOk = $false
foreach ($i in 1..30) {
    & "$Bin\codeguard.exe" doctor --global *> $null
    $procesos = @(Get-Process codeguard-daemon -ErrorAction SilentlyContinue)
    if ($LASTEXITCODE -eq 0 -and $procesos.Count -eq 1) { $daemonOk = $true; break }
    Start-Sleep -Milliseconds 500
}
if ($daemonOk) {
    $DaemonSeDetuvo = $false
    Ok "exactamente un daemon corriendo y VERIFICADO por el pipe"
} else {
    throw "el daemon nuevo no confirmó estado saludable y único en 15s; revisa con 'codeguard doctor --global'"
}

# ── 7. verificacion final ────────────────────────────────────────────────────
Step "Verificacion (codeguard repair)"
& "$Bin\codeguard.exe" repair
Write-Host ""
Write-Host "LISTO. Siguiente paso por repo: cd al proyecto y 'codeguard init'" -ForegroundColor Green
