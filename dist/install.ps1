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

# ── 5. API key del modelo (Administrador de credenciales) ────────────────────
#
# La clave va a la boveda del usuario, NO al registro.
#
# Se pasa por la ENTRADA ESTANDAR y no como argumento: un argumento es visible
# en la lista de procesos mientras dura, y en PowerShell queda ademas en el
# historial del usuario.
if ($ApiKey) {
    $ApiKey | & "$Bin\codeguard.exe" config --guardar-clave FOUNDRY_API_KEY
    if ($LASTEXITCODE -eq 0) {
        Ok "FOUNDRY_API_KEY guardada en el Administrador de credenciales"
    } else {
        Write-Host "    No se pudo guardar FOUNDRY_API_KEY en el Administrador de credenciales" -ForegroundColor Yellow
        Write-Host "    Guardala desde la ventana del agente (codeguard config) cuando arranque." -ForegroundColor Yellow
    }
} else {
    Write-Host "    (sin -ApiKey: la capa LLM quedara apagada hasta definir FOUNDRY_API_KEY)" -ForegroundColor Yellow
}

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

Get-Process codeguard-daemon -ErrorAction SilentlyContinue | Stop-Process -Force -Confirm:$false
Start-Process "$Bin\codeguard-daemon.exe"
Ok "daemon corriendo (el orbe vive abajo a la derecha)"

# ── 7. verificacion final ────────────────────────────────────────────────────
Step "Verificacion (codeguard repair)"
& "$Bin\codeguard.exe" repair
Write-Host ""
Write-Host "LISTO. Siguiente paso por repo: cd al proyecto y 'codeguard init'" -ForegroundColor Green
