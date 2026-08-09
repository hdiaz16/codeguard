# =============================================================================
# CodeGuard - desinstalador
# Quita el agente de esta maquina: binarios, motores, arranque, PATH y datos.
# NO toca los repos: para desenrolar un repo usa -Repos con sus rutas.
# Uso:  powershell -ExecutionPolicy Bypass -File uninstall.ps1 [-Datos] [-Repos "C:\a","C:\b"]
# =============================================================================
param(
    [switch]$Datos,          # borra tambien la BD, el log y el registro de proyectos
    [string[]]$Repos = @()   # repos a desenrolar (quita hooks y config local de git)
)
$ErrorActionPreference = "Continue"
function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "    $m" -ForegroundColor Green }

$Root = Join-Path $env:LOCALAPPDATA "CodeGuard"
$Data = Join-Path $env:LOCALAPPDATA "codeguard"

Step "Deteniendo el daemon"
Get-Process codeguard-daemon -ErrorAction SilentlyContinue | Stop-Process -Force -Confirm:$false
Start-Sleep 1
Get-CimInstance Win32_Process -Filter "Name='msedgewebview2.exe'" |
    Where-Object { $_.CommandLine -like "*codeguard*" } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -Confirm:$false -ErrorAction SilentlyContinue }
Ok "detenido"

Step "Quitando el arranque con la sesion"
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "CodeGuard" -ErrorAction SilentlyContinue
Ok "clave Run eliminada"

Step "Limpiando el PATH de usuario"
$userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($userPath) {
    $limpio = ($userPath -split ';' | Where-Object { $_ -and $_ -notlike "*\CodeGuard\bin*" -and $_ -notlike "*\CodeGuard\engines*" }) -join ';'
    [Environment]::SetEnvironmentVariable("PATH", $limpio, "User")
    Ok "entradas de CodeGuard removidas"
}

Step "Borrando binarios y motores"
if (Test-Path $Root) { Remove-Item -Recurse -Force $Root -ErrorAction SilentlyContinue }
Ok $Root

if ($Datos) {
    Step "Borrando datos locales (BD, log, registro de proyectos)"
    if (Test-Path $Data) { Remove-Item -Recurse -Force $Data -ErrorAction SilentlyContinue }
    $wv = Join-Path $env:APPDATA "codeguard-daemon.exe"
    if (Test-Path $wv) { Remove-Item -Recurse -Force $wv -ErrorAction SilentlyContinue }
    Ok "telemetria y cache eliminadas"
} else {
    Write-Host "    (la BD y el registro se conservan; usa -Datos para borrarlos)" -ForegroundColor Yellow
}

foreach ($r in $Repos) {
    Step "Desenrolando $r"
    if (-not (Test-Path $r)) { Write-Host "    no existe" -ForegroundColor Yellow; continue }
    git -C $r config --unset core.hooksPath 2>$null
    git -C $r config --unset codeguard.binpath 2>$null
    foreach ($d in @(".githooks", ".codeguard")) {
        $p = Join-Path $r $d
        if (Test-Path $p) { Remove-Item -Recurse -Force $p -ErrorAction SilentlyContinue }
    }
    Ok "hooks y config removidos (lo versionado vuelve con git checkout)"
}

Write-Host ""
Write-Host "CodeGuard desinstalado." -ForegroundColor Green
