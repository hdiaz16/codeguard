# =============================================================================
# CodeGuard - desinstalador
# Quita el agente de esta maquina: binarios, motores, arranque, PATH y datos.
# NO toca los repos: para desenrolar un repo usa -Repos con sus rutas.
# Uso:  powershell -ExecutionPolicy Bypass -File uninstall.ps1 [-Datos] [-Repos "C:\a","C:\b"]
# =============================================================================
param(
    [switch]$Datos,          # borra tambien la BD, el log y el registro de proyectos
    [string[]]$Repos = @(),  # repos a desenrolar (quita hooks y config local de git)
    [switch]$SoloRepos       # desenrolar esos repos SIN desinstalar el agente
)
$ErrorActionPreference = "Continue"
function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "    $m" -ForegroundColor Green }

$Root = Join-Path $env:LOCALAPPDATA "CodeGuard"
$Data = Join-Path $env:LOCALAPPDATA "codeguard"

# Desenrolar un repo y desinstalar el agente son cosas distintas. Antes -Repos
# hacia las dos, asi que quien solo queria sacar un proyecto de la lista se
# quedaba sin agente en toda la maquina.
if ($SoloRepos) {
    if (-not $Repos) { Write-Host "-SoloRepos necesita -Repos con al menos una ruta" -ForegroundColor Red; exit 1 }
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
    # Quitarlos del registro con el propio agente. Editar repos.json desde
    # PowerShell salio mal: ConvertTo-Json desenvuelve los arreglos de un solo
    # elemento y el registro dejaba de ser una lista, asi que el panel se
    # quedaba sin ningun proyecto. El formato es del lado Go y ahi se maneja.
    $cg = Join-Path $Root "bin\codeguard.exe"
    if (Test-Path $cg) {
        foreach ($r in $Repos) { & $cg forget $r 2>&1 | Out-Null }
        Ok "quitados de la lista del agente"
    }
    Write-Host ""
    Write-Host "Repos desenrolados. El agente sigue instalado." -ForegroundColor Green
    exit 0
}

Step "Deteniendo el daemon"
# PRIMERO se le pide, DESPUES se le mata. Un daemon fusilado con Stop-Process
# no llega a quitar su icono, y Windows deja un orbe FANTASMA pintado en la
# bandeja hasta que algo la refresca (en la bandeja nueva de Windows 11, solo
# reiniciar Explorer, que no es cosa que un desinstalador deba hacer). El
# apagado por IPC pasa por app.Quit(), el mismo camino que el boton "Salir de
# CodeGuard" del menu, y ese si desmonta la bandeja. El taskkill queda como
# ultimo recurso: un daemon viejo (< 1.13.1) no conoce el comando, y un daemon
# colgado no contesta.
$cg = Join-Path $Root "bin\codeguard.exe"
$vivo = Get-Process codeguard-daemon -ErrorAction SilentlyContinue
if ($vivo -and (Test-Path $cg)) {
    & $cg daemon-stop 2>&1 | Out-Null
    $vivo = Get-Process codeguard-daemon -ErrorAction SilentlyContinue
}
if ($vivo) {
    $vivo | Stop-Process -Force -Confirm:$false
    Write-Host "    (a la fuerza: puede quedar un icono fantasma en la bandeja hasta reiniciar Explorer)" -ForegroundColor Yellow
}
Start-Sleep 1
Get-CimInstance Win32_Process -Filter "Name='msedgewebview2.exe'" |
    Where-Object { $_.CommandLine -like "*codeguard*" } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -Confirm:$false -ErrorAction SilentlyContinue }
Ok "detenido"

# La entrada de "Aplicaciones instaladas" que deja CodeGuard-Setup.exe (Inno).
# Este script y el Setup son dos caminos de instalacion que no se conocian:
# desinstalar por aqui dejaba la entrada fantasma en el panel de Windows
# apuntando a una version vieja, y ejecutar aquel unins000.exe despues podia
# comerse una instalacion nueva hecha por script. Se quita la entrada y sus
# archivos; los archivos reales los borra este script pieza a pieza mas abajo.
Step "Quitando el registro del instalador grafico (si existe)"
Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue |
    Where-Object { (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).DisplayName -like "CodeGuard*" } |
    ForEach-Object { Remove-Item $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue }
foreach ($f in @("unins000.dat", "unins000.exe")) {
    $p = Join-Path $Root $f
    if (Test-Path $p) { Remove-Item -Force $p -ErrorAction SilentlyContinue }
}
Ok "sin entradas duplicadas en Apps instaladas"

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

# CUIDADO: en Windows los nombres de carpeta no distinguen mayusculas, asi que
# %LOCALAPPDATA%\CodeGuard (binarios) y %LOCALAPPDATA%\codeguard (datos) son EL
# MISMO directorio. Borrar el arbol entero se llevaba por delante la BD, el
# registro de proyectos y la configuracion personal del modelo, aunque el
# script dijera que los conservaba. Por eso aqui se borra lo instalado pieza a
# pieza y nunca la carpeta completa.
Step "Borrando binarios y motores"
foreach ($sub in @("bin", "engines", "rulepacks")) {
    $p = Join-Path $Root $sub
    if (Test-Path $p) { Remove-Item -Recurse -Force $p -ErrorAction SilentlyContinue }
}
Ok "$Root\{bin, engines, rulepacks}"

if ($Datos) {
    Step "Borrando datos locales (BD, log, registro de proyectos, config del modelo)"
    foreach ($f in @("codeguard.db", "codeguard.db-shm", "codeguard.db-wal",
                     "daemon.log", "repos.json", "warm-repos.txt", "llm-local.yaml")) {
        $p = Join-Path $Data $f
        if (Test-Path $p) { Remove-Item -Force $p -ErrorAction SilentlyContinue }
    }
    $wv = Join-Path $env:APPDATA "codeguard-daemon.exe"
    if (Test-Path $wv) { Remove-Item -Recurse -Force $wv -ErrorAction SilentlyContinue }
    Ok "telemetria, registro y cache eliminados"
    # Ya vacia, la carpeta se va; si quedo algo del usuario, se respeta.
    if ((Test-Path $Root) -and -not (Get-ChildItem $Root -Force)) {
        Remove-Item -Force $Root -ErrorAction SilentlyContinue
    }
} else {
    Write-Host "    (la BD, el registro y tu config del modelo se conservan; usa -Datos para borrarlos)" -ForegroundColor Yellow
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
