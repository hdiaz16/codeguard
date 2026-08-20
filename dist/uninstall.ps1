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

# Limpieza de instalador grafico legacy (solo archivos, sin tocar registro)
Step "Limpiando archivos de instalacion"
foreach ($f in @("unins000.dat", "unins000.exe", "engines.ps1", "instalar-motores.ps1", "motores.json")) {
    $p = Join-Path $Root $f
    if (Test-Path $p) { Remove-Item -Force $p -ErrorAction SilentlyContinue }
}
Ok "archivos del instalador removidos"

Step "Quitando el arranque con la sesion (carpeta Inicio)"
$startupLnk = Join-Path ([Environment]::GetFolderPath("Startup")) "CodeGuard.lnk"
if (Test-Path $startupLnk) {
    Remove-Item -Force $startupLnk -ErrorAction SilentlyContinue
    Ok "acceso directo de Inicio eliminado"
}
# Limpieza preventiva de residuo legacy en registro de versiones previas
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "CodeGuard" -ErrorAction SilentlyContinue

Step "Limpiando snippet de perfiles de PowerShell"
$perfiles = @($PROFILE.CurrentUserAllHosts, $PROFILE.CurrentUserCurrentHost) | Select-Object -Unique
foreach ($p in $perfiles) {
    if ($p -and (Test-Path $p)) {
        $c = Get-Content $p -Raw
        if ($c -match '# >>> CodeGuard >>>') {
            $c = $c -replace '(?s)\r?\n?# >>> CodeGuard >>>.*?# <<< CodeGuard <<<\r?\n?', "`n"
            Set-Content -Path $p -Value $c.Trim() -Encoding UTF8
            Ok "snippet removido de $p"
        }
    }
}

# CUIDADO: en Windows los nombres de carpeta no distinguen mayusculas, asi que
# %LOCALAPPDATA%\CodeGuard (binarios) y %LOCALAPPDATA%\codeguard (datos) son EL
# MISMO directorio. Borrar el arbol entero se llevaba por delante la BD, el
# registro de proyectos y la configuracion personal del modelo, aunque el
# script dijera que los conservaba. Por eso aqui se borra lo instalado pieza a
# pieza y nunca la carpeta completa.
Step "Borrando binarios y motores"
# descargas\ es el cache de zips que crea engines.ps1 para reanudar instalaciones,
# y semgrep\ el que el motor genera al correr: los dos son restos de la
# instalacion —se regeneran solos—, NO datos del usuario, asi que se borran con o
# sin -Datos. Dejarlos tenia dos efectos, y el segundo es el que importa: la
# carpeta raiz nunca quedaba vacia (el paso final de borrarla era letra muerta) y
# la instalacion siguiente arrancaba sobre restos de la anterior.
foreach ($sub in @("bin", "engines", "rulepacks", "descargas", "semgrep")) {
    $p = Join-Path $Root $sub
    if (Test-Path $p) { Remove-Item -Recurse -Force $p -ErrorAction SilentlyContinue }
}
Ok "$Root\{bin, engines, rulepacks, descargas, semgrep}"
# Los motores de Python (semgrep, squawk, ruff, mypy) los instala pip a nivel de
# USUARIO, fuera de $Root, y quedan fuera del alcance a proposito: pueden estar
# ahi porque el usuario los usa para otra cosa, y borrarlos a ciegas seria
# destructivo. Se dice en voz alta en vez de callarlo.
Write-Host "    (los paquetes pip semgrep/squawk/ruff/mypy NO se desinstalan: son paquetes de usuario. 'pip uninstall' si no los quieres)" -ForegroundColor Yellow

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
# Explicito: sin esto, el script devolvia el exit code del ULTIMO comando
# nativo que corrio — p.ej. el daemon-stop fallido contra un daemon viejo — y
# cualquier automatizacion que llame al desinstalador leia "fallo" sobre una
# desinstalacion que termino entera y bien (medido: exit 2 con salida perfecta).
exit 0
