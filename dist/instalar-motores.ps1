# =============================================================================
# CodeGuard - runner de motores para el setup (sin ventanas)
# El instalador lo lanza OCULTO y lee su progreso desde dos archivos: el log,
# del que muestra la ultima linea, y el de progreso, con el que mueve la barra.
# Al terminar escribe el codigo de salida en el .done.
#   log     : %TEMP%\codeguard-motores[-<id>].log       (ultima linea = detalle)
#   progreso: %TEMP%\codeguard-motores[-<id>].progress  (lineas CGP|...)
#   faltan  : %TEMP%\codeguard-motores[-<id>].faltan    (parte de lo ausente)
#   done    : %TEMP%\codeguard-motores[-<id>].done      (codigo de salida)
# =============================================================================
param(
    # Identificador de ESTA corrida, que el setup genera y comparte. Sin el,
    # dos instalaciones simultaneas escribian los mismos cuatro archivos y cada
    # asistente podia leer el resultado del otro: uno anunciaba "listo" con el
    # .done que acababa de dejar la instalacion del vecino. Vacio = ejecucion a
    # mano, con los nombres de siempre.
    [string]$Id = ""
)

# PowerShell 7 inyecta sus rutas de modulos en el PSModulePath del sistema, y
# Windows PowerShell 5.1 las hereda al ser lanzado como proceso hijo: acaba
# cargando el Microsoft.PowerShell.Utility de la 7 y perdiendo cmdlets propios.
# Se fija aqui tambien, no solo en engines.ps1, porque este script usa cmdlets
# propios (Out-File, Set-Content, Start-Sleep) antes y despues de invocarlo.
$env:PSModulePath = @(
    (Join-Path $env:ProgramFiles "WindowsPowerShell\Modules"),
    (Join-Path $env:SystemRoot "system32\WindowsPowerShell\v1.0\Modules")
) -join ';'

# ── Como se DECODIFICA lo que escriben los .exe ─────────────────────────────
#
# Poner el log en UTF-8 arregla la mitad del problema: la de las lineas que
# escribe PowerShell. La otra mitad es como PowerShell LEE lo que escriben los
# programas nativos (codeguard.exe repair, curl, go, pip, winget), y eso lo
# decide [Console]::OutputEncoding.
#
# El instalador lanza esta consola OCULTA, y una consola oculta nace con la
# pagina ANSI del sistema (1252). Los exes escriben UTF-8, asi que PowerShell
# los decodificaba con la pagina equivocada y los acentos llegaban rotos al
# log: medido, «no arranca aqui» salia como «no arranca aquÃ­» — y esa linea es
# justo el aviso de que a un motor le falta un JDK mas nuevo.
#
# Va aqui y no en engines.ps1 porque engines.ps1 corre en ESTE proceso y hereda
# el ajuste. Y va en try/catch porque el setter necesita una consola: si algun
# dia esto se ejecuta sin ella, se pierde un acento, no la instalacion.
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

$sufijo = if ($Id) { "-$Id" } else { "" }
$log      = Join-Path $env:TEMP "codeguard-motores$sufijo.log"
$flag     = Join-Path $env:TEMP "codeguard-motores$sufijo.done"
$progreso = Join-Path $env:TEMP "codeguard-motores$sufijo.progress"
$faltan   = Join-Path $env:TEMP "codeguard-motores$sufijo.faltan"
Remove-Item $flag, $log, $progreso, $faltan -Force -ErrorAction SilentlyContinue

# ── Un solo runner a la vez, SIN matar a nadie ───────────────────────────────
#
# Antes esto barria la lista de procesos y fusilaba cualquier powershell.exe
# que tuviera "instalar-motores.ps1" en su linea de comandos. Tenia dos
# problemas de fondo:
#
#  1. Mataba trabajo VIVO. Un segundo setup lanzado mientras el primero bajaba
#     los 70 MB de PMD se llevaba por delante la descarga del primero, que
#     ademas no se enteraba: se quedaba esperando un .done que ya no iba a
#     escribir nadie hasta agotar su plazo de una hora.
#  2. No resolvia la carrera real, que no es "dos runners existen" sino "dos
#     runners escriben el mismo directorio de motores y los mismos parciales".
#
# El lock exclusivo dice lo mismo sin violencia: quien lo tiene, trabaja; quien
# no, ESPERA. Y lo suelta el sistema operativo al morir el proceso, asi que un
# setup cerrado a la mitad no deja la puerta cerrada para el siguiente — que es
# como fallan estos cerrojos cuando se hacen con un archivo centinela a mano.
$lockPath = Join-Path (Join-Path $env:LOCALAPPDATA "CodeGuard") ".motores.lock"
New-Item -ItemType Directory -Force (Split-Path $lockPath) | Out-Null
$lock = $null
# El plazo es el mismo que espera el asistente: si el otro runner tarda mas de
# una hora, este ya no le sirve a nadie.
for ($i = 1; $i -le 3600 -and -not $lock; $i++) {
    try {
        $lock = [System.IO.File]::Open($lockPath, 'OpenOrCreate', 'ReadWrite', 'None')
    } catch {
        if ($i -eq 1) {
            "==> otra instalacion de motores esta en marcha: esperando a que termine" |
                Out-File -LiteralPath $log -Encoding utf8
        }
        Start-Sleep -Seconds 1
    }
}
if (-not $lock) {
    "otra instalacion de motores sigue ocupando el equipo tras una hora de espera." |
        Out-File -LiteralPath $log -Encoding utf8 -Append
    "Reintenta con: codeguard repair" |
        Out-File -LiteralPath $log -Encoding utf8 -Append
    Set-Content -LiteralPath $flag -Value 75
    return
}

$codigo = 0
try {
    # ── El log, en UTF-8 y con TODOS los flujos ──────────────────────────────
    #
    # Era `*>> $log`, y en Windows PowerShell 5.1 ese redirector escribe
    # UTF-16LE. El asistente lo lee con LoadStringsFromFile, que interpreta
    # ANSI: cada caracter llegaba seguido de un NUL y la etiqueta de Windows
    # corta en el primer NUL. Medido en un banco con el propio Inno Setup 6:
    # de tres lineas salian siete, la mitad eran un solo NUL, y lo unico que
    # ese control ha pintado en su vida es un "=".
    #
    # UTF-8 CON BOM —que es lo que produce Out-File -Encoding utf8 en 5.1— se
    # lee perfecto, y sin tocar una linea del .iss. Medido igual.
    #
    # Y es *>&1 y no 2>&1: engines.ps1 informa SOLO con Write-Host, que en 5.1
    # va por el flujo de informacion (6). Con 2>&1 se capturaria el flujo de
    # error y se perderia justo el texto que se quiere ensenar.
    & (Join-Path $PSScriptRoot "engines.ps1") -ProgressFile $progreso -FaltanFile $faltan *>&1 |
        Out-File -LiteralPath $log -Encoding utf8 -Append
    # ── El codigo se guarda AQUI, no despues ────────────────────────────────
    #
    # engines.ps1 sale con 2 cuando faltan motores. Antes ese valor se perdia:
    # lo unico que se miraba era $LASTEXITCODE despues de `codeguard repair`,
    # que lo habia pisado. Una instalacion a la que le faltaban compuertas
    # podia anunciarse como "Motores instalados y verificados" con solo que
    # repair devolviera 0 — el mismo pecado de afirmar sin comprobar que este
    # instalador ya persiguio una vez con el daemon.
    $codigoMotores = $LASTEXITCODE

    # verificacion final con el PATH inyectado en este proceso
    $env:PATH = (Join-Path $PSScriptRoot "bin") + ";" + (Join-Path $PSScriptRoot "engines") + ";" + $env:PATH
    & (Join-Path $PSScriptRoot "bin\codeguard.exe") repair *>&1 |
        Out-File -LiteralPath $log -Encoding utf8 -Append
    $codigoRepair = $LASTEXITCODE

    # Manda el de los motores: es el que sabe QUE falta. repair solo se usa si
    # los motores fueron bien y aun asi el agente no se dio por sano.
    if ($codigoMotores -ne 0)     { $codigo = $codigoMotores }
    elseif ($codigoRepair -ne 0)  { $codigo = $codigoRepair }
} catch {
    $_ | Out-String | Out-File -LiteralPath $log -Encoding utf8 -Append
    $codigo = 1
} finally {
    $lock.Dispose()
}
Set-Content -LiteralPath $flag -Value $codigo
