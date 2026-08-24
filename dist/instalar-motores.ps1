# =============================================================================
# CodeGuard - runner de motores para el setup (sin ventanas)
# El instalador lo lanza OCULTO y lee su progreso desde el log para mostrarlo
# dentro del asistente. Al terminar escribe el codigo de salida en el .done.
#   log : %TEMP%\codeguard-motores.log   (el asistente muestra la ultima linea)
#   done: %TEMP%\codeguard-motores.done  (contenido = codigo de salida)
# =============================================================================
# PowerShell 7 inyecta sus rutas de modulos en el PSModulePath del sistema, y
# Windows PowerShell 5.1 las hereda al ser lanzado como proceso hijo: acaba
# cargando el Microsoft.PowerShell.Utility de la 7 y perdiendo cmdlets propios.
# Se fija aqui tambien, no solo en engines.ps1, porque este script usa
# Get-CimInstance y Stop-Process antes de invocarlo.
$env:PSModulePath = @(
    (Join-Path $env:ProgramFiles "WindowsPowerShell\Modules"),
    (Join-Path $env:SystemRoot "system32\WindowsPowerShell\v1.0\Modules")
) -join ';'

# Un solo runner a la vez: si quedo uno huerfano de un setup anterior
# (asistente cerrado a la mitad), se retira antes de empezar. Dos runners
# descargando el mismo zip se corrompen entre si.
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like "*instalar-motores.ps1*" -and $_.ProcessId -ne $PID } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

$log  = Join-Path $env:TEMP "codeguard-motores.log"
$flag = Join-Path $env:TEMP "codeguard-motores.done"
Remove-Item $flag -ErrorAction SilentlyContinue
Remove-Item $log  -ErrorAction SilentlyContinue

$codigo = 0
try {
    & (Join-Path $PSScriptRoot "engines.ps1") *>> $log

    # verificacion final con el PATH inyectado en este proceso
    $env:PATH = (Join-Path $PSScriptRoot "bin") + ";" + (Join-Path $PSScriptRoot "engines") + ";" + $env:PATH
    & (Join-Path $PSScriptRoot "bin\codeguard.exe") repair *>> $log
    if ($LASTEXITCODE -ne 0) { $codigo = $LASTEXITCODE }
} catch {
    # mismo encoding que *>> (UTF-16): mezclarlo con ANSI vuelve ilegible el log
    $_ | Out-String | Add-Content $log -Encoding Unicode
    $codigo = 1
}
Set-Content -Path $flag -Value $codigo
