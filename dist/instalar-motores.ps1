# =============================================================================
# CodeGuard - runner de motores para el setup (sin ventanas)
# El instalador lo lanza OCULTO y lee su progreso desde el log para mostrarlo
# dentro del asistente. Al terminar escribe el codigo de salida en el .done.
#   log : %TEMP%\codeguard-motores.log   (el asistente muestra la ultima linea)
#   done: %TEMP%\codeguard-motores.done  (contenido = codigo de salida)
# =============================================================================
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

    # verificacion final con el PATH ya actualizado por el setup
    $env:PATH = [Environment]::GetEnvironmentVariable("PATH", "User") + ";" + $env:PATH
    & (Join-Path $PSScriptRoot "bin\codeguard.exe") repair *>> $log
    if ($LASTEXITCODE -ne 0) { $codigo = $LASTEXITCODE }
} catch {
    # mismo encoding que *>> (UTF-16): mezclarlo con ANSI vuelve ilegible el log
    $_ | Out-String | Add-Content $log -Encoding Unicode
    $codigo = 1
}
Set-Content -Path $flag -Value $codigo
