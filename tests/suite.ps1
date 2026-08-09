# =============================================================================
# CodeGuard - suite de pruebas end-to-end y rendimiento
# Ejecuta escenarios reales contra los repos enrolados y mide latencias.
# Uso:  powershell -ExecutionPolicy Bypass -File tests\suite.ps1
# =============================================================================
$ErrorActionPreference = "Continue"
$Bin     = Join-Path $env:LOCALAPPDATA "CodeGuard\bin"
$Engines = Join-Path $env:LOCALAPPDATA "CodeGuard\engines"
$env:PATH = "$Bin;$Engines;$(Join-Path $env:APPDATA 'Python\Python313\Scripts');$env:PATH"
$CG = Join-Path $Bin "codeguard.exe"

$script:pasos = @()
$script:fallos = 0
function Prueba($nombre, $esperado, $obtenido, $detalle = "") {
    $ok = $esperado -eq $obtenido
    if (-not $ok) { $script:fallos++ }
    $script:pasos += [pscustomobject]@{
        Prueba = $nombre; Esperado = $esperado; Obtenido = $obtenido
        Resultado = $(if ($ok) { "PASA" } else { "FALLA" }); Detalle = $detalle
    }
    $color = if ($ok) { "Green" } else { "Red" }
    Write-Host ("  {0,-46} {1}  {2}" -f $nombre, $(if ($ok) { "PASA " } else { "FALLA" }), $detalle) -ForegroundColor $color
}
function Titulo($t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }

# repos de prueba
$KNOW = "C:\Users\Hector Diaz\repos\knowhub"
$SAM  = "C:\Users\Hector Diaz\Documents\os-samantha"
$CGR  = "C:\Users\Hector Diaz\codeguard"

function LimpiarRepo($repo, $archivo) {
    Push-Location $repo
    # Si la prueba esperaba un bloqueo y el commit paso igual, el commit queda
    # en el historial y las corridas siguientes ya no cambian nada: git dice
    # "nothing to commit" y la prueba pasa por el motivo equivocado. Deshacerlo
    # es obligatorio, no cosmetico.
    if ($script:HeadAntes -and (git rev-parse HEAD 2>$null) -ne $script:HeadAntes) {
        Write-Host "    (deshaciendo commit que no debio pasar)" -ForegroundColor DarkYellow
        git reset --hard -q $script:HeadAntes 2>$null
    }
    git reset -q 2>$null
    if (Test-Path $archivo) { Remove-Item $archivo -Force }
    Pop-Location
}
function CommitProbar($repo, $archivo, $contenido, $mensaje) {
    Push-Location $repo
    $script:HeadAntes = (git rev-parse HEAD 2>$null)
    [IO.File]::WriteAllText((Join-Path $repo $archivo), $contenido)
    git add $archivo 2>$null | Out-Null
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $salida = git commit -m $mensaje 2>&1 | Out-String
    $sw.Stop()
    $code = $LASTEXITCODE
    Pop-Location
    return [pscustomobject]@{ Exit = $code; Salida = $salida; Ms = $sw.ElapsedMilliseconds }
}
function Revertir($repo) {
    Push-Location $repo
    git reset -q --soft HEAD~1 2>$null
    git restore --staged . 2>$null
    Pop-Location
}

Write-Host "CodeGuard - suite de pruebas" -ForegroundColor White
Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm')`n"

# ── 0. Estado del entorno ────────────────────────────────────────────────────
Titulo "0. Entorno"
$daemon = Get-Process codeguard-daemon -ErrorAction SilentlyContinue
Prueba "daemon corriendo" $true ($daemon -ne $null)
Prueba "binario instalado" $true (Test-Path $CG)
$rep = & $CG repair 2>&1 | Out-String
Prueba "motores completos" $true ($rep -match "todo en orden") ($rep -split "`n" | Where-Object { $_ -match "FALTA" }) -join " "
$st = & $CG status --todos 2>&1 | Out-String
# El enrolamiento en si (config, hooks, hooksPath, binpath, rulepack, baseline).
# Un HALLAZGOS.md con pendientes NO es un fallo de enrolamiento: es trabajo por hacer.
$fallosEnrolamiento = ([regex]::Matches($st, "✗ (config|hooks|hooksPath|binpath|rulepack|baseline)")).Count
Prueba "enrolamiento sin fallos" 0 $fallosEnrolamiento
Prueba "3 proyectos registrados" 3 (([regex]::Matches($st, "──")).Count)

# ── 1. Escenarios funcionales ────────────────────────────────────────────────
Titulo "1. Escenarios end-to-end"

$r = CommitProbar $SAM "internal\domain\t_limpio.go" "package domain`n`nfunc TLimpio(a int) int { return a + 1 }`n" "suite: limpio"
Prueba "commit limpio pasa" 0 $r.Exit "$($r.Ms) ms"
Prueba "  informa veredicto" $true ($r.Salida -match "listo — commit permitido")
if ($r.Exit -eq 0) { Revertir $SAM }
LimpiarRepo $SAM "internal\domain\t_limpio.go"

# OJO con el dato de prueba: un PAT de GitHub lleva 36 caracteres tras "ghp_".
# Con menos, gitleaks NO lo reconoce (y hace bien) — la prueba fallaria por el
# dato, no por el producto.
$pat = "ghp_" + "Zt4nB8xWqR2yE5cM7vD1fH3jL6sA0pQuVwXy"
$r = CommitProbar $KNOW "src\lib\t_secreto.ts" "export const k = '$pat';`n" "suite: secreto"
Prueba "secreto BLOQUEA" 1 $r.Exit "$($r.Ms) ms"
Prueba "  bloquea offline (antes de la red)" $true ($r.Salida -match "NADA sali")
Prueba "  instruye rotar primero" $true ($r.Salida -match "rota la credencial PRIMERO")
LimpiarRepo $KNOW "src\lib\t_secreto.ts"

# variante: nombre revelador -> regla generica.
# El literal se ARMA en ejecucion: si estuviera completo en el archivo,
# CodeGuard bloquearia su propia suite (y haria bien).
$gen = "sk-" + "proj-9fK2mN7pQ4rT8vX1zB5cD0gH3jL6sA"
$r = CommitProbar $KNOW "src\lib\t_secreto2.ts" "export const apiKey = '$gen';`n" "suite: secreto generico"
Prueba "credencial con nombre revelador BLOQUEA" 1 $r.Exit "$($r.Ms) ms"
LimpiarRepo $KNOW "src\lib\t_secreto2.ts"

$r = CommitProbar $KNOW "src\lib\t_any.ts" "export function f(d: any) { return d; }`n" "suite: any"
Prueba "regla de la casa BLOQUEA" 1 $r.Exit "$($r.Ms) ms"
Prueba "  cita archivo y linea" $true ($r.Salida -match "t_any\.ts:\d+")
LimpiarRepo $KNOW "src\lib\t_any.ts"

$sql = "ALTER TABLE documents ADD COLUMN sku text NOT NULL;`nCREATE INDEX idx_sku ON documents (sku);`n"
$r = CommitProbar $KNOW "supabase\migrations\099_suite.sql" $sql "suite: migracion"
Prueba "migracion insegura BLOQUEA" 1 $r.Exit "$($r.Ms) ms"
Prueba "  explica el lock" $true ($r.Salida -match "NOT NULL|CONCURRENTLY|lock")
LimpiarRepo $KNOW "supabase\migrations\099_suite.sql"

$r = CommitProbar $SAM "internal\domain\t_fmt.go" "package domain`nfunc  TFmt( x int )int{`nreturn x}`n" "suite: formato"
Prueba "formato sin gofmt BLOQUEA" 1 $r.Exit "$($r.Ms) ms"
LimpiarRepo $SAM "internal\domain\t_fmt.go"

# bypass
Push-Location $KNOW
[IO.File]::WriteAllText((Join-Path $KNOW "src\lib\t_bypass.ts"), "export function b(d: any) { return d; }`n")
git add src\lib\t_bypass.ts | Out-Null
git commit --no-verify -m "suite: bypass" 2>&1 | Out-Null
$bypassOk = $LASTEXITCODE -eq 0
$msg = git log -1 --format=%B | Out-String
Pop-Location
Prueba "--no-verify permite el commit" $true $bypassOk
Prueba "  sin trailer (queda como bypass)" $false ($msg -match "Codeguard-Run-Id")
Revertir $KNOW
LimpiarRepo $KNOW "src\lib\t_bypass.ts"

# degradacion sin daemon
Titulo "2. Degradacion (P4: nunca secuestra el trabajo)"
Stop-Process -Name codeguard-daemon -Force -Confirm:$false -ErrorAction SilentlyContinue
Start-Sleep 2
$r = CommitProbar $SAM "internal\domain\t_sin_daemon.go" "package domain`n`nfunc TSinDaemon() int { return 7 }`n" "suite: sin daemon"
Prueba "sin daemon el commit sigue" 0 $r.Exit "$($r.Ms) ms"
Prueba "  avisa la capa degradada" $true ($r.Salida -match "daemon:offline")
if ($r.Exit -eq 0) { Revertir $SAM }
LimpiarRepo $SAM "internal\domain\t_sin_daemon.go"
Start-Process (Join-Path $Bin "codeguard-daemon.exe")
Start-Sleep 5

# ── 3. Rendimiento ───────────────────────────────────────────────────────────
Titulo "3. Rendimiento (5 commits limpios seguidos)"
$tiempos = @()
for ($i = 1; $i -le 5; $i++) {
    $r = CommitProbar $SAM "internal\domain\t_perf.go" "package domain`n`nfunc TPerf$i() int { return $i }`n" "suite: perf $i"
    $tiempos += $r.Ms
    if ($r.Exit -eq 0) { Revertir $SAM }
    Write-Host ("    corrida {0}: {1} ms" -f $i, $r.Ms) -ForegroundColor DarkGray
}
LimpiarRepo $SAM "internal\domain\t_perf.go"
$ord = $tiempos | Sort-Object
$p50 = $ord[[int]($ord.Count * 0.5)]
$p95 = $ord[[math]::Min($ord.Count - 1, [int]($ord.Count * 0.95))]
Prueba "p50 del hook < 6 s" $true ($p50 -lt 6000) "$p50 ms"
Prueba "p95 del hook < 12 s" $true ($p95 -lt 12000) "$p95 ms"

Titulo "4. Huella"
$d = Get-Process codeguard-daemon -ErrorAction SilentlyContinue
$wv = Get-CimInstance Win32_Process -Filter "Name='msedgewebview2.exe'" |
      Where-Object { $_.CommandLine -like "*codeguard*" }
$ramWv = ($wv | ForEach-Object { (Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue).WorkingSet64 } | Measure-Object -Sum).Sum
$ramTotal = [math]::Round(($d.WorkingSet64 + $ramWv) / 1MB)
Prueba "daemon (Go) < 60 MB" $true ([math]::Round($d.WorkingSet64/1MB) -lt 60) "$([math]::Round($d.WorkingSet64/1MB)) MB"
Prueba "RAM total del agente < 550 MB" $true ($ramTotal -lt 550) "$ramTotal MB (con $($wv.Count) webviews)"
$tam = [math]::Round(((Get-Item $CG).Length + (Get-Item (Join-Path $Bin "codeguard-daemon.exe")).Length) / 1MB, 1)
Prueba "binarios < 40 MB" $true ($tam -lt 40) "$tam MB"

Titulo "5. Comandos auxiliares"
Push-Location $CGR
$sw = [Diagnostics.Stopwatch]::StartNew(); $out = & $CG report 2>&1 | Out-String; $sw.Stop()
Prueba "report genera informe" $true ($out -match "informe:") "$($sw.ElapsedMilliseconds) ms"
$sw = [Diagnostics.Stopwatch]::StartNew(); $out = & $CG graph --deep 2>&1 | Out-String; $sw.Stop()
# Con el agente vivo abre en SU ventana; sin agente deja la copia de archivo.
Prueba "graph --deep abre el explorador" $true ($out -match "ventana del agente|explorador generado") "$($sw.ElapsedMilliseconds) ms"
Prueba "  no usa el navegador" $true (-not ($out -match "docs.explorador.index.html" -and $out -notmatch "ventana"))
$out = & $CG stats 2>&1 | Out-String
Prueba "stats responde" $true ($out.Length -gt 0)
$out = & $CG engines 2>&1 | Out-String
Prueba "engines verifica los binarios" $true ($out -match "publicados por sus autores")
Prueba "  gitleaks marcado como critico" $true ($out -match "gitleaks \(cr")
Pop-Location

Titulo "6. Integridad de los scripts de instalacion"
# Solo los scripts que escribimos nosotros: node_modules trae los suyos y no
# es asunto nuestro como los codifica npm.
function NuestrosScripts {
    Get-ChildItem (Split-Path $PSScriptRoot -Parent) -Recurse -Filter *.ps1 |
        Where-Object { $_.FullName -notmatch "node_modules|\\spikes\\" }
}
# Un error de sintaxis en install.ps1 no se nota hasta que un dev lo corre en
# su maquina y falla la instalacion entera. Un "$var:" mal escrito ya paso.
$malos = @()
NuestrosScripts | ForEach-Object {
    $errs = $null
    [void][System.Management.Automation.PSParser]::Tokenize((Get-Content $_.FullName -Raw), [ref]$errs)
    if ($errs -and $errs.Count) { $malos += "$($_.Name):$($errs[0].Token.StartLine)" }
}
Prueba "todos los .ps1 parsean" 0 $malos.Count ($malos -join ", ")
# PowerShell 5 rompe con UTF-8 sin BOM: los acentos y guiones largos salen mal.
$sinBom = @()
NuestrosScripts | ForEach-Object {
    $b = [System.IO.File]::ReadAllBytes($_.FullName)
    if ($b.Length -lt 3 -or $b[0] -ne 0xEF -or $b[1] -ne 0xBB -or $b[2] -ne 0xBF) { $sinBom += $_.Name }
}
Prueba "todos los .ps1 llevan BOM" 0 $sinBom.Count ($sinBom -join ", ")

# ── resumen ──────────────────────────────────────────────────────────────────
Write-Host ""
$total = $script:pasos.Count
$ok = $total - $script:fallos
if ($script:fallos -eq 0) {
    Write-Host "TODAS LAS PRUEBAS PASARON ($ok/$total)" -ForegroundColor Green
} else {
    Write-Host "$($script:fallos) PRUEBA(S) FALLARON — $ok/$total pasaron" -ForegroundColor Red
    $script:pasos | Where-Object { $_.Resultado -eq "FALLA" } | Format-Table Prueba, Esperado, Obtenido, Detalle -AutoSize
}
$script:pasos | Export-Csv -NoTypeInformation -Path (Join-Path $PSScriptRoot "ultimo-resultado.csv") -Encoding UTF8
Write-Host "detalle: tests\ultimo-resultado.csv"
