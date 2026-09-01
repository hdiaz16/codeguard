# Ensambla la carpeta de distribucion lista para repartir a los devs.
# Uso (desde la raiz del repo):  powershell -File dist\build-dist.ps1
$ErrorActionPreference = "Stop"
$repo = Split-Path $PSScriptRoot -Parent
Set-Location $repo

# La version viene de setup.iss - UNA fuente de verdad. Antes el binario
# decia "0.1.0-fase1" hardcodeado mientras el instalador decia 1.2.0, y no
# habia forma de saber que version corria de verdad.
$version = (Select-String (Join-Path $PSScriptRoot "setup.iss") -Pattern '#define MyAppVersion "([^"]+)"').Matches[0].Groups[1].Value
if (-not $version) { throw "no se pudo leer MyAppVersion de setup.iss" }

# El sunset de las huellas v1: fecha de ESTA release + 90 dias, inyectado como
# la version (turno 84 del consejo: reloj inyectable, nada cableado — la fecha
# normativa es la del binario; la cabecera de baseline.txt es informativa).
# Al cruzarla, el alias legacy deja de nacer y las baselines v1 sin renovar
# dejan de suprimir CON AVISO (finding.SunsetV1 y baseline.Load).
$sunsetV1 = (Get-Date).AddDays(90).ToString("yyyy-MM-dd")

# La pública sale de la misma privada DPAPI con la que se firmará abajo. No se
# lee de dist ni del rulepack: queda embebida en ambos ejecutables. Sin ella el
# build estable se aborta ANTES de producir binarios que aceptarían unsigned.
$eapPrevio = $ErrorActionPreference
$ErrorActionPreference = "Continue"
$releasePublic = (& go run .\cmd\codeguard-release public-key 2>&1 | Out-String).Trim()
$claveLista = ($LASTEXITCODE -eq 0 -and $releasePublic -match '^rel-[0-9a-f]{8}=[0-9a-f]{64}$')
$ErrorActionPreference = $eapPrevio
if (-not $claveLista) {
    throw "no hay una clave pública de release válida; ejecuta go run .\cmd\codeguard-release keygen y conserva su respaldo offline.`n$releasePublic"
}
$ldBase = "-s -w -X main.version=$version -X codeguard/internal/finding.SunsetV1=$sunsetV1 -X codeguard/internal/manifest.ReleaseKeys=$releasePublic"
Write-Host "==> compilando binarios optimizados (v$version, ventana dual de huellas v1 hasta $sunsetV1, rulepacks firmados)" -ForegroundColor Cyan
go build -trimpath -ldflags $ldBase -o dist\codeguard.exe .\cmd\codeguard
go build -trimpath -ldflags ("-H windowsgui " + $ldBase) -o dist\codeguard-daemon.exe .\cmd\daemon

Write-Host "==> copiando rulepack" -ForegroundColor Cyan
# Borrar antes de copiar: Copy-Item -Force fusiona en vez de reemplazar, asi
# que un rulepack retirado seguiria viajando en el instalador para siempre.
if (Test-Path dist\rulepacks) { Remove-Item dist\rulepacks -Recurse -Force }
Copy-Item rulepacks dist\ -Recurse -Force
# El modulo de herramientas viaja con el instalador: engines.ps1 compila
# staticcheck y govulncheck DESDE el (go -C tools install), no con
# modulo@version — asi las dependencias van fijadas por nuestro go.sum.
Copy-Item tools dist\ -Recurse -Force
# El corpus de pruebas de las reglas (testdata/) es del CI, no del usuario:
# son fixtures con codigo deliberadamente malo que nadie necesita instalado.
Get-ChildItem dist\rulepacks -Directory -Recurse -Filter testdata | Remove-Item -Recurse -Force

# La firma del rulepack (W3): cada version del paquete lleva manifest.json/.sig
# firmados con la clave de release (DPAPI local, docs/threat-model-rulepack.md).
# Se firma la copia de dist\ DESPUES de podar testdata: el manifiesto describe
# exactamente el arbol que se distribuye. Sin clave el build FALLA: un aviso no
# protege una release y permitirlo fue la via por la que un paquete estable
# podia salir con Verified=false.
# Ademas se genera rulepacks-limpieza.iss: el setup BORRA cada version que trae
# antes de copiarla (Inno copia archivo-por-archivo y fusionaria una version ya
# presente con otro contenido — la divergencia 130-vs-161 reglas medida el
# 2026-08-23 nacio exactamente asi). Las versiones que el paquete NO trae se
# conservan: son el last-known-good implicito.
$limpieza = @(
    "[InstallDelete]",
    '; perfiles WebView efimeros de daemons detenidos antes de actualizar',
    'Type: filesandordirs; Name: "{app}\wv_*"'
)
foreach ($pack in Get-ChildItem dist\rulepacks -Directory) {
    # Con ErrorActionPreference=Stop, el stderr de un comando nativo por 2>&1
    # se vuelve excepcion terminante en PowerShell 5.1 — y "sin clave" NO es
    # un error del build: es el estado dicho en amarillo. Se relaja solo aqui.
    $eapPrevio = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $salidaFirma = & go run .\cmd\codeguard-release sign-rulepack $pack.FullName 2>&1
    $firmado = ($LASTEXITCODE -eq 0)
    $ErrorActionPreference = $eapPrevio
    if (-not $firmado) {
        throw "rulepack $($pack.Name) no se pudo firmar; una distribucion estable nunca sale sin firma:`n$($salidaFirma -join "`n")"
    }
    $salidaFirma | ForEach-Object { Write-Host "    $_" }
    $limpieza += "Type: filesandordirs; Name: `"{app}\rulepacks\$($pack.Name)`""
    $limpieza += "Type: filesandordirs; Name: `"{app}\bin\rulepacks\$($pack.Name)`""
}
Set-Content -Path "dist\rulepacks-limpieza.iss" -Encoding UTF8 -Value ($limpieza -join "`r`n")

# El numero de reglas que el asistente le promete al usuario se CUENTA aqui, no
# se escribe a mano. Estuvo diciendo 112 cuando ya eran 119: el corpus de
# pruebas desperto reglas muertas y nadie se acordo de este texto. Un numero
# copiado a mano en una pantalla de bienvenida es un numero que envejece solo.
$reglas = (Select-String -Path "dist\rulepacks\*\semgrep\*.yaml" -Pattern '^\s*- id:\s*\S+').Count
if ($reglas -lt 1) { throw "no se pudo contar las reglas del rulepack" }
Set-Content -Path "dist\reglas.iss" -Encoding UTF8 -Value "#define MyRuleCount `"$reglas`""

# -- inventario de motores: el instalador dice la VERDAD de lo que instala ----
# El texto de bienvenida llego a prometer "16 motores" con 22 en el producto, y
# a no mencionar CINCO que este paquete no provisiona: el usuario se llevaba
# capas ausentes sin enterarse. Igual que el conteo de reglas, el numero y las
# listas se GENERAN de la fuente -- un dato escrito a mano envejece en silencio.
Write-Host "==> inventario de motores (generado, no escrito a mano)" -ForegroundColor Cyan
$inv = & go run ./cmd/codeguard-release inventario-motores | ConvertFrom-Json
# La FUENTE, no dist/motores.json: esa es una copia que se hace mas abajo, asi
# que leerla aqui daba el inventario de la compilacion ANTERIOR.
$mj  = Get-Content internal/engines/identidad/motores.json -Raw | ConvertFrom-Json
# Lo que ESTE paquete provisiona: binarios verificados por checksum, paquetes
# pip y modulos de Go compilados con nuestro go.sum. El nombre del paquete pip
# no siempre es el del motor (squawk-cli -> squawk).
$provisiona = @()
$provisiona += $mj.motores.PSObject.Properties.Name
$provisiona += $mj.paquetes.pip.PSObject.Properties.Name | ForEach-Object { $_ -replace '-cli$','' }
$provisiona += $mj.paquetes.go.PSObject.Properties.Name
if ($mj.paquetes.winget) {
    $provisiona += ($mj.paquetes.winget.PSObject.Properties.Name | Where-Object { -not $_.StartsWith('_') })
}
$instala = @(); $tuyos = @(); $faltan = @()
foreach ($prop in $inv.PSObject.Properties) {
    if ($provisiona -contains $prop.Name)               { $instala += $prop.Name }
    elseif ($prop.Value -in @('go','dotnet','java',''))  { $tuyos   += $prop.Name }
    else                                                 { $faltan  += $prop.Name }
}
$instala = @($instala | Sort-Object); $tuyos = @($tuyos | Sort-Object); $faltan = @($faltan | Sort-Object)
Write-Host ("    instala {0} - usa lo tuyo {1} - NO instala {2}: {3}" -f $instala.Count, $tuyos.Count, $faltan.Count, ($faltan -join ', '))
$defs = @()
$defs += ('#define MyMotorTotal "{0}"'       -f @($inv.PSObject.Properties).Count)
$defs += ('#define MyMotorInstala "{0}"'     -f $instala.Count)
$defs += ('#define MyMotorTuyos "{0}"'       -f $tuyos.Count)
$defs += ('#define MyMotorFaltan "{0}"'      -f $faltan.Count)
# Frases y no listas: con cero faltantes, «hacen falta aparte: » se leeria
# roto. El texto que ve el usuario se genera entero.
if ($faltan.Count -gt 0) {
    $fraseIss = ('{0} NO los instala este asistente y hacen falta aparte: {1}. Hasta que los instales, esas capas no miran nada, y CodeGuard te lo dice en cada analisis.' -f $faltan.Count, ($faltan -join ', '))
    $fraseTxt = ('NO se instalan y hacen falta aparte: {0}. Hasta que los instales, esas capas no miran nada.' -f ($faltan -join ', '))
} else {
    $fraseIss = 'Ninguno queda fuera: los que necesitan una herramienta propia los trae este asistente.'
    $fraseTxt = 'Ninguno queda fuera: los motores que necesitan una herramienta propia los trae este instalador.'
}
$defs += ('#define MyMotorFaltanFrase "{0}"' -f $fraseIss)
Set-Content -Path "dist/motores.iss" -Encoding UTF8 -Value ($defs -join "`r`n")
# El acuerdo tambien se GENERA, por el mismo motivo que la pantalla de
# bienvenida: llego a prometer 112 reglas cuando ya eran 130. Un numero
# escrito a mano en un documento de consentimiento envejece solo, y ese es el
# peor sitio donde puede pasar: es lo que el usuario acepta.
$plantilla = Get-Content "dist\acuerdo.plantilla.txt" -Raw -Encoding UTF8
if ($plantilla -notmatch "\{REGLAS\}") { throw "acuerdo.plantilla.txt ya no tiene el marcador {REGLAS}: el numero volveria a escribirse a mano" }
if ($plantilla -notmatch "\{FALTAN\}") { throw "acuerdo.plantilla.txt ya no tiene el marcador {FALTAN}: la lista de motores que NO se instalan volveria a escribirse a mano" }
Set-Content -Path "dist\acuerdo.txt" -Encoding UTF8 -NoNewline -Value ((($plantilla -replace "\{REGLAS\}", $reglas)) -replace "\{FALTAN\}", $fraseTxt)
Write-Host "==> el asistente y el acuerdo anunciaran $reglas reglas" -ForegroundColor Cyan

# motores.json: fuente de verdad de hashes, compartida con engines.ps1 y el
# setup. Se copia desde el agente para que nunca diverjan.
Copy-Item internal\engines\identidad\motores.json dist\ -Force

# Python no se resuelve en la maquina del usuario. El release genera el cierre
# transitivo completo desde PyPI oficial, fija cada wheel por SHA-256 y demuestra
# una instalacion sin red antes de dejarlo entrar al setup.
Write-Host "==> wheelhouse Python oficial, cerrado y reproducible" -ForegroundColor Cyan
powershell -NoProfile -ExecutionPolicy Bypass -File dist\build-python-wheelhouse.ps1

Write-Host "==> arte del asistente (estetica DUNA)" -ForegroundColor Cyan
powershell -NoProfile -ExecutionPolicy Bypass -File dist\build-wizard-art.ps1

# ── paquete instalador (CodeGuard-Setup.exe) si Inno Setup esta presente ─────
$iscc = @(
    (Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 6\ISCC.exe"),
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($iscc) {
    Write-Host "==> compilando CodeGuard-Setup.exe" -ForegroundColor Cyan
    & $iscc /Qp dist\setup.iss
    if ($LASTEXITCODE -ne 0) { throw "ISCC fallo con codigo $LASTEXITCODE" }
} else {
    Write-Host "    (sin Inno Setup - no se genera el setup.exe;" -ForegroundColor Yellow
    Write-Host "     instala con: winget install -e --id JRSoftware.InnoSetup)" -ForegroundColor Yellow
}

$size = (Get-ChildItem dist -Recurse -File | Measure-Object Length -Sum).Sum / 1MB
Write-Host ("LISTO: dist\ ({0:N1} MB) - reparte CodeGuard-Setup.exe (o la carpeta con install.ps1)" -f $size) -ForegroundColor Green
