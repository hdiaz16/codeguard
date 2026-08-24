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
Write-Host "==> compilando binarios optimizados (v$version, ventana dual de huellas v1 hasta $sunsetV1)" -ForegroundColor Cyan
go build -trimpath -ldflags "-s -w -X main.version=$version -X codeguard/internal/finding.SunsetV1=$sunsetV1" -o dist\codeguard.exe .\cmd\codeguard
go build -trimpath -ldflags "-s -w -H windowsgui -X main.version=$version -X codeguard/internal/finding.SunsetV1=$sunsetV1" -o dist\codeguard-daemon.exe .\cmd\daemon

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
# exactamente el arbol que se distribuye. Sin clave, el paquete sale SIN FIRMAR
# y se DICE en amarillo — un binario sin claves embebidas no exige firma, pero
# el estado objetivo es release firmado + binario con la publica embebida.
# Ademas se genera rulepacks-limpieza.iss: el setup BORRA cada version que trae
# antes de copiarla (Inno copia archivo-por-archivo y fusionaria una version ya
# presente con otro contenido — la divergencia 130-vs-161 reglas medida el
# 2026-08-23 nacio exactamente asi). Las versiones que el paquete NO trae se
# conservan: son el last-known-good implicito.
$limpieza = @("[InstallDelete]")
foreach ($pack in Get-ChildItem dist\rulepacks -Directory) {
    # Con ErrorActionPreference=Stop, el stderr de un comando nativo por 2>&1
    # se vuelve excepcion terminante en PowerShell 5.1 — y "sin clave" NO es
    # un error del build: es el estado dicho en amarillo. Se relaja solo aqui.
    $eapPrevio = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $salidaFirma = & go run .\cmd\codeguard-release sign-rulepack $pack.FullName 2>&1
    $firmado = ($LASTEXITCODE -eq 0)
    $ErrorActionPreference = $eapPrevio
    if ($firmado) {
        $salidaFirma | ForEach-Object { Write-Host "    $_" }
    } else {
        Write-Host "    AVISO: rulepack $($pack.Name) SIN FIRMAR (genera tu clave con: go run .\cmd\codeguard-release keygen)" -ForegroundColor Yellow
    }
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

# El acuerdo tambien se GENERA, por el mismo motivo que la pantalla de
# bienvenida: llego a prometer 112 reglas cuando ya eran 130. Un numero
# escrito a mano en un documento de consentimiento envejece solo, y ese es el
# peor sitio donde puede pasar: es lo que el usuario acepta.
$plantilla = Get-Content "dist\acuerdo.plantilla.txt" -Raw -Encoding UTF8
if ($plantilla -notmatch "\{REGLAS\}") { throw "acuerdo.plantilla.txt ya no tiene el marcador {REGLAS}: el numero volveria a escribirse a mano" }
Set-Content -Path "dist\acuerdo.txt" -Encoding UTF8 -NoNewline -Value ($plantilla -replace "\{REGLAS\}", $reglas)
Write-Host "==> el asistente y el acuerdo anunciaran $reglas reglas" -ForegroundColor Cyan

# motores.json: fuente de verdad de hashes, compartida con engines.ps1 y el
# setup. Se copia desde el agente para que nunca diverjan.
Copy-Item internal\engines\identidad\motores.json dist\ -Force

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
