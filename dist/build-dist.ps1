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

Write-Host "==> compilando binarios optimizados (v$version)" -ForegroundColor Cyan
go build -trimpath -ldflags "-s -w -X main.version=$version" -o dist\codeguard.exe .\cmd\codeguard
go build -trimpath -ldflags "-s -w -H windowsgui -X main.version=$version" -o dist\codeguard-daemon.exe .\cmd\daemon

Write-Host "==> copiando rulepack" -ForegroundColor Cyan
# Borrar antes de copiar: Copy-Item -Force fusiona en vez de reemplazar, asi
# que un rulepack retirado seguiria viajando en el instalador para siempre.
if (Test-Path dist\rulepacks) { Remove-Item dist\rulepacks -Recurse -Force }
Copy-Item rulepacks dist\ -Recurse -Force
# El corpus de pruebas de las reglas (testdata/) es del CI, no del usuario:
# son fixtures con codigo deliberadamente malo que nadie necesita instalado.
Get-ChildItem dist\rulepacks -Directory -Recurse -Filter testdata | Remove-Item -Recurse -Force

# El numero de reglas que el asistente le promete al usuario se CUENTA aqui, no
# se escribe a mano. Estuvo diciendo 112 cuando ya eran 119: el corpus de
# pruebas desperto reglas muertas y nadie se acordo de este texto. Un numero
# copiado a mano en una pantalla de bienvenida es un numero que envejece solo.
$reglas = (Select-String -Path "dist\rulepacks\*\semgrep\*.yaml" -Pattern '^\s*- id:\s*\S+').Count
if ($reglas -lt 1) { throw "no se pudo contar las reglas del rulepack" }
Set-Content -Path "dist\reglas.iss" -Encoding UTF8 -Value "#define MyRuleCount `"$reglas`""
Write-Host "==> el asistente anunciara $reglas reglas" -ForegroundColor Cyan

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
