# Ensambla la carpeta de distribucion lista para repartir a los devs.
# Uso (desde la raiz del repo):  powershell -File dist\build-dist.ps1
$ErrorActionPreference = "Stop"
$repo = Split-Path $PSScriptRoot -Parent
Set-Location $repo

Write-Host "==> compilando binarios optimizados" -ForegroundColor Cyan
go build -trimpath -ldflags "-s -w" -o dist\codeguard.exe .\cmd\codeguard
go build -trimpath -ldflags "-s -w -H windowsgui" -o dist\codeguard-daemon.exe .\cmd\daemon

Write-Host "==> copiando rulepack" -ForegroundColor Cyan
# Borrar antes de copiar: Copy-Item -Force fusiona en vez de reemplazar, asi
# que un rulepack retirado seguiria viajando en el instalador para siempre.
if (Test-Path dist\rulepacks) { Remove-Item dist\rulepacks -Recurse -Force }
Copy-Item rulepacks dist\ -Recurse -Force

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
