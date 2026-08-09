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

$size = (Get-ChildItem dist -Recurse -File | Measure-Object Length -Sum).Sum / 1MB
Write-Host ("LISTO: dist\ ({0:N1} MB) - reparte la carpeta y corre install.ps1" -f $size) -ForegroundColor Green
