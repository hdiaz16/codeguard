# Construye el bundle Python reproducible y offline de CodeGuard.
#
# Fuente única: paquetes.pip de motores.json. Pip se ejecuta con --isolated y
# el índice oficial explícito; cualquier artefacto resuelto fuera de PyPI rompe
# el build. El requirements.lock contiene TODO el cierre transitivo con SHA-256.
param(
    [string]$Catalogo = (Join-Path $PSScriptRoot "..\internal\engines\identidad\motores.json"),
    [string]$Salida = (Join-Path $PSScriptRoot "python")
)
$ErrorActionPreference = "Stop"

function EjecutarPython([string[]]$Argumentos) {
    $antes = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $salida = & python @Argumentos 2>&1 | Out-String -Width 4096
        $codigo = $LASTEXITCODE
    } finally { $ErrorActionPreference = $antes }
    if ($codigo -ne 0) { throw "python $($Argumentos -join ' ') fallo ($codigo):`n$salida" }
    return $salida
}

$version = (EjecutarPython @("-c", "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")).Trim()
if ($version -ne "3.13") {
    throw "el wheelhouse distribuido se construye con Python 3.13 x64; se encontro $version"
}

$catalogoObj = Get-Content -LiteralPath $Catalogo -Raw | ConvertFrom-Json
$pins = @()
foreach ($p in $catalogoObj.paquetes.pip.PSObject.Properties) {
    $pins += "$($p.Name)==$($p.Value)"
}
$pisosSeguros = @()
foreach ($p in $catalogoObj.paquetes.pip_transitivas_seguras.PSObject.Properties) {
    $pisosSeguros += "$($p.Name)==$($p.Value)"
}
if ($pins.Count -eq 0) { throw "motores.json no contiene paquetes.pip" }

$padre = Split-Path ([System.IO.Path]::GetFullPath($Salida)) -Parent
New-Item -ItemType Directory -Force $padre | Out-Null
$stage = Join-Path $padre (".python-bundle-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force $stage | Out-Null
try {
    $reportePath = Join-Path $stage "resolver-report.json"
    Write-Host "==> resolviendo cierre Python SOLO desde https://pypi.org/simple" -ForegroundColor Cyan
    EjecutarPython (@("-m", "pip", "--isolated", "install", "--dry-run", "--ignore-installed",
        "--only-binary=:all:", "--index-url", "https://pypi.org/simple", "--report", $reportePath,
        "--disable-pip-version-check") + $pins + $pisosSeguros) | Out-Null

    $reporte = Get-Content -LiteralPath $reportePath -Raw | ConvertFrom-Json
    $permitidos = @("files.pythonhosted.org", "pypi.org")
    $bloqueados = @()
    $lineas = @(
        "# GENERADO por dist/build-python-wheelhouse.ps1; no editar.",
        "# Plataforma: Windows x64, CPython 3.13. Instalacion: --require-hashes --no-index.",
        "# Fuente exclusiva: https://pypi.org/simple"
    )
    $procedencia = @()
    $vistos = @{}
    foreach ($item in @($reporte.install)) {
        $uri = [Uri]$item.download_info.url
        if ($permitidos -notcontains $uri.DnsSafeHost.ToLowerInvariant()) {
            $bloqueados += $item.download_info.url
            continue
        }
        $nombre = [regex]::Replace($item.metadata.name.ToLowerInvariant(), "[-_.]+", "-")
        $ver = [string]$item.metadata.version
        $sha = [string]$item.download_info.archive_info.hashes.sha256
        if (-not $sha -or $sha -notmatch '^[0-9a-f]{64}$') {
            throw "$nombre==$ver llego sin SHA-256 verificable desde PyPI"
        }
        if ($vistos.ContainsKey($nombre) -and $vistos[$nombre] -ne $ver) {
            throw "el resolver produjo dos versiones para ${nombre}: $($vistos[$nombre]) y $ver"
        }
        $vistos[$nombre] = $ver
        $lineas += "$nombre==$ver --hash=sha256:$sha"
        $procedencia += [ordered]@{ name=$nombre; version=$ver; url=$item.download_info.url; sha256=$sha }
    }
    if ($bloqueados.Count -gt 0) {
        throw "pip intento resolver fuera de repositorios oficiales:`n  $($bloqueados -join "`n  ")"
    }
    if ($vistos.Count -lt ($pins.Count + $pisosSeguros.Count)) {
        throw "el cierre resuelto tiene solo $($vistos.Count) paquetes para $($pins.Count) motores y $($pisosSeguros.Count) pisos seguros"
    }
    $lineasOrdenadas = @($lineas[0..2]) + @($lineas[3..($lineas.Count-1)] | Sort-Object)
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $lock = Join-Path $stage "requirements.lock"
    [System.IO.File]::WriteAllText($lock, ($lineasOrdenadas -join "`n") + "`n", $utf8)
    [System.IO.File]::WriteAllText((Join-Path $stage "provenance.json"),
        (($procedencia | ConvertTo-Json -Depth 5) + "`n"), $utf8)

    $wheelhouse = Join-Path $stage "wheelhouse"
    New-Item -ItemType Directory -Force $wheelhouse | Out-Null
    Write-Host "==> descargando wheelhouse con hashes obligatorios" -ForegroundColor Cyan
    EjecutarPython @("-m", "pip", "--isolated", "download", "--only-binary=:all:",
        "--index-url", "https://pypi.org/simple", "--require-hashes", "--dest", $wheelhouse,
        "--disable-pip-version-check", "-r", $lock) | Out-Null

    # Prueba del contrato que usara el instalador: sin red y desde cero.
    $smoke = Join-Path $stage ".smoke-venv"
    EjecutarPython @("-m", "venv", $smoke) | Out-Null
    $smokePy = Join-Path $smoke "Scripts\python.exe"
    $antes = $ErrorActionPreference; $ErrorActionPreference = "Continue"
    try {
        $smokeOut = & $smokePy -m pip --isolated install --no-index --find-links $wheelhouse `
            --require-hashes --disable-pip-version-check -r $lock 2>&1 | Out-String -Width 4096
        $smokeCode = $LASTEXITCODE
    } finally { $ErrorActionPreference = $antes }
    if ($smokeCode -ne 0) { throw "el wheelhouse no instala offline ($smokeCode):`n$smokeOut" }
    Remove-Item -LiteralPath $smoke -Recurse -Force
    Remove-Item -LiteralPath $reportePath -Force

    if (Test-Path -LiteralPath $Salida) { Remove-Item -LiteralPath $Salida -Recurse -Force }
    Move-Item -LiteralPath $stage -Destination $Salida
    Write-Host "    bundle Python cerrado: $($vistos.Count) paquetes, solo PyPI oficial" -ForegroundColor Green
} catch {
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
    throw
}
