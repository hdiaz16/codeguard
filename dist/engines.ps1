# =============================================================================
# CodeGuard - instalacion de motores (compartido por install.ps1 y el setup)
# Descarga gitleaks/trivy verificando cada zip y cada .exe contra el SHA-256
# publicado por sus autores, e instala los motores Python (semgrep, squawk,
# ruff). La fuente de verdad de versiones y hashes es motores.json - la misma
# que embebe el agente (internal/engines/identidad/motores.json); build-dist
# la copia aqui para que nunca diverjan.
# Uso:  powershell -ExecutionPolicy Bypass -File engines.ps1 [-SkipTrivy]
# =============================================================================
param(
    [string]$EnginesDir = (Join-Path $env:LOCALAPPDATA "CodeGuard\engines"),
    [string]$MotoresJson = (Join-Path $PSScriptRoot "motores.json"),
    [switch]$SkipTrivy   # trivy pesa ~60 MB; opcional en la primera ola
)
$ErrorActionPreference = "Stop"

# ── Blindaje 1: el PATH de modulos envenenado ────────────────────────────────
# PowerShell 7 inyecta SUS rutas de modulos en el PSModulePath de todo el
# sistema. Cuando Windows PowerShell 5.1 hereda esa variable —y la hereda
# siempre que lo lanza un proceso hijo, como hace el instalador— carga el
# Microsoft.PowerShell.Utility de la 7 dentro del host 5.1, y cmdlets enteros
# dejan de existir. Get-FileHash es uno de ellos.
#
# Sintoma real en la primera instalacion con el paquete: "Get-FileHash no se
# reconoce", justo en la linea que verifica el checksum de gitleaks. Invoke-
# WebRequest si funcionaba, asi que parecia un entorno sano. Le pasara a
# cualquiera con PowerShell 7 instalado, que en una maquina de desarrollo es
# lo normal.
$env:PSModulePath = @(
    (Join-Path $env:ProgramFiles "WindowsPowerShell\Modules"),
    (Join-Path $env:SystemRoot "system32\WindowsPowerShell\v1.0\Modules")
) -join ';'

function Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Ok($msg)   { Write-Host "    $msg" -ForegroundColor Green }

# ── Blindaje 2: el hash no depende de ningun modulo ──────────────────────────
# Aunque arriba se fije el PSModulePath, la verificacion de checksum es la
# unica linea de defensa contra un binario alterado: no puede depender de que
# un modulo resuelva bien. .NET siempre esta.
function Sha256Archivo([string]$ruta) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $fs = [System.IO.File]::OpenRead($ruta)
        try { return (-join ($sha.ComputeHash($fs) | ForEach-Object { $_.ToString('x2') })) }
        finally { $fs.Dispose() }
    } finally { $sha.Dispose() }
}

# ── Blindaje 3: descomprimir sin Expand-Archive ──────────────────────────────
# Expand-Archive vive en Microsoft.PowerShell.Archive y le afecta el mismo
# envenenamiento que a Get-FileHash.
Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
function ExtraerZip([string]$zip, [string]$destino) {
    if (Test-Path $destino) { Remove-Item -LiteralPath $destino -Recurse -Force }
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zip, $destino)
}

# ── Blindaje 4: temporales de una corrida anterior ───────────────────────────
# Un setup cancelado a la mitad deja el zip a medias en %TEMP%. Reutilizarlo
# hace fallar la verificacion con un mensaje de "checksum no coincide" que
# acusa al publicador de algo que no hizo.
function LimpiarTemporales([string]$nombre) {
    foreach ($p in @((Join-Path $env:TEMP "cg-$nombre.zip"), (Join-Path $env:TEMP "cg-$nombre"))) {
        if (Test-Path $p) { Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

New-Item -ItemType Directory -Force $EnginesDir | Out-Null
$catalogo = (Get-Content $MotoresJson -Raw | ConvertFrom-Json).motores

# ── motores descargables (gitleaks, trivy) con hash FIJADO ───────────────────
# Se verifica el zip ANTES de extraerlo y se aborta si no coincide: un binario
# alterado en transito o en el espejo no llega a instalarse.
function Install-Motor($name) {
    $v = $catalogo.$name.versiones | Select-Object -Last 1
    $exe = Join-Path $EnginesDir "$name.exe"
    if (Test-Path $exe) {
        # Presente no basta: tiene que ser el binario publicado. Si coincide,
        # una actualizacion no vuelve a descargar nada.
        if ((Sha256Archivo $exe) -eq $v.sha256_exe) {
            Ok "$name $($v.version) ya presente y verificado"; return
        }
        Write-Host "    $name presente pero NO coincide con el binario publicado" -ForegroundColor Yellow
        Write-Host "    se reemplazara por la version verificada" -ForegroundColor Yellow
        # OJO: no se borra todavia — el reemplazo se instala solo cuando la
        # descarga nueva ya esta verificada. Un fallo a medias no deja hueco.
    }

    # Restos de un setup cancelado a la mitad: se van ANTES de descargar.
    LimpiarTemporales $name
    $tmp = Join-Path $env:TEMP "cg-$name.zip"
    $dir = Join-Path $env:TEMP "cg-$name"
    try {
        Step "Descargando $name $($v.version)"
        $intento = 0
        while ($true) {
            try { Invoke-WebRequest -Uri $v.url -OutFile $tmp -UseBasicParsing; break }
            catch {
                $intento++
                if ($intento -ge 3) { throw }
                Write-Host "    la descarga fallo ($($_.Exception.Message)); reintento $intento de 2..." -ForegroundColor Yellow
                # Una descarga a medias no se reintenta encima: se retira.
                if (Test-Path $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
                Start-Sleep 4
            }
        }

        $zh = Sha256Archivo $tmp
        if ($zh -ne $v.sha256_zip) {
            throw @"
$name no coincide con el checksum publicado por sus autores.
  descargado: $zh
  esperado:   $($v.sha256_zip)
La descarga se descarto sin abrir. Puede ser una version distinta a la que
fijamos, un espejo alterado o una red que modifica el trafico. No se instala
nada hasta aclararlo.
"@
        }
        Ok "${name}: checksum del publicador verificado"

        ExtraerZip $tmp $dir
        $found = Get-ChildItem $dir -Recurse -Filter "$name.exe" | Select-Object -First 1
        if (-not $found) { throw "$name.exe no venia en el zip" }

        # Verificar el extraido ANTES de tocar el destino: el motor viejo (si lo
        # habia) sigue sano hasta que el nuevo este probado.
        $h = Sha256Archivo $found.FullName
        if ($h -ne $v.sha256_exe) {
            throw "${name}: el zip era correcto pero el .exe extraido no coincide ($h)"
        }
        Copy-Item $found.FullName $exe -Force
        Ok "$name $((Get-Item $exe).Length / 1MB -as [int]) MB - verificado"
    }
    finally {
        # Pase lo que pase —exito, checksum roto, red caida— los temporales no
        # se quedan. Antes solo se limpiaban en los caminos felices, y un fallo
        # dejaba el zip a medias para envenenar el siguiente intento.
        LimpiarTemporales $name
    }
}

Install-Motor "gitleaks"
if (-not $SkipTrivy) { Install-Motor "trivy" }

# ── Blindaje 5: los comandos nativos no son excepciones ──────────────────────
# Con $ErrorActionPreference = "Stop" y la salida redirigida a un archivo —que
# es como lo corre el instalador— PowerShell convierte CUALQUIER linea que un
# .exe escriba en stderr en un error terminante. pip escribe ahi sus avisos
# normales ("script X is not on PATH"), asi que el setup moria por catorce
# advertencias inofensivas mientras la instalacion iba perfecta.
#
# Correr devuelve la salida y el codigo real; el que manda es $LASTEXITCODE,
# que es lo unico que de verdad dice si el programa fallo.
function Correr([string]$exe, [string[]]$argumentos) {
    $previo = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $salida = & $exe @argumentos 2>&1 | Out-String
        return [pscustomobject]@{ Codigo = $LASTEXITCODE; Salida = $salida }
    } finally { $ErrorActionPreference = $previo }
}

# ── motores Python (semgrep, squawk, ruff) ───────────────────────────────────
Step "Motores Python (semgrep, squawk, ruff)"
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) {
    Step "Python no encontrado - instalando via winget"
    $w = Correr "winget" @("install", "-e", "--id", "Python.Python.3.13", "--silent",
                           "--accept-package-agreements", "--accept-source-agreements")
    if ($w.Codigo -ne 0) {
        throw "no se pudo instalar Python automaticamente (winget devolvio $($w.Codigo)).`n" +
              "Instalalo desde python.org y vuelve a ejecutar: codeguard repair`n$($w.Salida)"
    }
    $env:PATH = [Environment]::GetEnvironmentVariable("PATH", "User") + ";" + [Environment]::GetEnvironmentVariable("PATH", "Machine")
}

# --no-warn-script-location y --disable-pip-version-check: no son cosmetica.
# Son las dos fuentes de ruido en stderr que hacian caer al instalador, y
# ademas las que hacian que una instalacion correcta pareciera llena de fallos.
$pip = Correr "python" @("-m", "pip", "install", "--user", "--quiet",
                         "--no-warn-script-location", "--disable-pip-version-check",
                         "--upgrade", "semgrep", "squawk-cli", "ruff")
if ($pip.Codigo -ne 0) {
    throw "pip fallo (codigo $($pip.Codigo)):`n$($pip.Salida)"
}

$rutaScripts = Correr "python" @("-c", "import sysconfig; print(sysconfig.get_path('scripts', 'nt_user'))")
if ($rutaScripts.Codigo -ne 0) {
    throw "no se pudo averiguar donde instalo pip los scripts:`n$($rutaScripts.Salida)"
}
$pyScripts = $rutaScripts.Salida.Trim()
Ok "instalados en $pyScripts"

# Los scripts de Python van al PATH aqui mismo: es el unico paso que conoce
# la ruta (depende de la version de Python del usuario).
$userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($userPath -notlike "*$pyScripts*") {
    [Environment]::SetEnvironmentVariable("PATH", "$pyScripts;$userPath", "User")
    Ok "PATH de usuario: + $pyScripts"
}

# ── motores Go (govulncheck, staticcheck) ────────────────────────────────────
# govulncheck y staticcheck no entran en motores.json: los construye el
# toolchain de Go del usuario desde el fuente y GOSUMDB verifica las sumas,
# igual que pip verifica los motores de Python. Se instalan en $EnginesDir
# (via GOBIN) para que se encuentren por el mismo PATH que gitleaks y trivy.
#
# Sin toolchain de Go no se instalan y no es un error: un repo Go siempre
# viene con su toolchain, y en un repo sin Go estos motores jamas aplican.
Step "Motores Go (govulncheck, staticcheck)"
$goBin = Get-Command go -ErrorAction SilentlyContinue
if (-not $goBin) {
    Ok "no hay toolchain de Go - se omite (los motores solo aplican a repos Go)"
} else {
    $previoGobin = $env:GOBIN
    $env:GOBIN = $EnginesDir
    try {
        $gv = Correr "go" @("install", "golang.org/x/vuln/cmd/govulncheck@latest")
        if ($gv.Codigo -ne 0) {
            throw "go install govulncheck fallo (codigo $($gv.Codigo)):`n$($gv.Salida)"
        }
        Ok "govulncheck instalado en $EnginesDir"
        $sc = Correr "go" @("install", "honnef.co/go/tools/cmd/staticcheck@latest")
        if ($sc.Codigo -ne 0) {
            throw "go install staticcheck fallo (codigo $($sc.Codigo)):`n$($sc.Salida)"
        }
        Ok "staticcheck instalado en $EnginesDir"
    } finally {
        $env:GOBIN = $previoGobin
    }
}
