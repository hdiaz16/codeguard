# =============================================================================
# CodeGuard - instalacion de motores (compartido por install.ps1 y el setup)
# Descarga gitleaks/trivy verificando cada zip y cada .exe contra el SHA-256
# publicado por sus autores, instala los motores Python (semgrep, squawk,
# ruff, mypy) y los de Java (google-java-format, PMD) cuando hay un JDK.
# La fuente de verdad de versiones y hashes es motores.json - la misma
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

# ── Descarga con reintentos ──────────────────────────────────────────────────
# Reintentar sobre el archivo parcial dejaba un zip corrupto que fallaba la
# verificacion con un mensaje que acusaba al publicador de algo que no hizo.
# Se retira antes de cada reintento. Lo usan los tres instaladores de abajo.
function Descargar([string]$url, [string]$destino) {
    $intento = 0
    while ($true) {
        try { Invoke-WebRequest -Uri $url -OutFile $destino -UseBasicParsing; return }
        catch {
            $intento++
            if ($intento -ge 3) { throw }
            Write-Host "    la descarga fallo ($($_.Exception.Message)); reintento $intento de 2..." -ForegroundColor Yellow
            if (Test-Path $destino) { Remove-Item -LiteralPath $destino -Force -ErrorAction SilentlyContinue }
            Start-Sleep 4
        }
    }
}

# ── La huella de un arbol de archivos ────────────────────────────────────────
# PMD no es un ejecutable sino un arbol de 104 jars: verificar solo el lanzador
# o solo pmd-core daria una sensacion de cobertura que no existe, porque las
# reglas de Java viven en OTRO jar y una regla silenciada no se notaria.
#
# Esta funcion tiene que dar exactamente el mismo resultado que
# identidad.HuellaArbol en Go (internal/engines/identidad/identidad.go): ruta
# relativa con / mas ":" mas el sha del contenido, una linea por archivo,
# ordenadas de forma ordinal, y el sha256 de todo eso en UTF-8 unido por \n.
# Estan atadas a proposito - el instalador verifica lo que el agente volvera a
# comprobar despues con `codeguard engines`- y por eso el formato es lo mas
# simple que se puede escribir dos veces sin equivocarse. Comprobado: las dos
# dan 558a4e74... sobre pmd-bin-7.26.0.
#
# Solo entra el contenido: ni fechas, ni permisos, ni el orden del zip. Es lo
# que hace que dos extracciones del mismo artefacto coincidan en dos maquinas.
function HuellaArbol([string]$raiz) {
    $raiz = [System.IO.Path]::GetFullPath($raiz).TrimEnd('\')
    $prefijo = $raiz + '\'
    $lineas = New-Object System.Collections.Generic.List[string]
    foreach ($f in [System.IO.Directory]::EnumerateFiles($raiz, '*', [System.IO.SearchOption]::AllDirectories)) {
        $lineas.Add($f.Substring($prefijo.Length).Replace('\', '/') + ':' + (Sha256Archivo $f))
    }
    $lineas.Sort([System.StringComparer]::Ordinal)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes([string]::Join("`n", $lineas))
        return (-join ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }))
    } finally { $sha.Dispose() }
}

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
        Descargar $v.url $tmp

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

# ── motores Python (semgrep, squawk, ruff, mypy) ───────────────────────────
Step "Motores Python (semgrep, squawk, ruff, mypy)"
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
#
# Y las VERSIONES van fijadas, leidas de motores.json. Antes era `--upgrade`
# sin version: cada quien instalaba lo que hubiera ese dia y el CI otra cosa,
# asi que dos maquinas del mismo equipo aplicaban reglas distintas y la paridad
# local/CI -la promesa central del producto- dejaba de estar garantizada sin que
# nadie lo notara. Una regla de semgrep cambia de comportamiento entre versiones
# y el commit que pasa aqui falla alla.
$paquetes = (Get-Content $MotoresJson -Raw | ConvertFrom-Json).paquetes
$pins = @()
foreach ($n in $paquetes.pip.PSObject.Properties) { $pins += "$($n.Name)==$($n.Value)" }
Ok "versiones fijadas: $($pins -join ', ')"
$pip = Correr "python" (@("-m", "pip", "install", "--user", "--quiet",
                          "--no-warn-script-location", "--disable-pip-version-check") + $pins)
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
# Blindaje 6: este paso NO puede quedarse mudo.
#
# El asistente muestra en vivo la ultima linea de este log. Los dos motores de
# abajo no se descargan: se COMPILAN desde el fuente, y eso son minutos en los
# que antes no se escribia ni una linea. El usuario veia el asistente detenido
# en el mismo texto y concluia -con razon- que se habia colgado; paso en la
# primera instalacion limpia. Cada motor anuncia lo que va a hacer ANTES de
# empezar, y dice que compila y cuanto puede tardar.
Step "Motores Go (govulncheck, staticcheck)"
$goBin = Get-Command go -ErrorAction SilentlyContinue
if (-not $goBin) {
    Ok "no hay toolchain de Go - se omite (los motores solo aplican a repos Go)"
} else {
    $previoGobin = $env:GOBIN
    $env:GOBIN = $EnginesDir
    try {
        # Versiones fijadas desde motores.json, no @latest: si cada maquina
        # compila lo que haya ese dia, staticcheck estrena un check nuevo y de
        # pronto el CI rechaza lo que en local pasaba. GOSUMDB verifica las
        # sumas del fuente, asi que aqui basta con fijar la version.
        $descripciones = @{
            govulncheck = "analisis de alcanzabilidad de CVEs"
            staticcheck = "analisis semantico sobre la forma SSA"
        }
        $goMotores = @()
        foreach ($nombre in @("govulncheck", "staticcheck")) {
            $spec = $paquetes.go.$nombre
            $goMotores += @{ nombre = $nombre; paquete = "$($spec.modulo)@$($spec.version)";
                             que = $descripciones[$nombre] }
        }
        $n = 0
        foreach ($m in $goMotores) {
            $n++
            Step "compilando $($m.nombre) desde el fuente ($n de $($goMotores.Count)) - $($m.que)"
            Ok "esto tarda uno o dos minutos; no se descarga un binario, se compila"
            $inicio = Get-Date
            $r = Correr "go" @("install", $m.paquete)
            if ($r.Codigo -ne 0) {
                throw "go install $($m.nombre) fallo (codigo $($r.Codigo)):`n$($r.Salida)"
            }
            Ok "$($m.nombre) listo en $([int]((Get-Date) - $inicio).TotalSeconds) s"
        }
    } finally {
        $env:GOBIN = $previoGobin
    }
}

# -- motores Java (google-java-format, PMD) -----------------------------------
# Los dos son descargables con hash fijado, como gitleaks y trivy, pero ninguno
# es un .exe: google-java-format es un JAR suelto y PMD es un ARBOL de jars con
# su lanzador. De ahi los dos instaladores de abajo en vez de Install-Motor.
#
# Los dos se ejecutan con `java`. Sin JDK no se instalan y NO es un error, igual
# que los motores de Go: un repo sin Java no los necesita jamas, y bajar 77 MB
# para dejarlos sin usar seria cobrarle al usuario una descarga que no le sirve.
# El agente, por su parte, solo los busca cuando hay un .java tocado.

# Install-Jar: el artefacto ES el archivo instalado, asi que no hay nada que
# extraer y el hash del zip y el del instalado coinciden. Aun asi se verifica
# DOS veces -lo descargado y lo que quedo en su sitio- porque entre medias hay
# una copia, y una copia a medias (disco lleno) dejaria un jar truncado que
# `java -jar` rechazaria con un error mucho menos claro que este.
function Install-Jar($name) {
    $v = $catalogo.$name.versiones | Select-Object -Last 1
    $destino = Join-Path $EnginesDir $v.instalado
    if (Test-Path $destino) {
        if ((Sha256Archivo $destino) -eq $v.sha256_exe) {
            Ok "$name $($v.version) ya presente y verificado"; return
        }
        Write-Host "    $name presente pero NO coincide con el artefacto publicado" -ForegroundColor Yellow
        Write-Host "    se reemplazara por la version verificada" -ForegroundColor Yellow
    }
    $tmp = Join-Path $env:TEMP "cg-$name.jar"
    if (Test-Path $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    try {
        Step "Descargando $name $($v.version)"
        Descargar $v.url $tmp
        $h = Sha256Archivo $tmp
        if ($h -ne $v.sha256_zip) {
            throw @"
$name no coincide con el checksum publicado por sus autores.
  descargado: $h
  esperado:   $($v.sha256_zip)
La descarga se descarto. Puede ser una version distinta a la que fijamos, un
espejo alterado o una red que modifica el trafico. No se instala nada hasta
aclararlo.
"@
        }
        Ok "${name}: checksum del publicador verificado"
        Copy-Item $tmp $destino -Force
        $h2 = Sha256Archivo $destino
        if ($h2 -ne $v.sha256_exe) {
            Remove-Item -LiteralPath $destino -Force -ErrorAction SilentlyContinue
            throw "${name}: la descarga era correcta pero el jar copiado no coincide ($h2)"
        }
        Ok "$name $((Get-Item $destino).Length / 1MB -as [int]) MB - verificado"
    }
    finally {
        if (Test-Path $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}

# Install-Arbol: el zip trae UNA carpeta raiz (pmd-bin-7.26.0) que se instala
# entera. La segunda verificacion es la huella del arbol extraido, no la de un
# archivo: ver HuellaArbol arriba.
#
# El arbol nuevo se comprueba en el temporal y solo entonces se mueve al sitio.
# Al reves -borrar primero- un checksum roto dejaria al usuario sin el PMD que
# ya tenia, que es peor que quedarse con el viejo.
function Install-Arbol($name) {
    $v = $catalogo.$name.versiones | Select-Object -Last 1
    $destino = Join-Path $EnginesDir $v.instalado
    if (Test-Path $destino) {
        if ((HuellaArbol $destino) -eq $v.sha256_exe) {
            Ok "$name $($v.version) ya presente y verificado"; return
        }
        Write-Host "    $name presente pero su arbol NO coincide con el publicado" -ForegroundColor Yellow
        Write-Host "    se reemplazara por la version verificada" -ForegroundColor Yellow
    }
    LimpiarTemporales $name
    $tmp = Join-Path $env:TEMP "cg-$name.zip"
    $dir = Join-Path $env:TEMP "cg-$name"
    try {
        Step "Descargando $name $($v.version) (~70 MB: son 104 jars entre reglas y parsers)"
        Descargar $v.url $tmp
        $zh = Sha256Archivo $tmp
        if ($zh -ne $v.sha256_zip) {
            throw @"
$name no coincide con el checksum publicado por sus autores.
  descargado: $zh
  esperado:   $($v.sha256_zip)
La descarga se descarto sin abrir. No se instala nada hasta aclararlo.
"@
        }
        Ok "${name}: checksum del publicador verificado"

        ExtraerZip $tmp $dir
        $raiz = Join-Path $dir $v.instalado
        if (-not (Test-Path $raiz)) { throw "el zip de $name no traia la carpeta $($v.instalado)" }

        $h = HuellaArbol $raiz
        if ($h -ne $v.sha256_exe) {
            throw "${name}: el zip era correcto pero el arbol extraido no coincide ($h)"
        }
        if (Test-Path $destino) { Remove-Item -LiteralPath $destino -Recurse -Force }
        Move-Item -LiteralPath $raiz -Destination $destino -Force
        Ok "$name $($v.version) - arbol completo verificado"
    }
    finally { LimpiarTemporales $name }
}

Step "Motores Java (google-java-format, PMD)"
$javaBin = Get-Command java -ErrorAction SilentlyContinue
if (-not $javaBin) {
    Ok "no hay JDK - se omite (los motores solo aplican a repos Java)"
} else {
    Install-Jar "google-java-format"
    Install-Arbol "pmd"
}
