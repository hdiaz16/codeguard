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
    # Los zips a medias viven aquí y NO en %TEMP%: sobreviven al asistente para
    # que un reintento reanude en vez de repetir la descarga entera.
    [string]$DescargasDir = (Join-Path $env:LOCALAPPDATA "CodeGuard\descargas"),
    [string]$MotoresJson = (Join-Path $PSScriptRoot "motores.json"),
    # El asistente mueve su barra leyendo ESTE archivo, no el log. Una linea
    # por cambio de estado de un motor (ver «El contrato CGP» mas abajo).
    # Vacio = nadie escucha, y no se escribe nada: install.ps1 y `codeguard
    # repair` llaman a este script sin asistente delante.
    [string]$ProgressFile = "",
    # Donde se deja el parte de lo que falto. Parametrizado por la misma razon
    # que el de progreso: dos instalaciones a la vez no pueden compartirlo.
    [string]$FaltanFile = (Join-Path $env:TEMP "codeguard-motores.faltan"),
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


# ComprobarQueArranca ejecuta el motor recien instalado para ver si CORRE, no
# solo si su hash coincide.
#
# El hash responde "es el artefacto que publico su autor". No responde "esta
# maquina puede ejecutarlo", y son preguntas distintas: google-java-format
# 1.36.1 esta compilado para Java 21 (version de clase 65) y en una maquina con
# JDK 17 (61) muere con UnsupportedClassVersionError. La instalacion lo daba por
# bueno, `codeguard engines` lo listaba como "coincide con el binario publicado"
# —cierto y a la vez enganoso— y el formateo de Java quedaba degradado de forma
# PERMANENTE, sin que nada dijera por que ni que no se iba a arreglar solo.
#
# No aborta la instalacion: un motor que no arranca es un problema real pero no
# invalida los demas, y el pipeline ya sabe degradar una capa ausente. Lo que
# hace es DECIRLO, con la causa, en el momento en que se puede actuar.
function ComprobarQueArranca([string]$name, [string]$ruta, [switch]$EsBat) {
    $jdk = Get-Command java -ErrorAction SilentlyContinue
    if (-not $jdk) {
        Write-Host "    $name : no hay java en el PATH, no se pudo comprobar que arranque" -ForegroundColor Yellow
        return
    }
    # $ErrorActionPreference="Stop" esta activo arriba, y con el un exe que
    # escribe en stderr se convierte en un NativeCommandError ruidoso de
    # PowerShell: la traza tapaba justo el mensaje que esta funcion existe para
    # dar. Se baja a "Continue" solo aqui, y stderr se une a stdout.
    $antes = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    # -Width 4096 no es adorno: Out-String recorta a las COLUMNAS DEL HOST, y la
    # consola oculta que lanza el asistente tiene 80. El mensaje del JVM ocupa
    # ~220 caracteres, asi que se cortaba justo antes de la parte que dice la
    # version de clase — medido: con 80/100/120 el diagnostico no salia y el
    # usuario solo leia "LinkageError occurred", que no dice que hacer.
    # Se ensucia $LASTEXITCODE a proposito ANTES de lanzar: si el lanzamiento
    # falla y entra el catch, PowerShell CONSERVA el codigo del ultimo comando
    # nativo anterior — y lo que precede aqui es curl/go/pip, que dejan 0 al ir
    # bien. Sin esto, un motor que nunca llego a correr se anunciaba como
    # "arranca": el falso OK que esta funcion existe para evitar.
    $global:LASTEXITCODE = -1
    try {
        if ($EsBat) { $salida = (& $ruta --version 2>&1 | Out-String -Width 4096) }
        else        { $salida = (& java -jar $ruta --version 2>&1 | Out-String -Width 4096) }
    }
    catch { $salida = "$($_.Exception.Message)" }
    finally { $ErrorActionPreference = $antes }
    if ($LASTEXITCODE -eq 0) {
        Ok "${name}: arranca con el java de esta maquina"
        return
    }
    Write-Host "    $name : el artefacto es el publicado, pero NO ARRANCA en esta maquina" -ForegroundColor Yellow
    # Los dos numeros se buscan POR SEPARADO: con un solo patron y `.*?` en
    # medio no casaba, porque el punto no cruza saltos de linea y la traza de
    # Java los reparte en lineas distintas segun quien la formatee.
    $necesitaClase = if ($salida -match 'class file version (\d+)\.') { [int]$Matches[1] } else { 0 }
    $tieneClase    = if ($salida -match 'up to (\d+)\.')              { [int]$Matches[1] } else { 0 }
    # -ge 45 y no -gt 0: 45 es Java 1.1, la primera version de clase que existe.
    # Con -gt 0 una cifra basura del mensaje podia imprimir un "JDK -12".
    if ($necesitaClase -ge 45 -and $tieneClase -ge 45) {
        # La tabla de versiones de clase de Java: 61 = 17, 65 = 21.
        # Version de clase -> version de JDK: 45 = Java 1.1, asi que la resta es
        # 44 (61 -> 17, 65 -> 21). Comprobado contra las dos que se ven aqui.
        $necesita = $necesitaClase - 44
        $tiene    = $tieneClase - 44
        Write-Host "      necesita JDK $necesita y esta maquina tiene JDK $tiene" -ForegroundColor Yellow
        Write-Host "      instala un JDK $necesita o mas nuevo; hasta entonces esta capa quedara degradada" -ForegroundColor Yellow
    } else {
        Write-Host "      $(($salida -split "`n")[0])" -ForegroundColor Yellow
    }
}

New-Item -ItemType Directory -Force $EnginesDir | Out-Null
$catalogo = (Get-Content $MotoresJson -Raw | ConvertFrom-Json).motores

# ── El contrato CGP: progreso que no se inventa ──────────────────────────────
#
# La barra del asistente pertenecia a la fase de COPIA de Inno, que dura
# segundos. El trabajo real —descargar 130 MB y COMPILAR cuatro motores de Go—
# ocurre despues, en ssPostInstall, con la barra ya llena y quieta. Podia estar
# asi una hora. Para el usuario eso no es una barra de progreso: es una barra
# verde.
#
# Raspar el log para deducir el progreso NO sirve, y no es opinion: los pines
# de pip se instalan en UN solo comando para cinco motores, los motores ya
# presentes vuelven por un camino distinto, los de Go y Java se OMITEN enteros
# cuando falta su toolchain —y entonces no escriben ninguna linea de exito— y
# un motor caido escribe un aviso, no un «Ok». Contar lineas «Ok» daria una
# barra que se queda corta justo en las maquinas donde mas se omite.
#
# Asi que el progreso se declara aparte, en un archivo propio y en ASCII:
#
#     CGP|<seq>|<hechos>|<total>|<motor>|<estado>
#
# estados: working | ok | already-present | skipped | failed | not-attempted
#
# Reglas del contrato, y las tres importan:
#
#  1. «working» NO incrementa. Anuncia en que se esta, nada mas.
#  2. Cada motor tiene EXACTAMENTE UN estado terminal, y el primero manda. Por
#     eso el incremento vive aqui y no en cada sitio que llama: los caminos de
#     exito y de fallo se cruzan (Install-Motor termina bien e Intentar no
#     entra al catch; Install-Motor lanza e Intentar apunta el fallo) y contar
#     a mano acabaria contando dos veces o ninguna.
#  3. «hechos» significa MOTOR RESUELTO, no motor instalado. Un motor omitido
#     por falta de JDK o uno que fallo estan resueltos: ya no van a pasar nada
#     mas. Si no contaran, la barra se quedaria a medias en una maquina sin
#     Java afirmando que sigue trabajando.
#
# El total sale del MISMO inventario que cuenta build-dist.ps1 para escribir
# MyMotorInstala en motores.iss (motores + pip + go + winget). El asistente
# compara los dos numeros: si divergen, no pinta porcentaje — prefiere no decir
# nada a decir una fraccion falsa.
$script:CGPSeq = 0
$script:CGPHechos = 0
$script:CGPTerminados = @{}
$script:CGPUnidades = @()
$inventario = Get-Content $MotoresJson -Raw | ConvertFrom-Json
$script:CGPUnidades += $inventario.motores.PSObject.Properties.Name
$script:CGPUnidades += $inventario.paquetes.pip.PSObject.Properties.Name | ForEach-Object { $_ -replace '-cli$','' }
$script:CGPUnidades += $inventario.paquetes.go.PSObject.Properties.Name
if ($inventario.paquetes.winget) {
    $script:CGPUnidades += ($inventario.paquetes.winget.PSObject.Properties.Name | Where-Object { -not $_.StartsWith('_') })
}
$script:CGPTotal = $script:CGPUnidades.Count

function CGP([string]$motor, [string]$estado) {
    if (-not $ProgressFile) { return }
    if ($estado -ne 'working') {
        if ($script:CGPTerminados.ContainsKey($motor)) { return }
        $script:CGPTerminados[$motor] = $estado
        $script:CGPHechos++
    }
    $script:CGPSeq++
    # Add-Content abre y cierra en cada linea: lo escrito queda en disco al
    # instante y el asistente —que lee cada 250 ms— lo ve. Un Out-File abierto
    # durante toda la corrida podria no haber vaciado su bufer todavia.
    #
    # Y va envuelto en try/catch VACIO a proposito, que es de las pocas veces
    # que eso se justifica: $ErrorActionPreference vale "Stop" en este script,
    # el asistente esta leyendo el mismo archivo, y una colision de acceso
    # momentanea abortaria la instalacion entera por no poder pintar una barra.
    # El progreso es cosmetico; los motores no.
    try {
        Add-Content -LiteralPath $ProgressFile -Encoding ASCII -Value (
            "CGP|{0}|{1}|{2}|{3}|{4}" -f $script:CGPSeq, $script:CGPHechos, $script:CGPTotal, $motor, $estado)
    } catch { }
}

# CGPCerrarPendientes declara lo que nunca se intento. Se llama al final del
# camino sano: si el script muere antes, el contador se queda POR DEBAJO del
# total y el asistente lo dice tal cual. Rellenar la barra hasta el final
# fingiendo que se procesaron seria justo la mentira que esto viene a quitar.
function CGPCerrarPendientes {
    foreach ($u in $script:CGPUnidades) {
        if (-not $script:CGPTerminados.ContainsKey($u)) { CGP $u 'not-attempted' }
    }
}

# ── Descarga que REANUDA ─────────────────────────────────────────────────────
# La version anterior reintentaba desde CERO y borraba el parcial entre
# intentos. Con eso, una red que corta a mitad de archivo no falla: es
# IMPOSIBLE que termine nunca, por muchos reintentos que se le den.
#
# Pasó, y costó una instalación entera: en una red corporativa el zip de trivy
# (60 MB) bajaba a 8-35 KB/s y se cortaba; cada reintento volvía a empezar, y a
# la tercera el script se rindió con un archivo truncado que —claro— no cuadraba
# con el checksum del publicador. El mensaje acusaba a la cadena de suministro
# de lo que hacía la red.
#
# Ahora se reanuda con curl (-C -), que viene en Windows 10+ y sabe pedir "desde
# el byte N". Y el parcial se GUARDA entre corridas, en vez de tirarse: si el
# asistente se cierra con 28 de 60 MB bajados, el siguiente intento sigue desde
# ahí en lugar de repetir media hora de descarga.
#
# Devuelve $true si el archivo llegó COMPLETO, $false si se cortó. Quien llama
# distingue las dos cosas, que no son iguales: un archivo cortado se reanuda; un
# archivo completo que no cuadra con su hash es un problema de integridad y no
# se reintenta jamás — se aborta y se dice por qué.
function DescargarConReanudacion([string]$url, [string]$destino) {
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if (-not $curl) {
        # Sin curl no hay reanudación posible: se hace lo de antes, que al menos
        # funciona en redes sanas.
        try { Invoke-WebRequest -Uri $url -OutFile $destino -UseBasicParsing; return $true }
        catch { return $false }
    }

    $antes = if (Test-Path $destino) { (Get-Item $destino).Length } else { 0 }
    if ($antes -gt 0) {
        Write-Host ("    reanudando desde {0:N1} MB ya descargados" -f ($antes / 1MB)) -ForegroundColor DarkGray
    }

    # Se baja A TRAMOS de 45 s en vez de en una sola llamada larga, y por dos
    # motivos que costaron una instalación cada uno:
    #
    #  1. El asistente muestra la ÚLTIMA LÍNEA del log como señal de vida. Una
    #     descarga de 40 minutos no escribe ninguna, así que parecía colgado —y
    #     el usuario cerraba el asistente creyendo que estaba muerto—. Cada
    #     tramo imprime cuánto lleva, y la ventana se mueve.
    #  2. Cortar cada 45 s y reanudar es más robusto que una conexión larga en
    #     una red que las mata: se retoma desde el byte exacto.
    #
    # Se para cuando el archivo llega entero, o cuando TRES tramos seguidos no
    # avanzan ni un byte — ahí ya no es lentitud, es que no hay descarga.
    $sinAvanzar = 0
    for ($tramo = 1; $tramo -le 90; $tramo++) {
        $inicio = if (Test-Path $destino) { (Get-Item $destino).Length } else { 0 }

        # --fail para que un 404 o un 403 no acabe guardado como si fuera el zip.
        & $curl.Source -sL --fail --retry 2 --retry-all-errors --retry-delay 2 `
            -C - --connect-timeout 20 --max-time 45 -o $destino $url 2>$null
        if ($LASTEXITCODE -eq 0) { return $true }

        $ahora = if (Test-Path $destino) { (Get-Item $destino).Length } else { 0 }
        $kbs = [math]::Round(($ahora - $inicio) / 1KB / 45)
        if ($ahora -le $inicio) {
            $sinAvanzar++
            Write-Host ("    sin avance ({0} de 3) en {1:N1} MB" -f $sinAvanzar, ($ahora / 1MB)) -ForegroundColor Yellow
            if ($sinAvanzar -ge 3) { return $false }
        } else {
            $sinAvanzar = 0
            Write-Host ("    bajando: {0:N1} MB ({1} KB/s)" -f ($ahora / 1MB), $kbs)
        }
    }
    Write-Host "    la descarga no terminó en el tiempo previsto" -ForegroundColor Yellow
    return $false
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
            Ok "$name $($v.version) ya presente y verificado"
            CGP $name 'already-present'
            return
        }
        Write-Host "    $name presente pero NO coincide con el binario publicado" -ForegroundColor Yellow
        Write-Host "    se reemplazara por la version verificada" -ForegroundColor Yellow
        # OJO: no se borra todavia — el reemplazo se instala solo cuando la
        # descarga nueva ya esta verificada. Un fallo a medias no deja hueco.
    }

    # El zip a medias vive FUERA de %TEMP%, en un caché propio, y sobrevive a
    # un asistente cerrado: es lo que permite reanudar en vez de repetir.
    New-Item -ItemType Directory -Force $DescargasDir | Out-Null
    $tmp = Join-Path $DescargasDir "$name-$($v.version).zip"
    $dir = Join-Path $env:TEMP "cg-$name"
    if (Test-Path $dir) { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
    try {
        Step "Descargando $name $($v.version)"

        # Hasta seis vueltas: cada una reanuda donde quedó la anterior. Se sale
        # en cuanto el archivo llega ENTERO — el hash se comprueba después,
        # porque sobre un archivo incompleto no significa nada.
        # Seis vueltas como mucho, pero se corta antes si una vuelta ENTERA no
        # consiguió bajar ni un byte: ahí no hay lentitud que esperar, hay una
        # red que no responde, y insistir sólo alarga la agonía.
        #
        # Medido: sin esta salida, un endpoint muerto daba 18 intentos y más de
        # dos minutos y medio de "sin avance" — desde el asistente, indistinguible
        # de un cuelgue.
        $completo = $false
        for ($vuelta = 1; $vuelta -le 6 -and -not $completo; $vuelta++) {
            $antes = if (Test-Path $tmp) { (Get-Item $tmp).Length } else { 0 }
            $completo = DescargarConReanudacion $v.url $tmp
            if ($completo) { break }
            $despues = if (Test-Path $tmp) { (Get-Item $tmp).Length } else { 0 }
            if ($despues -le $antes) {
                Write-Host "    la descarga no avanza: se deja de insistir" -ForegroundColor Yellow
                break
            }
            Start-Sleep 3
        }
        if (-not $completo) {
            throw @"
${name}: la red no dejó terminar la descarga.
Lo bajado se CONSERVA en $tmp, así que reintentar sigue desde ahí y no
empieza de cero:  codeguard repair
"@
        }

        $zh = Sha256Archivo $tmp
        if ($zh -ne $v.sha256_zip) {
            # Archivo COMPLETO que no cuadra: esto ya no es la red cortando, y
            # no se reintenta. Se borra para que el intento siguiente no herede
            # un parcial envenenado, y se dice exactamente qué pasó.
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
            throw @"
$name no coincide con el checksum publicado por sus autores.
  descargado: $zh
  esperado:   $($v.sha256_zip)
La descarga llegó ENTERA y aun así no cuadra, así que no es un corte de red: es
una version distinta a la que fijamos, un espejo alterado o una red que modifica
el trafico. No se instala nada hasta aclararlo.
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
        CGP $name 'ok'
        # Ya instalado y verificado: el zip deja de hacer falta. Sólo aquí — en
        # cualquier otro camino se conserva para poder reanudar.
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
    finally {
        if (Test-Path $dir) { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

# ── Que un motor caiga no puede llevarse a los demás ──────────────────────────
# Antes, trivy fallando abortaba el script entero y govulncheck y staticcheck
# —que van después y no tienen nada que ver— no llegaban a instalarse nunca. Una
# instalación quedaba sin TRES compuertas por culpa de una descarga.
#
# El catálogo ya dice cuáles son críticos: gitleaks lo es (la compuerta de
# secretos es fail-closed, sin él no hay producto) y ahí sí se aborta. Los demás
# se apuntan y se sigue, y al final se dice qué falta y qué deja de revisarse.
$script:Faltantes = @()

function Intentar([string]$que, [scriptblock]$accion, [string]$sinEsto) {
    CGP $que 'working'
    try { & $accion }
    catch {
        $critico = $catalogo.$que.critico -eq $true
        if ($critico) { throw }   # gitleaks: sin él no se sigue
        Write-Host "    $que NO quedó instalado" -ForegroundColor Yellow
        Write-Host ("    " + ($_.Exception.Message -split "`n")[0]) -ForegroundColor Yellow
        $script:Faltantes += [pscustomobject]@{ Motor = $que; Sin = $sinEsto }
        CGP $que 'failed'
    }
}

Intentar "gitleaks" { Install-Motor "gitleaks" } "la compuerta de secretos"
if (-not $SkipTrivy) {
    Intentar "trivy" { Install-Motor "trivy" } "la compuerta de CVE en dependencias"
} else {
    # Omitido a peticion, no fallido: es una unidad RESUELTA y la barra tiene
    # que avanzar, o se quedaria corta el resto de la instalacion.
    CGP "trivy" 'skipped'
}

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
        # -Width 4096: Out-String recorta a las columnas del HOST, y la consola
        # oculta que lanza el setup trae 80. Sin esto, el mensaje de error de un
        # motor —que es justo lo que se guarda para explicarle al usuario qué
        # pasó— llega mutilado a mitad de una ruta.
        $salida = & $exe @argumentos 2>&1 | Out-String -Width 4096
        return [pscustomobject]@{ Codigo = $LASTEXITCODE; Salida = $salida }
    } finally { $ErrorActionPreference = $previo }
}

# ── motores Python (semgrep, squawk, ruff, mypy) ───────────────────────────
# El titulo sale de motores.json: escrito a mano se quedo sin bandit el dia
# que bandit entro al producto.
$nombresPy = ((Get-Content $MotoresJson -Raw | ConvertFrom-Json).paquetes.pip.PSObject.Properties.Name | ForEach-Object { $_ -replace '-cli$','' }) -join ', '
Step "Motores Python ($nombresPy)"
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
# pip instala los cinco de UNA vez, pero el contrato pide un estado terminal
# POR MOTOR: si aqui se emitiera uno solo, la barra se quedaria cuatro
# unidades corta durante el resto de la instalacion.
foreach ($n in $paquetes.pip.PSObject.Properties) { CGP ($n.Name -replace '-cli$','') 'ok' }

# Los scripts de Python se añaden al PATH del proceso actual (sin modificar el registro).
if ($env:PATH -notlike "*$pyScripts*") {
    $env:PATH = "$pyScripts;$env:PATH"
    Ok "PATH de sesion: + $pyScripts"
}

# -- motores por winget (shellcheck) ---------------------------------------
# Por que winget y no bajar el zip: shellcheck NO publica sumas SHA-256 de sus
# releases, asi que verificarlo contra "el checksum que publico su autor" -la
# disciplina del resto de motores- es imposible. El manifiesto de winget si
# lleva SHA256 y el cliente lo comprueba, asi que la cadena de verificacion
# existe aunque no sea la del autor. Se dice aqui y en motores.json.
#
# No es critico: si falla, se apunta y se sigue. Una capa ausente degrada; un
# instalador que se cae por un linter de shell no.
$wingetMotores = (Get-Content $MotoresJson -Raw | ConvertFrom-Json).paquetes.winget
if ($wingetMotores) {
    foreach ($prop in $wingetMotores.PSObject.Properties) {
        if ($prop.Name.StartsWith("_")) { continue }
        $motor = $prop.Name; $id = $prop.Value
        if (Get-Command $motor -ErrorAction SilentlyContinue) {
            Ok "$motor ya estaba"
            CGP $motor 'already-present'
            continue
        }
        CGP $motor 'working'
        Step "instalando $motor via winget ($id)"
        $w = Correr "winget" @("install", "-e", "--id", $id, "--silent",
                               "--accept-package-agreements", "--accept-source-agreements")
        if ($w.Codigo -ne 0) {
            Write-Host "    $motor NO se pudo instalar (winget devolvio $($w.Codigo))" -ForegroundColor Yellow
            $script:Faltantes += [pscustomobject]@{ Motor = $motor; Sin = "no se pudo instalar via winget" }
            CGP $motor 'failed'
            continue
        }
        $env:PATH = [Environment]::GetEnvironmentVariable("PATH", "User") + ";" + [Environment]::GetEnvironmentVariable("PATH", "Machine")
        Ok "$motor instalado"
        CGP $motor 'ok'
    }
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
    foreach ($n in $paquetes.go.PSObject.Properties.Name) { CGP $n 'skipped' }
} else {
    $previoGobin = $env:GOBIN
    $env:GOBIN = $EnginesDir
    try {
        # Se compila desde el MODULO DE HERRAMIENTAS empaquetado (tools/ junto a
        # este script), no con `go install modulo@version`: los go.mod de las
        # herramientas fijan PISOS de dependencias que van por detras de las
        # correcciones de seguridad (medido 2026-08-22: staticcheck v0.8.1
        # seleccionaba x/mod v0.35.0 con dos CVE HIGH corregidos en v0.40.0).
        # Desde nuestro modulo, MVS toma el maximo de los requisitos y nuestro
        # go.sum firma el arbol completo; GOSUMDB sigue verificando las sumas.
        # La version que motores.json declara se comprueba CONTRA EL BINARIO
        # compilado (go version -m): si tools/ y motores.json divergen, se dice.
        $dirTools = Join-Path $PSScriptRoot "tools"
        if (-not (Test-Path (Join-Path $dirTools "go.mod"))) {
            Write-Host "    falta el modulo de herramientas ($dirTools): sin el no se compilan los motores de Go" -ForegroundColor Yellow
            $script:Faltantes += [pscustomobject]@{ Motor = "staticcheck y govulncheck"; Sin = "modulo de herramientas ausente" }
            foreach ($n in $paquetes.go.PSObject.Properties.Name) { CGP $n 'skipped' }
            return
        }
        $descripciones = @{
            govulncheck = "analisis de alcanzabilidad de CVEs"
            staticcheck = "analisis semantico sobre la forma SSA"
            gosec       = "patrones inseguros en Go"
            actionlint  = "inyeccion de shell en workflows de GitHub Actions"
        }
        $goMotores = @()
        # La lista sale de motores.json, no de aqui: escrita a mano, los motores
        # nuevos entraban al producto y NO al instalador -- paso con gosec,
        # actionlint, bandit y shellcheck, cuatro capas que el usuario no tenia
        # y nadie le decia.
        foreach ($nombre in $paquetes.go.PSObject.Properties.Name) {
            $spec = $paquetes.go.$nombre
            $goMotores += @{ nombre = $nombre; paquete = $spec.modulo;
                             raiz = $spec.modulo_raiz; version = $spec.version;
                             aislado = [bool]$spec.aislado;
                             que = $descripciones[$nombre] }
        }
        $n = 0
        foreach ($m in $goMotores) {
            $n++
            CGP $m.nombre 'working'
            Step "compilando $($m.nombre) desde el fuente ($n de $($goMotores.Count)) - $($m.que)"
            Ok "esto tarda uno o dos minutos; no se descarga un binario, se compila"
            $inicio = Get-Date
            if ($m.aislado) {
                # Su propio grafo: no cabe en el modulo de herramientas (ver
                # _por_que_aislado en motores.json). Sigue con version fijada.
                $r = Correr "go" @("install", ($m.paquete + "@" + $m.version))
            } else {
                $r = Correr "go" @("-C", $dirTools, "install", $m.paquete)
            }
            if ($r.Codigo -ne 0) {
                # Uno que no compila no se lleva al otro por delante: se apunta
                # y se sigue. Los dos son motores distintos con compuertas
                # distintas, y perder las dos por un fallo de red al bajar un
                # módulo sería regalar cobertura.
                Write-Host "    $($m.nombre) NO se pudo compilar" -ForegroundColor Yellow
                Write-Host ("    " + (($r.Salida -split "`n")[0])) -ForegroundColor Yellow
                $script:Faltantes += [pscustomobject]@{
                    Motor = $m.nombre
                    Sin   = $m.que
                }
                CGP $m.nombre 'failed'
                continue
            }
            # La version declarada en motores.json se comprueba contra el
            # binario REAL (modulos embebidos): si tools/go.mod y motores.json
            # divergen, esto lo grita en vez de instalar otra cosa en silencio.
            $exe = Join-Path $env:GOBIN "$($m.nombre).exe"
            # Anclado a la linea `mod`: la linea `path .../cmd/<motor>` tambien
            # contiene la raiz del modulo y NO lleva version — agarrarla daba
            # un mismatch falso (medido en el CI: govulncheck 'embebia otra
            # version' que era su propia linea path).
            $embebido = (& go version -m $exe 2>$null | Select-String -Pattern ("^\s*mod\s+" + [regex]::Escape($m.raiz) + "\s") | Select-Object -First 1) -replace '\s+', ' '
            if ($embebido -notmatch [regex]::Escape($m.version)) {
                Write-Host "    $($m.nombre): la version embebida no es la declarada ($($m.version)): $embebido" -ForegroundColor Yellow
                $script:Faltantes += [pscustomobject]@{
                    Motor = $m.nombre
                    Sin   = "version embebida distinta de motores.json"
                }
                CGP $m.nombre 'failed'
                continue
            }
            Ok "$($m.nombre) $($m.version) listo en $([int]((Get-Date) - $inicio).TotalSeconds) s"
            CGP $m.nombre 'ok'
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
            Ok "$name $($v.version) ya presente y verificado"
            ComprobarQueArranca $name $destino
            CGP $name 'already-present'
            return
        }
        Write-Host "    $name presente pero NO coincide con el artefacto publicado" -ForegroundColor Yellow
        Write-Host "    se reemplazara por la version verificada" -ForegroundColor Yellow
    }
    # El parcial vive en el cache de descargas y NO en %TEMP%, igual que el de
    # gitleaks y trivy: sobrevive al asistente para que un reintento reanude.
    # Antes se borraba al entrar Y en el finally, asi que la reanudacion que
    # promete el mensaje de error era imposible: cada intento repetia el
    # archivo entero.
    New-Item -ItemType Directory -Force $DescargasDir | Out-Null
    $tmp = Join-Path $DescargasDir "$name-$($v.version).jar"
    try {
        Step "Descargando $name $($v.version)"
        # El booleano se IGNORABA. Una descarga cortada llegaba a la
        # comprobacion de hash y salia por el camino de "no coincide con el
        # checksum publicado por sus autores": se acusaba al publicador —o a la
        # red de estar alterando el trafico— de lo que era, simplemente, una
        # descarga a medias. Son dos diagnosticos distintos y dos remedios
        # distintos: uno se reanuda, el otro no se reintenta jamas.
        if (-not (DescargarConReanudacion $v.url $tmp)) {
            throw @"
${name}: la red no dejó terminar la descarga.
Lo bajado se CONSERVA en $tmp, así que reintentar sigue desde ahí y no
empieza de cero:  codeguard repair
"@
        }
        $h = Sha256Archivo $tmp
        if ($h -ne $v.sha256_zip) {
            # COMPLETO y aun asi no cuadra: eso ya no es la red. El parcial se
            # borra —y solo aqui— para que el intento siguiente no herede un
            # archivo envenenado; en los demas caminos se conserva.
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
            throw @"
$name no coincide con el checksum publicado por sus autores.
  descargado: $h
  esperado:   $($v.sha256_zip)
La descarga llegó ENTERA y aun así no cuadra, así que no es un corte de red: es
una version distinta a la que fijamos, un espejo alterado o una red que modifica
el trafico. No se instala nada hasta aclararlo.
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
        ComprobarQueArranca $name $destino
        CGP $name 'ok'
        # Instalado y verificado: el parcial ya no hace falta. Solo aqui.
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
    finally {
        # Residuo del esquema viejo (%TEMP%\cg-<name>.jar), por si esta maquina
        # viene de una version anterior.
        $viejo = Join-Path $env:TEMP "cg-$name.jar"
        if (Test-Path $viejo) { Remove-Item -LiteralPath $viejo -Force -ErrorAction SilentlyContinue }
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
            Ok "$name $($v.version) ya presente y verificado"
            ComprobarQueArranca $name (Join-Path $destino "bin\pmd.bat") -EsBat
            CGP $name 'already-present'
            return
        }
        Write-Host "    $name presente pero su arbol NO coincide con el publicado" -ForegroundColor Yellow
        Write-Host "    se reemplazara por la version verificada" -ForegroundColor Yellow
    }
    # Solo el arbol EXTRAIDO es temporal. El zip de 70 MB vive en el cache de
    # descargas para que un corte de red se reanude en vez de repetirse: antes
    # LimpiarTemporales lo borraba al entrar y otra vez en el finally, asi que
    # cada intento empezaba de cero. En una red lenta eso es media hora tirada
    # por intento.
    LimpiarTemporales $name
    New-Item -ItemType Directory -Force $DescargasDir | Out-Null
    $tmp = Join-Path $DescargasDir "$name-$($v.version).zip"
    $dir = Join-Path $env:TEMP "cg-$name"
    try {
        Step "Descargando $name $($v.version) (~70 MB: son 104 jars entre reglas y parsers)"
        # El booleano se ignoraba: una descarga cortada se presentaba como
        # checksum alterado. Ver la misma correccion en Install-Jar.
        if (-not (DescargarConReanudacion $v.url $tmp)) {
            throw @"
${name}: la red no dejó terminar la descarga.
Lo bajado se CONSERVA en $tmp, así que reintentar sigue desde ahí y no
empieza de cero:  codeguard repair
"@
        }
        $zh = Sha256Archivo $tmp
        if ($zh -ne $v.sha256_zip) {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
            throw @"
$name no coincide con el checksum publicado por sus autores.
  descargado: $zh
  esperado:   $($v.sha256_zip)
La descarga llegó ENTERA y aun así no cuadra: no es un corte de red. Se
descarto sin abrir. No se instala nada hasta aclararlo.
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
        ComprobarQueArranca $name (Join-Path $destino "bin\pmd.bat") -EsBat
        CGP $name 'ok'
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
    finally { LimpiarTemporales $name }
}

Step "Motores Java (google-java-format, PMD)"
$javaBin = Get-Command java -ErrorAction SilentlyContinue
if (-not $javaBin) {
    Ok "no hay JDK - se omite (los motores solo aplican a repos Java)"
    CGP "google-java-format" 'skipped'
    CGP "pmd" 'skipped'
} else {
    CGP "google-java-format" 'working'
    Install-Jar "google-java-format"
    CGP "pmd" 'working'
    Install-Arbol "pmd"
}

# ── El parte final: qué falta y qué deja de revisarse ─────────────────────────
# "Algun motor no quedo completo" no le sirve a nadie: no dice cuál, ni qué se
# apaga con él, ni qué hacer. Y el usuario ya se fue a commitear creyendo que
# tiene un producto entero.
#
# Se escribe también a un archivo aparte para que el asistente lo enseñe en su
# ventana: el log completo lleva trazas de PowerShell dentro y nadie lo abre.
#
# La ruta llega por parametro ($FaltanFile): dos instalaciones a la vez
# compartian este archivo y la segunda ensenaba el parte de la primera.
$faltanTxt = $FaltanFile
Remove-Item $faltanTxt -Force -ErrorAction SilentlyContinue

# Lo que nunca se intento se declara antes de cerrar, para que el asistente no
# se quede esperando un estado que ya no va a llegar.
CGPCerrarPendientes

if ($script:Faltantes.Count -gt 0) {
    Write-Host ""
    Write-Host "INSTALACION INCOMPLETA" -ForegroundColor Yellow
    $lineas = @()
    foreach ($f in $script:Faltantes) {
        $lineas += "  falta $($f.Motor) - sin el no corre $($f.Sin)"
    }
    $lineas += ""
    $lineas += "CodeGuard funciona, pero esas compuertas NO revisan nada, y el CI si las"
    $lineas += "corre: un commit puede pasar aqui y morir alla."
    $lineas += ""
    $lineas += "Reintenta con:  codeguard repair"
    $lineas += "Lo ya descargado se conserva, asi que reanuda y no vuelve a empezar."
    $lineas | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
    Set-Content -Path $faltanTxt -Value ($lineas -join "`r`n") -Encoding UTF8
    exit 2
}

Write-Host ""
Ok "todos los motores aplicables quedaron instalados y verificados"

# El 0 se declara, no se hereda.
#
# instalar-motores.ps1 lee $LASTEXITCODE despues de invocar este script, y sin
# un exit explicito ese valor es el del ULTIMO comando nativo que corriera aqui
# dentro -- curl, go, pip, winget-- que puede ser cualquier cosa. El camino
# sano tiene que decir 0 con todas las letras, igual que el camino incompleto
# dice 2 unas lineas mas arriba.
exit 0
