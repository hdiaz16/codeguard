package proc

import "strings"

// Perfiles de entorno por SUBPROCESO (W4, t.116, fusión Kimi+GPT): cada motor
// declara qué familia de variables necesita ADEMÁS del piso común, y nada
// más. Hasta hoy la lista blanca era una sola para todos: NODE_PATH llegaba a
// trivy, PYTHONPATH a gitleaks y los proxies a motores que jamás tocan la red
// — cada variable de más es superficie que un entorno envenenado puede usar.
//
// La declaración es ADITIVA sobre el piso (condición de Kimi: una lista
// completa por motor nace olvidada en el motor #12) y el constructor tipado
// es la única vía de los motores (condición de GPT: `Entorno(extra...)` libre
// dejaba a cualquier adaptador reintroducir lo que quisiera — el arch-test de
// linters lo prohíbe fuera de la tabla de declaración).
//
// GOFLAGS, GONOSUMDB y GONOSUMCHECK murieron de la lista entera: los dos
// últimos son variables MUERTAS del toolchain moderno, y GOFLAGS es el vector
// de envenenamiento que ambos consejeros señalaron (un `-mod=mod` en el
// entorno del dev altera lo que staticcheck compila); los repos vendoreados
// no la necesitan — Go detecta vendor/ solo.
type Perfil int

const (
	// PerfilBasico: solo el piso común. Binarios Go puros sin toolchain
	// (gitleaks) y sondas.
	PerfilBasico Perfil = iota
	// PerfilGo: toolchain de Go OFFLINE (gofmt/govet/gosec/staticcheck) —
	// cachés y raíces, sin GOPROXY: compilar el módulo no debe ir a la red
	// en el camino del commit.
	PerfilGo
	// PerfilGoRed: PerfilGo + GOPROXY + proxies/CA. Para govulncheck, que
	// baja la vulndb y resuelve módulos por diseño.
	PerfilGoRed
	// PerfilNode: eslint/tsc/biome — resolución de node y caché de npm.
	PerfilNode
	// PerfilPython: semgrep/ruff/bandit/mypy/squawk — el intérprete y sus
	// rutas, con UTF-8 SIEMPRE fijo (la lección de los acentos en cp1252
	// deja de ser un extra que cada llamador recuerda).
	PerfilPython
	// PerfilDotnet: dotnet format/build OFFLINE (--no-restore).
	PerfilDotnet
	// PerfilDotnetRed: PerfilDotnet + proxies/CA. Para dotnet-vuln, que
	// restaura y consulta nuget.org por diseño.
	PerfilDotnetRed
	// PerfilJava: google-java-format y PMD — solo JAVA_HOME de más.
	PerfilJava
	// PerfilCompleto: la unión entera (la lista histórica). SOLO para la
	// medición de contratos (internal/engines/contrato), que reproduce el
	// entorno con el que se midieron los contratos originales, y para
	// EntornoGit. Ningún motor de análisis lo usa.
	PerfilCompleto
)

// piso es lo que TODO subproceso necesita para existir en Windows: arrancar,
// resolver binarios, escribir temporales y leer el perfil del usuario (trivy
// cachea su base ahí; git lee su config global del home).
//
// ⚠️ ANTES DE QUITAR UNA DE AQUÍ, lee el aviso de coste en entorno.go: desde
// que el hook falla cerrado y git corre con este entorno, una variable de git
// que falte no degrada — BLOQUEA el commit en todas las máquinas.
var piso = map[string]bool{
	"SYSTEMROOT": true, "WINDIR": true, "COMSPEC": true, "PATHEXT": true,
	"SYSTEMDRIVE": true, "PROGRAMFILES": true, "PROGRAMFILES(X86)": true,
	"PROGRAMDATA": true, "COMMONPROGRAMFILES": true,
	"NUMBER_OF_PROCESSORS": true, "PROCESSOR_ARCHITECTURE": true, "OS": true,
	"PATH": true, "TEMP": true, "TMP": true,
	"USERPROFILE": true, "HOMEDRIVE": true, "HOMEPATH": true, "HOME": true,
	"LOCALAPPDATA": true, "APPDATA": true, "USERNAME": true,
}

// extrasDe: lo que cada perfil AÑADE al piso. Los nombres van en MAYÚSCULAS;
// la comparación es case-insensitive como siempre.
var extrasDe = map[Perfil][]string{
	PerfilBasico: {},
	PerfilGo:     {"GOPATH", "GOROOT", "GOCACHE", "GOMODCACHE"},
	PerfilGoRed: {"GOPATH", "GOROOT", "GOCACHE", "GOMODCACHE", "GOPROXY",
		"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
		"REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR"},
	PerfilNode: {"NODE_PATH", "NPM_CONFIG_CACHE"},
	PerfilPython: {"PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV",
		"PYTHONUTF8", "PYTHONIOENCODING", "MYPYPATH"},
	PerfilDotnet: {"DOTNET_ROOT", "DOTNET_CLI_TELEMETRY_OPTOUT", "NUGET_PACKAGES"},
	PerfilDotnetRed: {"DOTNET_ROOT", "DOTNET_CLI_TELEMETRY_OPTOUT", "NUGET_PACKAGES",
		"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
		"REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS"},
	PerfilJava: {"JAVA_HOME"},
}

// fijasDe: lo que el perfil IMPONE (extras con valor), pase lo que pase en el
// entorno del usuario. Python en Windows lee/escribe cp1252 sin esto y rompe
// los acentos — era un extra que CUATRO llamadores repetían y el quinto
// olvidaría.
var fijasDe = map[Perfil][]string{
	PerfilPython: {"PYTHONUTF8=1", "PYTHONIOENCODING=utf-8"},
}

// egressHint es el freno de red de los perfiles SIN red declarada (W4, Q4
// t.116): proxies apuntando a un puerto MUERTO de loopback (falla en
// milisegundos, sin backoff) y NO_PROXY VACÍO — la corrección de GPT: `*`
// significa «salta el proxy y conecta DIRECTO», exactamente lo contrario.
//
// Se llama egress-HINT y no sandbox de red A PROPÓSITO: solo frena a las
// herramientas legítimas que respetan las variables de proxy. Un binario
// hostil hace net.Dial directo y lo ignora — ese lo cierra WFP/AppContainer,
// que es compuerta de flota. El límite honesto queda dicho aquí y en el
// threat model.
var egressHint = []string{
	"HTTP_PROXY=http://127.0.0.1:9/", "HTTPS_PROXY=http://127.0.0.1:9/",
	"http_proxy=http://127.0.0.1:9/", "https_proxy=http://127.0.0.1:9/",
	"NO_PROXY=", "no_proxy=",
}

// conRed dice qué perfiles DECLARAN red: solo ellos ven los proxies reales
// del usuario y se libran del freno.
var conRed = map[Perfil]bool{
	PerfilGoRed:     true,
	PerfilDotnetRed: true,
	PerfilCompleto:  true,
}

// EntornoDePerfil arma el entorno de un subproceso: piso + los extras del
// perfil + lo impuesto por el perfil + lo que pase el llamador (que siempre
// gana). Es LA vía de los motores; Entorno() a secas queda para
// PerfilCompleto (contrato y git).
func EntornoDePerfil(p Perfil, extra ...string) []string {
	if p == PerfilCompleto {
		return Entorno(extra...)
	}
	permitido := make(map[string]bool, len(piso)+16)
	for k := range piso {
		permitido[k] = true
	}
	for _, k := range extrasDe[p] {
		permitido[strings.ToUpper(k)] = true
	}
	todos := append([]string{}, fijasDe[p]...)
	if !conRed[p] {
		todos = append(todos, egressHint...)
	}
	todos = append(todos, extra...)
	return entornoFiltrado(permitido, todos)
}
