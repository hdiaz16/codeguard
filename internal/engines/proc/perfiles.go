package proc

import (
	"log"
	"strings"

	"codeguard/internal/engines/politicared"
)

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
	// PerfilGo: toolchain de Go (gofmt/govet/gosec/staticcheck/govulncheck) —
	// cachés y raíces. Que vea o no GOPROXY y los proxies del usuario NO lo
	// decide el perfil: lo decide la política de red del motor.
	PerfilGo
	// PerfilNode: eslint/tsc/biome — resolución de node y caché de npm.
	PerfilNode
	// PerfilPython: semgrep/ruff/bandit/mypy/squawk — el intérprete y sus
	// rutas, con UTF-8 SIEMPRE fijo (la lección de los acentos en cp1252
	// deja de ser un extra que cada llamador recuerda).
	PerfilPython
	// PerfilDotnet: dotnet format/build/vuln — el SDK y sus cachés. Igual que
	// con Go, la red la decide la política del motor y no esta familia.
	PerfilDotnet
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
	PerfilNode:   {"NODE_PATH", "NPM_CONFIG_CACHE"},
	PerfilPython: {"PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV",
		"PYTHONUTF8", "PYTHONIOENCODING", "MYPYPATH"},
	PerfilDotnet: {"DOTNET_ROOT", "DOTNET_CLI_TELEMETRY_OPTOUT", "NUGET_PACKAGES"},
	PerfilJava:   {"JAVA_HOME"},
}

// extrasRedComunes es lo que ve CUALQUIER familia cuyo motor declare red: los
// proxies de verdad del usuario y sus raíces de certificados. Sin las CA, un
// equipo detrás de un proxy que inspecciona TLS no puede resolver nada.
var extrasRedComunes = []string{
	"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
	"REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR",
}

// extrasRedDe es lo que añade cada familia POR ENCIMA de las comunes cuando su
// motor declara red. Son las dos variables que antes distinguían PerfilGoRed y
// PerfilDotnetRed de sus versiones offline.
var extrasRedDe = map[Perfil][]string{
	PerfilGo:     {"GOPROXY"},
	PerfilDotnet: {"NODE_EXTRA_CA_CERTS"},
}

// reservadasDeRed son las variables que la POLÍTICA controla y que un llamador
// no puede fijar por su cuenta.
//
// Sin esto, la autoridad del registro sería de mentira: entornoFiltrado añade
// los `extra` del llamador DESPUÉS del egress-hint y sin pasarlos por la lista
// blanca, así que un adaptador que pasara HTTP_PROXY=… (por descuido o por
// copiar de otro sitio) se saltaría el freno de red entero. Lo señaló GPT al
// revisar el cableado y se comprobó leyendo entornoFiltrado.
var reservadasDeRed = map[string]bool{
	"HTTP_PROXY": true, "HTTPS_PROXY": true, "NO_PROXY": true,
	"GOPROXY": true, "REQUESTS_CA_BUNDLE": true, "SSL_CERT_FILE": true,
	"SSL_CERT_DIR": true, "NODE_EXTRA_CA_CERTS": true,
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

// EntornoDePerfil arma el entorno de un subproceso SIN RED: piso + los extras
// de la familia + lo que la familia impone + lo que pase el llamador.
//
// Ya no existe ningún perfil que conceda red, y esa ausencia es la garantía:
// la ÚNICA puerta a los proxies reales es EntornoDeMotor consultando el
// registro de política. Un llamador que no pase por ahí corre frenado, se
// llame como se llame. Queda para los subprocesos que NO son motores —el
// calentamiento del daemon y las sondas de versión—; Entorno() a secas sigue
// siendo lo de PerfilCompleto (contrato y git).
func EntornoDePerfil(p Perfil, extra ...string) []string {
	if p == PerfilCompleto {
		return Entorno(extra...)
	}
	return entornoDeFamilia(p, false, extra)
}

// EntornoDeMotor arma el entorno de un MOTOR: la familia la elige el llamador
// (qué toolchain necesita), y si ve la red o no lo decide el registro de
// política a partir del nombre del motor. Ese reparto es el punto entero del
// cableado — el llamador ya no puede concederse red.
//
// Un nombre desconocido cae en denegado (fail-closed), así que equivocarse
// escribiéndolo frena al motor en vez de soltarlo: el error se nota y no se
// paga en seguridad. PerfilCompleto no se acepta: es la unión histórica de la
// medición de contratos y de git, que no son motores y no tienen política.
func EntornoDeMotor(motor string, familia Perfil, extra ...string) []string {
	if familia == PerfilCompleto {
		// Programación, no entrada: un motor jamás debe pedir la unión
		// histórica, que se salta el estrechamiento por perfiles entero.
		panic("proc: EntornoDeMotor no acepta PerfilCompleto (motor " + motor + ")")
	}
	return entornoDeFamilia(familia, politicared.RequiereRedDuranteAnalisis(motor), extra)
}

func entornoDeFamilia(p Perfil, conRed bool, extra []string) []string {
	permitido := make(map[string]bool, len(piso)+16)
	for k := range piso {
		permitido[k] = true
	}
	for _, k := range extrasDe[p] {
		permitido[strings.ToUpper(k)] = true
	}
	if conRed {
		for _, k := range extrasRedComunes {
			permitido[strings.ToUpper(k)] = true
		}
		for _, k := range extrasRedDe[p] {
			permitido[strings.ToUpper(k)] = true
		}
	}
	todos := append([]string{}, fijasDe[p]...)
	if !conRed {
		todos = append(todos, egressHint...)
	}
	// Los extras del llamador van al final —siguen ganando sobre lo demás—
	// pero NO pueden tocar las variables que gobierna la política.
	for _, e := range extra {
		i := strings.IndexByte(e, '=')
		if i > 0 && reservadasDeRed[strings.ToUpper(e[:i])] {
			log.Printf("proc: se ignora %q en los extras: la red la manda la política del motor, no el llamador", e[:i])
			continue
		}
		todos = append(todos, e)
	}
	return entornoFiltrado(permitido, todos)
}
