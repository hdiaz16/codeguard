package proc

import (
	"os"
	"strings"
)

// El daemon guarda la API key del modelo en su entorno. Pasarle os.Environ()
// a cada motor se la entregaba entera a gitleaks, semgrep, trivy, squawk, tsc
// y ruff — seis binarios de terceros que no tienen ningún motivo para verla.
// Ninguno de ellos habla con el modelo.
//
// Por eso el entorno se arma con una lista de lo permitido y no quitando lo
// peligroso: una lista de prohibidos deja pasar la siguiente variable secreta
// que alguien añada, y esa es justo la que no queremos regalar.

// permitidas son las variables que los motores necesitan de verdad. Cada una
// está aquí porque algo se rompe sin ella, no por si acaso.
var permitidas = map[string]bool{
	// Windows no arranca un proceso sin esto.
	"SYSTEMROOT": true, "WINDIR": true, "COMSPEC": true, "PATHEXT": true,
	"SYSTEMDRIVE": true, "PROGRAMFILES": true, "PROGRAMFILES(X86)": true,
	"PROGRAMDATA": true, "COMMONPROGRAMFILES": true,
	"NUMBER_OF_PROCESSORS": true, "PROCESSOR_ARCHITECTURE": true, "OS": true,

	// Encontrar los binarios y escribir temporales.
	"PATH": true, "TEMP": true, "TMP": true,

	// Perfil del usuario: trivy cachea su base de vulnerabilidades ahí, y git
	// lee la configuración global desde el home.
	"USERPROFILE": true, "HOMEDRIVE": true, "HOMEPATH": true, "HOME": true,
	"LOCALAPPDATA": true, "APPDATA": true, "USERNAME": true,

	// Cadenas de herramientas.
	"GOPATH": true, "GOROOT": true, "GOCACHE": true, "GOMODCACHE": true,
	"GOFLAGS": true, "GOPROXY": true, "GONOSUMDB": true, "GONOSUMCHECK": true,
	"NODE_PATH": true, "NODE_OPTIONS": true, "NPM_CONFIG_CACHE": true,
	"DOTNET_ROOT": true, "DOTNET_CLI_TELEMETRY_OPTOUT": true, "NUGET_PACKAGES": true,
	"JAVA_HOME":  true,
	"PYTHONPATH": true, "PYTHONHOME": true, "VIRTUAL_ENV": true,
	"PYTHONUTF8": true, "PYTHONIOENCODING": true,

	// Redes corporativas con proxy: sin esto trivy no baja su base.
	"HTTP_PROXY": true, "HTTPS_PROXY": true, "NO_PROXY": true,
	"http_proxy": true, "https_proxy": true, "no_proxy": true,
	"REQUESTS_CA_BUNDLE": true, "SSL_CERT_FILE": true, "SSL_CERT_DIR": true,
	"NODE_EXTRA_CA_CERTS": true,
}

// Entorno arma el entorno de un motor: sólo lo permitido, más lo que se le
// pase. Los extra van en la forma "CLAVE=valor" y siempre ganan.
func Entorno(extra ...string) []string {
	out := make([]string, 0, len(permitidas)+len(extra))
	puestas := map[string]bool{}
	for _, e := range extra {
		if i := strings.IndexByte(e, '='); i > 0 {
			puestas[strings.ToUpper(e[:i])] = true
		}
	}
	for _, e := range os.Environ() {
		i := strings.IndexByte(e, '=')
		if i <= 0 {
			continue
		}
		clave := e[:i]
		if puestas[strings.ToUpper(clave)] {
			continue // lo pisa un extra
		}
		if permitidas[strings.ToUpper(clave)] {
			out = append(out, e)
		}
	}
	return append(out, extra...)
}

// Filtradas cuenta cuántas variables se quedaron fuera. Sirve para poder
// decirlo en el diagnóstico en vez de que sea invisible.
func Filtradas() int {
	n := 0
	for _, e := range os.Environ() {
		i := strings.IndexByte(e, '=')
		if i > 0 && !permitidas[strings.ToUpper(e[:i])] {
			n++
		}
	}
	return n
}
