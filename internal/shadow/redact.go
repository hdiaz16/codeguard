package shadow

import "regexp"

// Redacción P5 (spec §15): antes de que el diff salga a la red, se enmascara
// todo lo que parezca credencial. La compuerta de secretos ya bloqueó lo que
// gitleaks detecta en lo staged, pero el diff puede arrastrar contexto con
// secretos que el escáner no cubre — esos tampoco deben viajar.

// redactAsignacion es la única regex que conserva la clave y tapa solo el valor.
// Vive fuera de redactors con su reemplazo explícito: depender de su posición
// en el slice (el viejo `if i == 6`) rompía la redacción silenciosamente al
// añadir o reordenar patrones.
//
// El valor sin comillas admite signos ($, !, #, %, &...) habituales en
// contraseñas; una clase estrecha ([A-Za-z0-9+/_.-]) redactaba solo hasta el
// primer signo y dejaba el resto visible. [^\s"']{8,} captura el valor completo
// hasta el delimitador real (espacio o comilla).
var redactAsignacion = regexp.MustCompile(`(?i)((password|passwd|pwd|secret|api[_-]?key|apikey|token|credential)s?["']?\s*[:=]\s*)("[^"]{6,}"|'[^']{6,}'|[^\s"']{8,})`)

var redactors = []*regexp.Regexp{
	// llaves y tokens con formato conocido
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),                          // AWS access key
	regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{30,}`),                // GitHub tokens clásicos
	regexp.MustCompile(`github_pat_[A-Za-z0-9_]{40,}`),              // GitHub fine-grained PAT
	regexp.MustCompile(`sk-[A-Za-z0-9_-]{20,}`),                     // OpenAI-style
	regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`),              // Slack
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}`), // JWT
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`),
	// cadenas de conexión con contraseña embebida
	regexp.MustCompile(`(?i)(Password|Pwd)=[^;"'\s]{4,}`),
	// URLs con credenciales user:pass@
	regexp.MustCompile(`[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]{4,}@`),
}

// Redact enmascara credenciales aparentes en el texto antes de enviarlo al modelo.
func Redact(s string) string {
	// Primero la asignación clave=valor: conserva la clave y tapa el valor.
	// Se aplica antes que las de conexión/URL, como en el orden original.
	s = redactAsignacion.ReplaceAllString(s, "${1}«REDACTADO»")
	for _, re := range redactors {
		s = re.ReplaceAllString(s, "«REDACTADO»")
	}
	return s
}
