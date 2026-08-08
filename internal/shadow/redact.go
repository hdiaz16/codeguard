package shadow

import "regexp"

// Redacción P5 (spec §15): antes de que el diff salga a la red, se enmascara
// todo lo que parezca credencial. La compuerta de secretos ya bloqueó lo que
// gitleaks detecta en lo staged, pero el diff puede arrastrar contexto con
// secretos que el escáner no cubre — esos tampoco deben viajar.

var redactors = []*regexp.Regexp{
	// llaves y tokens con formato conocido
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),                          // AWS access key
	regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{30,}`),                // GitHub tokens
	regexp.MustCompile(`sk-[A-Za-z0-9_-]{20,}`),                     // OpenAI-style
	regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`),              // Slack
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}`), // JWT
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`),
	// asignaciones de credenciales: clave = "valor"
	regexp.MustCompile(`(?i)((password|passwd|pwd|secret|api[_-]?key|apikey|token|credential)s?["']?\s*[:=]\s*)("[^"]{6,}"|'[^']{6,}'|[A-Za-z0-9+/_.-]{12,})`),
	// cadenas de conexión con contraseña embebida
	regexp.MustCompile(`(?i)(Password|Pwd)=[^;"'\s]{4,}`),
	// URLs con credenciales user:pass@
	regexp.MustCompile(`[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]{4,}@`),
}

// Redact enmascara credenciales aparentes en el texto antes de enviarlo al modelo.
func Redact(s string) string {
	for i, re := range redactors {
		if i == 6 { // la asignación clave=valor conserva la clave, tapa el valor
			s = re.ReplaceAllString(s, "${1}«REDACTADO»")
			continue
		}
		s = re.ReplaceAllString(s, "«REDACTADO»")
	}
	return s
}
