package engines

// RedDeclarada es la política de red de un motor (W4, Q4 t.115: tri-estado y
// no bool — GPT: trivy actualiza su BD y luego escanea offline; regalarle red
// durante TODO el análisis por un bool sería mentir en las dos direcciones).
type RedDeclarada string

const (
	// RedDenegada: el motor no tiene nada que hacer en la red durante el
	// análisis. Su perfil de entorno lleva el egress-hint (proxies muertos).
	RedDenegada RedDeclarada = "denied"
	// RedSoloActualizar: la fase de red es una ACTUALIZACIÓN fuera del camino
	// del commit (la BD de trivy, que además baja nuestro cliente Go propio,
	// no el motor); el análisis corre denegado.
	RedSoloActualizar RedDeclarada = "update-only"
	// RedRequerida: el motor consulta la red POR DISEÑO en el análisis
	// (govulncheck resuelve módulos y vulndb; dotnet-vuln consulta nuget.org).
	// Su perfil ve los proxies reales del usuario.
	RedRequerida RedDeclarada = "required"
)

// redPorMotor es EL registro (único, en runtime; su proyección a motores.json
// queda anotada para W6 — jamás se duplica a mano en dos sitios que
// diverjan). La clave es Engine.Name(). Lo que NO esté aquí se lee como
// denegado: el motor nuevo que necesite red lo DECLARA o corre frenado.
var redPorMotor = map[string]RedDeclarada{
	"gitleaks":           RedDenegada,
	"semgrep":            RedDenegada, // --metrics=off --disable-version-check
	"squawk":             RedDenegada,
	"trivy":              RedSoloActualizar, // --skip-db-update SIEMPRE; la DB la baja internal/trivydb
	"govulncheck":        RedRequerida,      // módulos + vulndb por diseño
	"staticcheck":        RedDenegada,       // compila OFFLINE (PerfilGo sin GOPROXY)
	"gofmt":              RedDenegada,
	"govet":              RedDenegada,
	"gosec":              RedDenegada,
	"ruff":               RedDenegada,
	"bandit":             RedDenegada,
	"mypy":               RedDenegada,
	"tsc":                RedDenegada, // npx --no-install
	"eslint":             RedDenegada, // --no-install
	"dotnet-format":      RedDenegada,
	"dotnet-build":       RedDenegada,  // --no-restore
	"dotnet-vuln":        RedRequerida, // restaura y consulta nuget.org por diseño
	"google-java-format": RedDenegada,
	"pmd":                RedDenegada,
}

// RedDe devuelve la política declarada; lo desconocido es DENEGADO
// (fail-closed: un motor que nadie declaró no gana red por omisión).
func RedDe(nombre string) RedDeclarada {
	if r, ok := redPorMotor[nombre]; ok {
		return r
	}
	return RedDenegada
}
