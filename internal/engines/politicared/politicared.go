// Package politicared es EL registro de la política de red de los motores.
//
// Vive en un paquete HOJA a propósito. La política la consulta
// internal/engines/proc para armar el entorno de cada subproceso, y proc no
// puede importar a su paquete padre internal/engines sin arriesgar un ciclo el
// día que engines necesite proc. Un paquete hoja lo pueden importar los dos.
//
// Historia, para que no se repita: este registro nació en W4 (Q4, t.115)
// declarándose «EL registro único … jamás se duplica a mano en dos sitios que
// diverjan», y durante meses NO lo fue. La decisión efectiva vivía en otro
// sitio —qué perfil de entorno elegía a mano cada motor: PerfilGoRed daba red,
// PerfilGo no— y este registro no lo leía nadie más que su propio test. Dos
// autoridades para la misma pregunta en una superficie de seguridad, que es
// justo lo que el comentario juraba evitar. Se cableó el 2026-08-25: hoy los
// perfiles con red NO EXISTEN, así que la única forma de que un motor vea la
// red de verdad es estar declarado aquí.
package politicared

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
	//
	// Produce el MISMO entorno que RedDenegada y aun así no sobra: dice que la
	// red de ese motor existe pero ocurre en otro sitio, así que un trivy que
	// un día intentara salir a la red DURANTE el análisis es un defecto, no una
	// sorpresa. La distinción es de intención y se conserva para auditoría.
	RedSoloActualizar RedDeclarada = "update-only"
	// RedRequerida: el motor consulta la red POR DISEÑO en el análisis
	// (govulncheck resuelve módulos y vulndb; dotnet-vuln consulta nuget.org).
	// Su perfil ve los proxies reales del usuario.
	RedRequerida RedDeclarada = "required"
)

// registro es la tabla, por Engine.Name(). Lo que NO esté aquí se lee como
// denegado: el motor nuevo que necesite red lo DECLARA o corre frenado.
var registro = map[string]RedDeclarada{
	"gitleaks":           RedDenegada,
	"semgrep":            RedDenegada, // --metrics=off --disable-version-check
	"squawk":             RedDenegada,
	"trivy":              RedSoloActualizar, // --skip-db-update SIEMPRE; la DB la baja internal/trivydb
	"govulncheck":        RedRequerida,      // módulos + vulndb por diseño
	"staticcheck":        RedDenegada,       // compila OFFLINE (perfil de Go sin GOPROXY)
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
	"actionlint":         RedDenegada,
	"psscriptanalyzer":   RedDenegada,
	"shellcheck":         RedDenegada,
}

// De devuelve la política declarada; lo desconocido es DENEGADO (fail-closed:
// un motor que nadie declaró no gana red por omisión).
func De(nombre string) RedDeclarada {
	if r, ok := registro[nombre]; ok {
		return r
	}
	return RedDenegada
}

// Declarada dice si el motor tiene entrada EXPLÍCITA. Existe porque De() no
// distingue «declarado denegado» de «nadie lo declaró», y esa diferencia es
// justo la que vigila el test de catálogo: el fail-closed silencioso es la red
// de seguridad, no la licencia para no declarar.
func Declarada(nombre string) bool {
	_, ok := registro[nombre]
	return ok
}

// RequiereRedDuranteAnalisis proyecta el tri-estado a la única pregunta que el
// entorno sabe contestar: ¿este motor ve la red de verdad mientras analiza?
//
// Se escribe por IGUALDAD con RedRequerida y jamás como «todo lo que no sea
// denegado»: esa segunda forma le regalaría red a update-only hoy y a
// cualquier valor nuevo mañana.
func RequiereRedDuranteAnalisis(nombre string) bool {
	return De(nombre) == RedRequerida
}
