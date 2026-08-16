// Package squawk adapta el linter de migraciones PostgreSQL (pilar datos,
// sección 6.3.1 — bloqueante por riesgo de caída de producción).
package squawk

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/gobwas/glob"

	"codeguard/internal/engines"
	"codeguard/internal/engines/proc"
	"codeguard/internal/finding"
)

type Engine struct {
	Binary string // vacío = buscar en PATH
	// MigrationGlobs viene de paths.migrations de la config.
	MigrationGlobs []string
	// Dialect viene de paths.migrations_dialect, ya normalizado. Squawk sólo
	// entiende PostgreSQL; contra otro motor no se corre. Vacío = postgres.
	Dialect string
}

func (e *Engine) Name() string { return "squawk" }

// aplicaDialecto: squawk parsea el dialecto de PostgreSQL y nada más. Correrlo
// sobre SQLite o MySQL no produce falsos positivos benignos: produce hallazgos
// BLOQUEANTES cuyo arreglo rompe el esquema. El caso que lo destapó fue el
// propio repo de CodeGuard —un esquema SQLite ejecutado con go:embed dentro de
// una transacción— al que squawk exigía CREATE INDEX CONCURRENTLY: sintaxis
// inexistente en SQLite, e ilegal dentro de una transacción en cualquier motor.
func (e *Engine) aplicaDialecto() bool {
	d := strings.ToLower(strings.TrimSpace(e.Dialect))
	return d == "" || d == "postgres"
}

func (e *Engine) migrationFiles(in engines.Input) []string {
	var globs []glob.Glob
	for _, p := range e.MigrationGlobs {
		if g, err := glob.Compile(p, '/'); err == nil {
			globs = append(globs, g)
		}
	}
	var out []string
	for _, f := range in.Files {
		if f.Status == "D" || filepath.Ext(f.Path) != ".sql" {
			continue
		}
		for _, g := range globs {
			if g.Match(f.Path) {
				out = append(out, f.Path)
				break
			}
		}
	}
	return out
}

func (e *Engine) Applies(in engines.Input) bool {
	return e.aplicaDialecto() && len(e.migrationFiles(in)) > 0
}

type violation struct {
	File    string `json:"file"`
	Line    int    `json:"line"` // base 0
	Rule    string `json:"rule_name"`
	Level   string `json:"level"`
	Message string `json:"message"`
	Help    string `json:"help"`
}

// blockingRules son las operaciones con riesgo real de tirar producción
// (sección 7: migración insegura BLOQUEA). Squawk las reporta como Warning
// por defecto; aquí se promueven según la política de la casa.
var blockingRules = map[string]bool{
	"disallowed-unique-constraint":      true, // lock ACCESS EXCLUSIVE mientras construye el índice
	"require-concurrent-index-creation": true, // bloquea escrituras durante la creación
	"adding-required-field":             true, // NOT NULL sin default reescribe/bloquea la tabla
	"ban-drop-column":                   true,
	"ban-drop-table":                    true,
	"ban-drop-database":                 true,
	"ban-drop-not-null":                 true,
	"changing-column-type":              true, // reescribe la tabla con lock exclusivo
	"adding-serial-primary-key-field":   true,
	"disallowed-not-null-constraint":    true,
	"renaming-column":                   true, // rompe la versión anterior en despliegues por fases
	"renaming-table":                    true,
}

func (e *Engine) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	bin := e.Binary
	if bin == "" {
		bin = "squawk"
	}
	files := e.migrationFiles(in)
	args := append([]string{"--reporter", "json"}, files...)
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = in.RepoRoot
	cmd.Env = proc.Entorno("PYTHONUTF8=1", "PYTHONIOENCODING=utf-8")
	salida, runErr := proc.Correr(ctx, cmd, proc.MaxSalida)
	out := salida.Stdout
	// squawk sale con código != 0 cuando hay violaciones; el JSON sigue siendo válido.
	if runErr != nil && len(out) == 0 {
		return nil, fmt.Errorf("squawk no corrió: %w", runErr)
	}
	if salida.Recortada {
		return nil, fmt.Errorf("squawk devolvió más de %d MB de salida", proc.MaxSalida>>20)
	}
	var violations []violation
	if err := json.Unmarshal(out, &violations); err != nil {
		return nil, fmt.Errorf("salida de squawk ilegible: %v", err)
	}

	findings := make([]finding.Finding, 0, len(violations))
	lineas := map[string][]string{} // archivo → sus líneas, leído una sola vez
	// Los errores de sintaxis se apartan: no hablan del código, hablan de que
	// squawk no supo leerlo. Ver ilegibles.
	porArchivoIlegible := map[string]violation{}
	for _, v := range violations {
		if v.Rule == "syntax-error" {
			if _, ya := porArchivoIlegible[v.File]; !ya {
				porArchivoIlegible[v.File] = v
			}
			continue
		}
		blocking := v.Level == "Error" || blockingRules[v.Rule]
		sev := finding.Warning
		if blocking {
			sev = finding.Error
		}
		// El resto del producto le habla al desarrollador en español; una
		// migración bloqueada es el peor momento para obligarle a traducir.
		msg, arreglo := traducir(v.Rule, v.Message, v.Help)
		f := finding.Finding{
			Engine:   "squawk",
			RuleKey:  v.Rule,
			Pillar:   finding.Data,
			Severity: sev,
			// Política §7: migración insegura bloquea (migration_unsafe: block).
			Blocking: blocking,
			File:     filepath.ToSlash(v.File),
			Line:     v.Line + 1, // squawk reporta base 0
			Message:  msg,
			Why: "Cambio de esquema con riesgo de lock o incompatibilidad. Pasar el lint no basta: " +
				"aplica la migración con lock_timeout y statement_timeout configurados en Postgres.",
			// La salida del dialecto va pegada a los bloqueantes, y sólo a ellos.
			//
			// Hay esquemas que no llevan ninguna marca que delate su motor —el de
			// este mismo repo es SQLite y no tiene ni una—, así que la detección
			// automática los deja en PostgreSQL y sus reglas les caen encima. Sin
			// esta línea, el dev de un repo así se queda mirando un "usa
			// CONCURRENTLY" que en SQLite NI SIQUIERA EXISTE, sin forma de saber
			// que el problema es de configuración y no suyo. Un bloqueo cuyo
			// arreglo es imposible es peor que no bloquear.
			FixHint:  arreglo + salidaPorDialecto(blocking),
			Verified: true,
			Source:   finding.Deterministic,
			// El SQL REAL de la línea, leído del archivo. Antes iba el nombre
			// de la regla, y como el fingerprint es regla+ruta+contenido, TODAS
			// las ocurrencias de una regla en un archivo colapsaban en un solo
			// hash: baselinear un índice inseguro suprimía también los futuros
			// del mismo archivo — un agujero en "sólo lo nuevo bloquea", justo
			// en la capa que protege producción.
			LineContent: lineaSQL(in.RepoRoot, v.File, v.Line, lineas),
		}
		f.ComputeFingerprint()
		findings = append(findings, f)
	}
	return append(findings, ilegibles(in.RepoRoot, porArchivoIlegible, lineas)...), nil
}

// noEsSQLQueSquawkLea reconoce los archivos que son PostgreSQL VÁLIDO pero que
// el analizador no puede parsear, y devuelve qué son. Cadena vacía = no es
// ninguno de estos casos, así que el error de sintaxis es de verdad.
//
// Los tres salieron de medir squawk 2.62 contra migraciones reales, y en los
// tres bloquear sería un falso positivo sin salida: la sintaxis está bien y el
// motor SÍ es PostgreSQL, así que ni «corrige la sintaxis» ni «declara el
// dialecto» sirven de nada. Lo único que le quedaba al dev era excluir el
// archivo del análisis, que es tirar la cobertura entera por un formato.
func noEsSQLQueSquawkLea(repoRoot, rel string) string {
	raw, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(rel)))
	if err != nil {
		return "" // sin poder leerlo no se absuelve a nadie
	}
	texto := string(raw)
	switch {
	case reCopyStdin.MatchString(texto):
		// La forma en que pg_dump vuelca datos. Son filas, no esquema.
		return "es un volcado de datos de pg_dump (COPY … FROM stdin), no un cambio de esquema"
	case reMetaPsql.MatchString(texto):
		// \set, \connect, \i … los interpreta psql, no el servidor.
		return "lleva meta-comandos de psql (\\set, \\connect…), que no son SQL del servidor"
	case reMarcadorPlantilla.MatchString(texto):
		// Flyway y compañía sustituyen ${schema} antes de aplicar.
		return "lleva marcadores de plantilla (${…}) que se sustituyen antes de aplicarse"
	}
	return ""
}

var (
	reCopyStdin         = regexp.MustCompile(`(?im)^\s*copy\s+.+\bfrom\s+stdin\b`)
	reMetaPsql          = regexp.MustCompile(`(?m)^\s*\\(set|connect|c|i|ir|echo|gexec|copy)\b`)
	reMarcadorPlantilla = regexp.MustCompile(`\$\{[A-Za-z_][A-Za-z0-9_]*\}`)
)

func salidaPorDialecto(blocking bool) string {
	if !blocking {
		return "" // un aviso no deja a nadie atascado: no hace falta la escapatoria
	}
	return "  ·  Si este esquema NO es PostgreSQL, nada de esto aplica: declara el motor " +
		"en .codeguard/config.yaml → paths.migrations_dialect (sqlite | mysql | sqlserver) " +
		"y esta capa dejará de revisarlo."
}

// ilegibles convierte los errores de sintaxis en UN aviso por archivo que dice
// lo que de verdad ocurre: squawk no pudo leer ese SQL.
//
// Un `syntax-error` no es un problema del código. Es el parser de PostgreSQL
// tropezando, y la causa casi siempre es que el archivo no es PostgreSQL.
// Medido sobre un repo MySQL: 79 hallazgos, todos syntax-error, presentados
// como "problemas que el CI también rechazaría" y bloqueando el commit. El dev
// no tiene nada que arreglar ahí — el arreglo es una línea de configuración —,
// y una lista de 79 acusaciones falsas es la forma más rápida de que deje de
// leer lo que dice esta herramienta.
//
// Colapsa a uno por archivo, pero SIGUE BLOQUEANDO, y esto último se aprendió
// por las malas. La primera versión lo dejó pasar como aviso, y un validador
// midió lo que eso abría: cuando squawk no parsea un archivo NO evalúa el
// resto —sólo reporta el error de sintaxis—, así que un `DROP COLUMN` en una
// migración PostgreSQL con un typo entraba con EXIT=0. Antes lo frenaba el
// error de sintaxis; después no lo frenaba nada.
//
// Así que se bloquea, porque es literalmente cierto que esta migración no se
// pudo revisar y la compuerta existe para no dejar pasar lo no revisado. Lo
// que cambia respecto al principio es el MENSAJE: uno solo por archivo en vez
// de setenta y nueve, y con las dos salidas reales — arreglar la sintaxis, o
// declarar el motor si esto no es PostgreSQL.
func ilegibles(repoRoot string, porArchivo map[string]violation, lineas map[string][]string) []finding.Finding {
	if len(porArchivo) == 0 {
		return nil
	}
	archivos := make([]string, 0, len(porArchivo))
	for f := range porArchivo {
		archivos = append(archivos, f)
	}
	sort.Strings(archivos) // orden estable: el informe no puede bailar entre corridas
	out := make([]finding.Finding, 0, len(archivos))
	for _, archivo := range archivos {
		v := porArchivo[archivo]
		// Hay PostgreSQL perfectamente válido que squawk no sabe parsear, y ahí
		// bloquear sería un falso positivo con las dos salidas cerradas: la
		// sintaxis está bien Y el motor sí es PostgreSQL, así que ni corregirla
		// ni declarar el dialecto arreglan nada. Medido sobre squawk 2.62.
		if quePasaAqui := noEsSQLQueSquawkLea(repoRoot, v.File); quePasaAqui != "" {
			f := finding.Finding{
				Engine:   "squawk",
				RuleKey:  "migracion-fuera-del-alcance",
				Pillar:   finding.Data,
				Severity: finding.Warning,
				Blocking: false,
				File:     filepath.ToSlash(v.File),
				Line:     v.Line + 1,
				Message:  "no reviso esta migración: " + quePasaAqui,
				Why: "El analizador de migraciones lee sentencias de esquema. Esto no lo es, " +
					"así que no puede decir nada útil sobre ello — y fingir lo contrario " +
					"sería peor que callar.",
				FixHint: "No hay nada que arreglar. Si aquí dentro SÍ hay cambios de esquema, " +
					"sepáralos en su propia migración para que se revisen.",
				Verified:    true,
				Source:      finding.Deterministic,
				LineContent: lineaSQL(repoRoot, v.File, v.Line, lineas),
			}
			f.ComputeFingerprint()
			out = append(out, f)
			continue
		}
		f := finding.Finding{
			Engine:   "squawk",
			RuleKey:  "migracion-ilegible",
			Pillar:   finding.Data,
			Severity: finding.Error,
			Blocking: true,
			File:     filepath.ToSlash(v.File),
			Line:     v.Line + 1,
			Message:  "no pude revisar esta migración: no parsea como PostgreSQL",
			Why: "Cuando el análisis tropieza con la sintaxis DEJA DE MIRAR el resto del archivo. " +
				"Un DROP COLUMN o un NOT NULL sin default más abajo no se evaluarían, así que " +
				"dejar pasar esto sería firmar como revisada una migración que nadie leyó.",
			FixHint: "Dos salidas: si esto es PostgreSQL, corrige la sintaxis (" +
				strings.TrimSpace(v.Message) + "). Si NO lo es, declara el motor en " +
				".codeguard/config.yaml → paths.migrations_dialect " +
				"(postgres | sqlite | mysql | sqlserver) y esta capa dejará de aplicarse.",
			Verified:    true,
			Source:      finding.Deterministic,
			LineContent: lineaSQL(repoRoot, v.File, v.Line, lineas),
		}
		f.ComputeFingerprint()
		out = append(out, f)
	}
	return out
}

// lineaSQL devuelve la línea (base 0) del archivo, leyendo cada archivo una
// sola vez por análisis. Si el archivo no se puede leer o la línea no existe,
// devuelve un marcador estable: en ese caso raro las ocurrencias de una regla
// en ese archivo siguen colapsando en un fingerprint — inevitable sin
// contenido — pero deja de ser la norma para pasar a ser la excepción.
func lineaSQL(repoRoot, rel string, linea int, cache map[string][]string) string {
	ls, ok := cache[rel]
	if !ok {
		raw, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(rel)))
		if err == nil {
			ls = strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")
		}
		cache[rel] = ls // también el fallo: no reintentar por cada violación
	}
	if linea < 0 || linea >= len(ls) || strings.TrimSpace(ls[linea]) == "" {
		return "sin-contenido-de-linea"
	}
	return ls[linea]
}
