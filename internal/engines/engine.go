// Package engines define la interfaz común de los adaptadores de escáneres
// (sección 18: un adaptador por herramienta).
package engines

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
)

type Input struct {
	RepoRoot     string
	Files        []gitdiff.ChangedFile
	RulepackDir  string // raíz del rulepack pinneado (rulepacks/<ver>)
	MigrationsGl []string
}

// Engine es un escáner determinista. Run devuelve hallazgos; un error de
// ejecución NO bloquea (sección 14) — el orquestador lo registra como capa
// degradada. La única excepción es la compuerta de secretos (fail-closed),
// que el orquestador trata aparte.
type Engine interface {
	Name() string
	// Applies decide si el engine corre para este conjunto de archivos.
	Applies(in Input) bool
	Run(ctx context.Context, in Input) ([]finding.Finding, error)
}

// EstadoCobertura dice si un motor terminó de mirar una unidad de trabajo.
// El bool Applies + "Run no falló" NO probaba cobertura: un adaptador que
// recorre archivo por archivo y omite uno con código de salida 0 pasaba por
// «ejecutado» (veto de GPT, W6 Q2). El recibo obliga a declarar QUÉ se cubrió.
type EstadoCobertura string

const (
	// CoberturaCompleta: la unidad se analizó ENTERA.
	CoberturaCompleta EstadoCobertura = "complete"
	// CoberturaParcial: se analizó a medias (parser parcial, timeout de un
	// objetivo, fragmento ilegible). El «sin hallazgos» de esa unidad NO cubre
	// lo que no se miró — nunca es limpio.
	CoberturaParcial EstadoCobertura = "partial"
	// CoberturaOmitida: la unidad estaba planeada y NO se llegó a mirar.
	CoberturaOmitida EstadoCobertura = "skipped"
)

// Unidad es un objetivo de análisis que un motor promete mirar. La CLASE deja
// que un motor de PROYECTO (tsc, dotnet) reporte su unidad natural
// (project:ruta) sin fingir archivo por archivo, y que uno de archivo reporte
// file:ruta. La identidad de una unidad es (Clase, Ruta): así el plan y los
// recibos se cruzan sin ambigüedad.
type Unidad struct {
	Clase string // "file" | "project" | "module" | "repo"
	Ruta  string // ruta relativa con '/'; "." para lo que abarca el repo entero
}

// Recibo es la PRUEBA de que un motor miró (o no) una unidad, con su resultado.
type Recibo struct {
	Unidad Unidad
	Estado EstadoCobertura
	// Motivo es un código estable (no un texto libre) para agrupar en el
	// historial de salud de capas; vacío cuando la unidad completó.
	Motivo string
}

// Resultado enriquece la salida de un motor con los recibos de cobertura. Lo
// devuelven los motores que recorren objetivo por objetivo (ver ConCobertura);
// los demás no lo usan.
type Resultado struct {
	Findings []finding.Finding
	Recibos  []Recibo
}

// ConCobertura lo implementan SOLO los motores con riesgo real de omisión: los
// que recorren su entrada objetivo por objetivo y pueden dejar uno a medias con
// código de salida 0 (semgrep es el caso medido). Declaran su plan (qué van a
// mirar) y devuelven un recibo por objetivo; el orquestador cruza plan contra
// recibos y una unidad planeada sin recibo COMPLETO rompe la garantía de esa
// capa (§14: había algo que mirar y no se miró del todo).
//
// La mayoría de motores NO lo implementa a propósito: invocan la herramienta
// UNA vez sobre toda su unidad y son todo-o-nada — «Run terminó sin error» sí
// prueba cobertura completa, porque no hay punto intermedio entre «la
// herramienta procesó su unidad» y «falló». Para ellos el orquestador deriva un
// único recibo de su unidad natural, sin que el adaptador cargue con nada.
type ConCobertura interface {
	Engine
	// Plan enumera las unidades que este motor promete mirar para esta entrada.
	Plan(in Input) []Unidad
	// RunConCobertura corre y devuelve hallazgos MÁS un recibo por unidad. Un
	// error sigue degradando la capa entera, igual que Run.
	RunConCobertura(ctx context.Context, in Input) (Resultado, error)
}

// Cache es el caché de resultados deterministas (§9, tabla file_cache): una
// clave de contenido → los hallazgos de ESE contenido con este rulepack y
// esta config. La clave es opaca para el caché: el motor de archivos usa el
// sha del archivo; los motores de módulo (staticcheck, govulncheck) usan la
// huella agregada del módulo con su prefijo. Nil = sin caché, todo se
// analiza. Ambas operaciones son best-effort: un caché caído degrada a
// "analizar de nuevo", nunca a error.
type Cache interface {
	// Leer devuelve, de las claves dadas, las que tienen resultado guardado.
	Leer(claves []string) map[string][]finding.Finding
	// Guardar persiste hallazgos por entrada; la lista vacía también cuenta —
	// "analizado y limpio" es el resultado que más veces se reutiliza.
	//
	// Cada entrada llega con su Vigente: la implementación lo consulta ANTES
	// de escribir y descarta la entrada si responde false. Ver Cacheable.
	Guardar(entradas []Cacheable)
}

// Cacheable es una entrada de caché con su prueba de vigencia.
//
// Existe por el bug #8, reproducido determinista (bug8_toctou_test.go): la
// clave se calcula en el instante del diff y el motor lee el disco DESPUÉS,
// en el suyo. Si el archivo muta entre ambos —un autosave en medio de un
// análisis en frío—, los hallazgos del contenido nuevo se guardaban bajo la
// clave del viejo: una entrada que MIENTE sobre qué contenido analizó, y que
// sirve líneas falsas en cada acierto futuro. Persistente.
//
// Vigente recalcula la FUENTE de la clave (el sha del archivo, la huella del
// módulo — cada tipo de clave sabe la suya) y responde si sigue describiendo
// el disco. Es un campo obligatorio y no una opción a propósito: con 14
// adaptadores armando claves por separado, el que no aporte su recomputación
// NO COMPILA — la clase de guarda que vive en un comentario no vigila a nadie.
//
// Riesgo residual aceptado con números (debate del plan, turno 58): una
// mutación DESPUÉS de Vigente y antes del INSERT (milisegundos contra los
// segundos del bug original), y el ABA byte-exacto (dos mutaciones con
// reversión idéntica dentro de la ventana). Si el residuo muerde en la
// práctica, el manifiesto de entradas de W1 añade mtime capturado en el
// instante del diff.
type Cacheable struct {
	Clave    string
	Vigente  func() bool
	Findings []finding.Finding
}

// VigenciaDeArchivo es el Vigente de una clave cuya fuente es la huella de UN
// archivo: recalcula gitdiff.SHA256De —la MISMA definición que usó el diff—
// en el momento de guardar. Dos definiciones de la huella fue exactamente la
// clase de deriva que este paquete no se puede permitir.
func VigenciaDeArchivo(repoRoot, rel, sha string) func() bool {
	return func() bool { return gitdiff.SHA256De(repoRoot, rel) == sha }
}

// VigenciaDeArchivos cubre las entradas COMPARTIDAS por contenido (dos rutas,
// misma huella): todas las rutas deben seguir teniendo el contenido que la
// clave describe, porque el acierto futuro puede servirle a cualquiera.
func VigenciaDeArchivos(repoRoot string, rels []string, sha string) func() bool {
	return func() bool {
		for _, rel := range rels {
			if gitdiff.SHA256De(repoRoot, rel) != sha {
				return false
			}
		}
		return true
	}
}

// VigenciaDeClave es el Vigente genérico para claves compuestas (huella de
// módulo + config + día…): recalcular exige repetir la misma construcción, y
// eso solo lo sabe hacer quien la armó.
func VigenciaDeClave(clave string, recalcular func() string) func() bool {
	return func() bool { return recalcular() == clave }
}

// HuellaModulo resume el contenido de un módulo en una sola huella: los
// archivos RASTREADOS del directorio dado que pasen el filtro, con su sha de
// contenido del árbol de trabajo. Es la clave de caché de los motores que
// analizan el módulo entero: módulo sin cambios = mismos hallazgos.
//
// Punto ciego asumido: los archivos sin rastrear no entran en la huella
// aunque el compilador los vea — el mismo punto ciego que ya tiene el
// informe, que solo alimenta archivos rastreados. Devuelve vacío (no
// cacheable) si el módulo no se puede enumerar.
func HuellaModulo(repoRoot, dir string, filtro func(rel string) bool) string {
	return LeerHuellasRepo(repoRoot).Modulo(dir, filtro)
}

// HuellasRepo es el recorrido del repo hecho UNA vez, para quien necesita varias
// huellas en la misma corrida.
//
// Existe por dotnetbuild: pedía una huella por cada .csproj tocado y cada
// llamada pagaba un `git ls-files` del repo entero, más el re-hash de los
// archivos compartidos por varios proyectos (el caso típico de un Core.csproj
// referenciado por todos). En un monorepo eso se come una parte real del
// presupuesto del gancho, que es un pre-commit con el dev esperando.
//
// La alternativa era que el llamador replicara el formato de la huella para
// derivarla él; se descartó porque dos copias del mismo formato divergen, y aquí
// divergir significa que una clave de caché deja de corresponder a su contenido.
// Así el formato vive en un solo sitio —Modulo— y lo que se comparte es el
// trabajo.
//
// Los shas se calculan PEREZOSAMENTE y se memorizan: una sola huella cuesta
// exactamente lo que costaba (sólo se hashea lo que pasa el filtro), y varias
// comparten tanto el listado como los archivos que tengan en común.
//
// No es seguro usarlo desde varias goroutines: el memo no lleva candado porque
// el único consumidor recorre sus proyectos en serie.
type HuellasRepo struct {
	repoRoot   string
	rutas      []string
	shas       map[string]string
	enumerable bool
}

// LeerHuellasRepo enumera los archivos rastreados. Si el repo no se puede
// enumerar, las huellas que salgan de aquí serán vacías — o sea "no cacheable",
// el mismo criterio que tenía HuellaModulo.
func LeerHuellasRepo(repoRoot string) *HuellasRepo {
	rutas, err := gitdiff.Rastreados(repoRoot)
	return &HuellasRepo{
		repoRoot:   repoRoot,
		rutas:      rutas,
		shas:       make(map[string]string, len(rutas)),
		enumerable: err == nil && len(rutas) > 0,
	}
}

func (h *HuellasRepo) sha(rel string) string {
	if s, ok := h.shas[rel]; ok {
		return s
	}
	s := gitdiff.SHA256De(h.repoRoot, rel)
	h.shas[rel] = s
	return s
}

// Modulo es HuellaModulo sobre un recorrido ya hecho. Mismo formato, byte a byte:
// las claves de caché ya guardadas siguen siendo válidas.
func (h *HuellasRepo) Modulo(dir string, filtro func(rel string) bool) string {
	if h == nil || !h.enumerable {
		return ""
	}
	rutas := h.rutas
	prefijo := ""
	if dir != "." && dir != "" {
		prefijo = strings.TrimSuffix(dir, "/") + "/"
	}
	var partes []string
	for _, r := range rutas {
		if prefijo != "" && !strings.HasPrefix(r, prefijo) {
			continue
		}
		if filtro != nil && !filtro(r) {
			continue
		}
		sha := h.sha(r)
		if sha == "" {
			// Un archivo ilegible haría la huella inestable: mejor no cachear.
			return ""
		}
		partes = append(partes, r+":"+sha)
	}
	if len(partes) == 0 {
		return ""
	}
	sort.Strings(partes)
	sum := sha256.Sum256([]byte(strings.Join(partes, "\n")))
	return hex.EncodeToString(sum[:])
}
