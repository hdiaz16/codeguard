package linters

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"codeguard/internal/engines"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
)

// Ruff cubre dos compuertas de §7 para Python: lint de errores (ruff check,
// reglas por defecto E4/E7/E9/F que son errores genuinos → BLOQUEA) y
// formato (ruff format --check → BLOQUEA).
type Ruff struct {
	Binary string
	// Cache es por ARCHIVO: ruff evalúa cada .py por su cuenta, así que tocar
	// 1 de 200 cuesta 1.
	//
	// Faltaba, y no era gratis: ruff es un proceso externo que se lanzaba dos
	// veces (check y format) sobre TODOS los archivos Python del diff en cada
	// commit, incluidos los que nadie tocó desde la última vez. Se destapó al
	// verificar la invalidación del caché: los cuatro ejes se comprobaban sobre
	// semgrep y ruff quedaba fuera de la medición, que es tanto como decir que
	// nadie sabía si acertaba.
	//
	// La clave lleva dentro la configuración de ruff DEL REPO (ruff.toml,
	// pyproject.toml, setup.cfg). Sin eso, cambiar una regla en pyproject no
	// invalidaría nada y ruff seguiría dando el veredicto de la configuración
	// anterior — el mismo fallo que ya costó una corrección invisible con
	// govulncheck.
	Cache engines.Cache
}

func (Ruff) Name() string { return "ruff" }

func (Ruff) Applies(in engines.Input) bool { return len(filesWithExt(in, ".py")) > 0 }

type ruffDiag struct {
	Code     string `json:"code"`
	Message  string `json:"message"`
	Filename string `json:"filename"`
	Location struct {
		Row int `json:"row"`
	} `json:"location"`
	Fix *struct {
		Message string `json:"message"`
	} `json:"fix"`
}

func (e Ruff) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	bin := e.Binary
	if bin == "" {
		bin = "ruff"
	}
	archivos := filesWithExt(in, ".py")

	// ── Aciertos de caché ──
	//
	// La clave identifica al archivo por ruta Y contenido (ver claveRuff), así
	// que un acierto es siempre del MISMO archivo: los hallazgos se reproducen
	// tal cual, sin reescribir la ruta ni recalcular la huella.
	var findings []finding.Finding
	pendientes := archivos
	// La huella se calcula UNA vez y la comparten lectura y escritura. Antes se
	// recalculaba al guardar, y eso abría una ventana: un cambio de configuración
	// a mitad de corrida hacía escribir bajo una clave distinta de la leída, y el
	// caché dejaba de acertar sin que nada fallara.
	cfgHash := ""
	if e.Cache != nil {
		cfgHash = huellaConfigRuff(in.RepoRoot, archivos)
		claves := make(map[string]string, len(archivos)) // ruta → clave
		var lista []string
		for _, f := range archivos {
			if f.SHA256 == "" {
				continue // sin huella no es cacheable
			}
			k := claveRuff(cfgHash, f.Path, f.SHA256)
			claves[f.Path] = k
			lista = append(lista, k)
		}
		aciertos := e.Cache.Leer(lista)
		var quedan []gitdiff.ChangedFile
		for _, f := range archivos {
			k, tieneClave := claves[f.Path]
			fs, ok := aciertos[k]
			if !tieneClave || !ok {
				quedan = append(quedan, f)
				continue
			}
			findings = append(findings, fs...)
		}
		pendientes = quedan
	}
	if len(pendientes) == 0 {
		return findings, nil
	}

	var paths []string
	raiz := filepath.Clean(in.RepoRoot)
	for _, f := range pendientes {
		// La ruta sale del diff y acaba como argumento de un proceso externo:
		// Join la limpia pero no la CONTIENE, así que una absoluta o un ".." la
		// sacaría del repo y ruff analizaría archivos ajenos. Se rechaza con
		// error, no se salta en silencio: un diff así es avería o manipulación, y
		// omitir el archivo lo dejaría sin analizar dando el commit por bueno.
		rel := filepath.FromSlash(f.Path)
		abs := filepath.Join(raiz, rel)
		if filepath.IsAbs(rel) || (abs != raiz && !strings.HasPrefix(abs, raiz+string(filepath.Separator))) {
			return nil, fmt.Errorf("ruta del diff fuera del repo: %q", f.Path)
		}
		paths = append(paths, abs)
	}
	nuevos := []finding.Finding{}

	// ── lint de errores ──
	// El "--" separa banderas de operandos: una ruta que empiece por "-" no
	// debe leerse como bandera de ruff. clap lo honra en `check` y `format`.
	checkOut, err := runTool(ctx, "ruff", in.RepoRoot, bin, append([]string{"check", "--output-format", "json", "--exit-zero", "--"}, paths...)...)
	if err != nil {
		return nil, fmt.Errorf("ruff no corrió: %w", err)
	}
	var diags []ruffDiag
	if jerr := json.Unmarshal([]byte(checkOut), &diags); jerr != nil {
		return nil, fmt.Errorf("salida de ruff ilegible: %v", jerr)
	}
	for _, d := range diags {
		fix := "Revisa la regla " + d.Code + " en la documentación de Ruff."
		if d.Fix != nil && d.Fix.Message != "" {
			fix = d.Fix.Message + " (auto-corregible con `ruff check --fix`)."
		}
		f := finding.Finding{
			Engine:   "ruff",
			RuleKey:  d.Code,
			Pillar:   finding.Quality,
			Severity: finding.Error,
			Blocking: true,
			File:     relTo(in.RepoRoot, d.Filename),
			Line:     d.Location.Row,
			Message:  d.Message,
			Why:      "Las reglas por defecto de Ruff (pyflakes + errores de sintaxis) son errores reales, no estilo.",
			FixHint:  fix,
			Verified: true,
			Source:   finding.Deterministic,
			// LineContent lo rellena finding.AsignarHuellas con la línea real
			// (W6, t.128): la v1 hasheaba «regla mensaje» y su alias se
			// reconstruye en contenidoLegacy desde RuleKey+Message.
		}
		nuevos = append(nuevos, f)
	}

	// ── formato ──
	//
	// runToolConSalida y no runTool: `ruff format --check` sale con 1 cuando
	// hay archivos sin formatear (hallazgos) pero con 2 cuando NO PUDO revisar
	// —config inválida, sintaxis que no parsea, panic—. En ese caso la salida
	// no trae ni un "Would reformat:" ni un "-->", el parser de abajo no
	// extrae nada, y sin el código de salida eso se reportaba como "formato
	// limpio" sobre archivos que ruff no miró: el verde silencioso simétrico
	// al que runToolConSalida cerró en tsc.
	fmtOut, fmtFallo, err := runToolConSalida(ctx, "ruff", in.RepoRoot, bin, append([]string{"format", "--check", "--"}, paths...)...)
	if err != nil {
		return nil, fmt.Errorf("ruff format no corrió: %w", err)
	}
	seen := map[string]bool{}
	formatTargets := 0
	for _, line := range strings.Split(fmtOut, "\n") {
		line = strings.TrimSpace(line)
		var target string
		switch {
		// ruff < 0.9: "Would reformat: path"
		case strings.HasPrefix(line, "Would reformat: "):
			target = strings.TrimPrefix(line, "Would reformat: ")
		// ruff moderno: "--> path:linea:col"
		case strings.HasPrefix(line, "--> "):
			target = strings.TrimPrefix(line, "--> ")
			if i := strings.Index(target, ".py:"); i >= 0 {
				target = target[:i+3]
			}
		default:
			continue
		}
		formatTargets++
		rel := relTo(in.RepoRoot, target)
		if seen[rel] {
			continue
		}
		seen[rel] = true
		f := finding.Finding{
			Engine:      "ruff",
			RuleKey:     "ruff-format",
			Pillar:      finding.Quality,
			Severity:    finding.Error,
			Blocking:    true,
			File:        rel,
			Line:        1,
			Message:     "Archivo sin formatear (ruff format)",
			Why:         "El formato inconsistente genera diffs ruidosos y discusiones sin valor.",
			FixHint:     "Ejecuta `ruff format " + rel + "` (es auto-corregible).",
			Verified:    true,
			Source:      finding.Deterministic,
			LineContent: rel,
			Identidad:   finding.IdentidadSemantica,
		}
		nuevos = append(nuevos, f)
	}

	// Fail-closed: exit ≠0 sin UN SOLO target parseado significa que ruff no
	// revisó el formato (avería real), no que estaba todo limpio. Devolver
	// cero hallazgos aquí sería el verde silencioso, y encima quedaría
	// congelado en el caché como veredicto limpio — el agravante que ya se
	// sufrió con govet/govulncheck. Se devuelve error ANTES de Guardar, así
	// que una avería nunca se cachea.
	if fmtFallo && formatTargets == 0 {
		return nil, fmt.Errorf("ruff format falló al ejecutarse (no se pudo revisar el formato): %s", strings.TrimSpace(fmtOut))
	}

	if e.Cache != nil {
		e.Cache.Guardar(porArchivoRuff(nuevos, pendientes, cfgHash, in.RepoRoot))
	}
	return append(findings, nuevos...), nil
}

// claveRuff identifica el veredicto de ruff sobre UN archivo, y la construyen
// tanto la lectura como la escritura: una sola definición, o las dos mitades se
// desincronizan en silencio y el caché deja de acertar sin que nada falle.
//
// Lleva la RUTA dentro, no sólo la configuración y el contenido, porque el
// veredicto de ruff no es función de (config, contenido): ruff selecciona
// reglas por patrón de ruta —per-file-ignores, exclude, extend-exclude—, así
// que el mismo texto en tests/dup.py y en src/dup.py sale limpio en uno y con
// hallazgo en el otro, por decisión explícita del repo. Sin la ruta, el caché
// colapsaba en una entrada dos casos que ruff distingue y servía el veredicto
// del gemelo permisivo: el hallazgo del archivo estricto desaparecía del
// informe sin dejar rastro.
//
// La alternativa —mirar si la config trae per-file-ignores y sólo entonces
// meter la ruta— se descartó: exigiría parsear TOML y setup.cfg y cubrir
// exclude, extend-exclude, extend-per-file-ignores y lo que ruff añada mañana.
// Sería frágil por construcción, y lo que se compra a cambio es sólo compartir
// entrada entre archivos duplicados —un ahorro marginal— a cambio de arriesgar
// un fallo de corrección invisible.
func claveRuff(cfgHash, ruta, sha string) string {
	return "ruff:" + cfgHash + ":" + ruta + ":" + sha
}

// porArchivoRuff reparte los hallazgos por su archivo y los deja bajo la clave
// con la que se buscarán la próxima vez.
//
// Guarda TAMBIÉN los archivos limpios, con lista vacía: "analizado y sin nada"
// es el resultado que más veces se reutiliza, y no guardarlo dejaría el caché
// acertando sólo en los archivos con problemas — justo al revés de lo útil.
func porArchivoRuff(fs []finding.Finding, archivos []gitdiff.ChangedFile, cfgHash, repoRoot string) []engines.Cacheable {
	porRuta := map[string][]finding.Finding{}
	for _, f := range fs {
		porRuta[f.File] = append(porRuta[f.File], f)
	}
	out := make([]engines.Cacheable, 0, len(archivos))
	for _, a := range archivos {
		if a.SHA256 == "" {
			continue
		}
		out = append(out, engines.Cacheable{
			Clave:    claveRuff(cfgHash, a.Path, a.SHA256),
			Vigente:  engines.VigenciaDeArchivo(repoRoot, a.Path, a.SHA256),
			Findings: porRuta[a.Path],
		})
	}
	return out
}

// huellaConfigRuff resume todo lo que puede cambiar el veredicto de ruff sin que
// cambie el contenido del .py: la VERSIÓN del binario y la configuración que vive
// en el repo.
//
// La configuración va dentro de la clave porque ruff obedece a esos archivos:
// cambiar una regla en pyproject.toml cambia el veredicto sin que cambien ni el
// contenido del .py ni la configuración de CodeGuard. Sin esto, el caché serviría
// el resultado de la configuración anterior y la regla nueva no se aplicaría a
// nada que ya estuviera analizado — una corrección que no llega, que es el fallo
// que este proyecto lleva persiguiendo.
//
// La VERSIÓN del binario se auditó y se dejó FUERA a propósito: javafmt y
// javalint sí la meten, pero la leen de la ruta del artefacto versionado «sin
// pagar» un proceso extra (java.go), y a ruff lo instala pip como
// Scripts\ruff.exe, sin versión en la ruta — habría que invocar `ruff --version`
// en cada corrida. No compensa: el análisis es POR DIFF, así que un contenido
// distinto ya produce una clave distinta, y el único caso que quedaría fuera es
// que reaparezca un archivo con el MISMO sha y la misma config después de
// actualizar ruff.
//
// Y la configuración no es sólo la de la raíz: ruff la descubre por directorio y
// la de una subcarpeta manda sobre los archivos de esa subcarpeta. Se buscan
// configs en los directorios de los archivos afectados y sus padres hasta la
// raíz — recorrer el repo entero en cada commit costaría más de lo que el caché
// ahorra.
func huellaConfigRuff(repoRoot string, archivos []gitdiff.ChangedFile) string {
	h := sha256.New()
	// Se acumulan en un mapa y se hashean ORDENADAS: el orden en que git liste
	// los archivos del diff no puede cambiar la huella del mismo repo.
	configs := map[string][]byte{}
	raiz := filepath.Clean(repoRoot)
	for _, f := range archivos {
		dir := filepath.Dir(filepath.Join(raiz, filepath.FromSlash(f.Path)))
		for {
			if dir != raiz && !strings.HasPrefix(dir, raiz+string(filepath.Separator)) {
				break // ruta que se sale del repo: nada que buscar ahí fuera
			}
			for _, nombre := range []string{"ruff.toml", ".ruff.toml", "pyproject.toml", "setup.cfg"} {
				ruta := filepath.Join(dir, nombre)
				if _, ya := configs[ruta]; ya {
					continue
				}
				if b, err := os.ReadFile(ruta); err == nil {
					configs[ruta] = b
				}
			}
			if dir == raiz {
				break
			}
			dir = filepath.Dir(dir)
		}
	}
	rutas := make([]string, 0, len(configs))
	for r := range configs {
		rutas = append(rutas, r)
	}
	sort.Strings(rutas)
	for _, r := range rutas {
		h.Write([]byte(r))
		h.Write(configs[r])
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}
