package linters

import (
	"bytes"
	"context"
	"go/format"
	"os"
	"path/filepath"

	"codeguard/internal/engines"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
)

// GoFmt implementa la compuerta de formato para Go (§7: formato BLOQUEA —
// auto-corregible, cero ambigüedad).
//
// No ejecuta el binario gofmt: usa go/format, que ES gofmt como librería.
// La versión anterior lanzaba `gofmt -l` y, por cada archivo con CRLF, otro
// gofmt por stdin para distinguir "mal formateado" de "sólo finales de línea"
// — en un repo Windows recién clonado eso son cientos de procesos bajo el
// sandbox (~6 s medidos) para responder que todo estaba bien. En proceso son
// milisegundos, no hay binario que pueda faltar, y la paridad con el CI queda
// por construcción: el CI corre este mismo código.
type GoFmt struct {
	// Cache por ARCHIVO. gofmt es el único motor que no lanza un proceso —usa
	// go/format en memoria— así que cachearlo parecía no valer la pena.
	//
	// Sí la vale, y por un motivo que no es el evidente: la huella del archivo
	// ya viene calculada en el diff, así que un acierto se ahorra LEER el
	// archivo y parsearlo, no sólo formatearlo. En un diff grande eso son
	// cientos de lecturas de disco que no ocurren.
	//
	// Y hay una razón que pesa más que el rendimiento: con gofmt fuera del
	// caché, la verificación de invalidación no podía medirse sobre todos los
	// motores a la vez y había que acotarla. Una medición acotada esconde
	// justo lo que no se está midiendo.
	Cache engines.Cache
}

func (GoFmt) Name() string { return "gofmt" }

func (GoFmt) Applies(in engines.Input) bool { return len(filesWithExt(in, ".go")) > 0 }

func (e GoFmt) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	archivos := filesWithExt(in, ".go")

	// ── Aciertos de caché ──
	// Direccionado por contenido: dos archivos idénticos comparten entrada, así
	// que al reproducir un acierto se reescribe la ruta y se recalcula la
	// huella para el archivo de ESTA corrida.
	var findings []finding.Finding
	pendientes := archivos
	if e.Cache != nil {
		var lista []string
		for _, cf := range archivos {
			if cf.SHA256 != "" {
				lista = append(lista, "gofmt:"+cf.SHA256)
			}
		}
		aciertos := e.Cache.Leer(lista)
		var quedan []gitdiff.ChangedFile
		for _, cf := range archivos {
			fs, ok := aciertos["gofmt:"+cf.SHA256]
			if cf.SHA256 == "" || !ok {
				quedan = append(quedan, cf)
				continue
			}
			for _, h := range fs {
				if h.File != cf.Path {
					h.File = cf.Path
					h.ComputeFingerprint()
				}
				findings = append(findings, h)
			}
		}
		pendientes = quedan
	}

	nuevos := []finding.Finding{}
	for _, cf := range pendientes {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		raw, err := os.ReadFile(filepath.Join(in.RepoRoot, filepath.FromSlash(cf.Path)))
		if err != nil {
			continue // borrado entre el diff y aquí; no hay nada que formatear
		}
		// Los finales de línea son asunto de git (.gitattributes), no del
		// formato: en Windows autocrlf deja CRLF en disco y bloquear por eso
		// convertiría el agente en un obstáculo. Se compara normalizado a LF.
		normalizado := bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))
		formateado, err := format.Source(normalizado)
		if err != nil {
			// No parsea como Go: eso lo señala govet/el compilador con un
			// mensaje mejor que el nuestro. El formato no es el problema.
			continue
		}
		if bytes.Equal(bytes.TrimRight(formateado, "\n"), bytes.TrimRight(normalizado, "\n")) {
			continue
		}
		f := finding.Finding{
			Engine:      "gofmt",
			RuleKey:     "gofmt",
			Pillar:      finding.Quality,
			Severity:    finding.Error,
			Blocking:    true,
			File:        cf.Path,
			Line:        1,
			Message:     "Archivo sin formatear (gofmt)",
			Why:         "El formato inconsistente genera diffs ruidosos y discusiones sin valor.",
			FixHint:     "Ejecuta `gofmt -w " + cf.Path + "` (es auto-corregible).",
			Verified:    true,
			Source:      finding.Deterministic,
			LineContent: cf.Path,
		}
		f.ComputeFingerprint()
		nuevos = append(nuevos, f)
	}

	if e.Cache != nil {
		e.Cache.Guardar(porArchivoGoFmt(nuevos, pendientes))
	}
	return append(findings, nuevos...), nil
}

// porArchivoGoFmt deja cada hallazgo bajo la clave de contenido de su archivo,
// e incluye los archivos LIMPIOS con lista vacía: "analizado y bien formateado"
// es el resultado que más veces se reutiliza, y es el 99% de los archivos.
func porArchivoGoFmt(fs []finding.Finding, archivos []gitdiff.ChangedFile) map[string][]finding.Finding {
	porRuta := map[string][]finding.Finding{}
	for _, f := range fs {
		porRuta[f.File] = append(porRuta[f.File], f)
	}
	out := map[string][]finding.Finding{}
	for _, a := range archivos {
		if a.SHA256 == "" {
			continue
		}
		out["gofmt:"+a.SHA256] = porRuta[a.Path]
	}
	return out
}
