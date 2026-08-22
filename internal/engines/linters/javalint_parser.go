package linters

import (
	"encoding/json"
	"fmt"
	"strings"

	"codeguard/internal/finding"
)

// ── la salida JSON de PMD ────────────────────────────────────────────────────

type pmdReporte struct {
	Files []struct {
		Filename   string         `json:"filename"`
		Violations []pmdViolacion `json:"violations"`
	} `json:"files"`
	// ProcessingErrors son los archivos que PMD NO pudo analizar (no parsean, no
	// se pudieron leer). Salen con código 5 y el resto del informe es válido.
	ProcessingErrors []struct {
		Filename string `json:"filename"`
		Message  string `json:"message"`
	} `json:"processingErrors"`
	// ConfigurationErrors son problemas de las REGLAS que le pasamos, no del
	// código del usuario.
	ConfigurationErrors []struct {
		Rule    string `json:"rule"`
		Message string `json:"message"`
	} `json:"configurationErrors"`
}

type pmdViolacion struct {
	BeginLine int    `json:"beginline"`
	EndLine   int    `json:"endline"`
	Rule      string `json:"rule"`
	RuleSet   string `json:"ruleset"`
	// Priority es 1 (la más alta) a 5. PMD la fija por regla en su catálogo.
	Priority        int    `json:"priority"`
	Description     string `json:"description"`
	ExternalInfoURL string `json:"externalInfoUrl"`
}

const porQuePMD = "Es análisis del AST de Java —PMD parsea el archivo y evalúa la regla sobre el árbol—, " +
	"no un parecido textual: lo que señala está en la estructura del código, no en cómo se escribió."

func hallazgosPMD(repoRoot, dirProyecto string, raw []byte) ([]finding.Finding, error) {
	var rep pmdReporte
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, fmt.Errorf("salida de pmd ilegible en %s: %v", dirProyecto, err)
	}
	// Un error de configuración es NUESTRO, no del repo: significa que la regla
	// no llegó a evaluarse. Presentar el resto como análisis completo sería
	// prometer una cobertura que no hubo, así que la capa se declara degradada
	// entera — el mismo corte que hace biome con sus internalError.
	if len(rep.ConfigurationErrors) > 0 {
		c := rep.ConfigurationErrors[0]
		return nil, fmt.Errorf("pmd no pudo cargar sus reglas en %s (%s): %s",
			dirProyecto, c.Rule, jRecortar(colapsar(c.Message), 300))
	}

	var findings []finding.Finding
	for _, a := range rep.Files {
		file := rutaRepoJava(repoRoot, dirProyecto, a.Filename)
		for _, v := range a.Violations {
			sev, bloquea := severidadPMD(v.Priority)
			f := finding.Finding{
				Engine:   "pmd",
				RuleKey:  v.Rule,
				Pillar:   finding.Quality,
				Severity: sev,
				Blocking: bloquea,
				File:     file,
				Line:     maxLinea(v.BeginLine),
				EndLine:  v.EndLine,
				Message:  v.Description,
				Why:      porQuePMD,
				FixHint:  arregloPMD(v),
				Verified: true,
				Source:   finding.Deterministic,
				// El fingerprint (§9) no lleva número de línea para sobrevivir a
				// los desplazamientos del archivo; con la regla y la descripción
				// dentro, dos violaciones distintas de la misma regla en el mismo
				// archivo siguen siendo dos hallazgos.
				LineContent: v.Rule + " " + v.Description,
			}
			f.ComputeFingerprint()
			findings = append(findings, f)
		}
	}

	// Un archivo que no parsea NO se calla. PMD es el único motor de este
	// producto que mira la sintaxis de Java (no hay compuerta de compilación
	// para Java como tsc o dotnet build), así que ignorarlo dejaría pasar un
	// .java roto con el informe en verde. Tampoco degrada el motor entero: los
	// demás archivos SÍ se analizaron y sus hallazgos son válidos, a diferencia
	// de dotnet-build donde el fallo es del proyecto completo.
	for _, pe := range rep.ProcessingErrors {
		file := rutaRepoJava(repoRoot, dirProyecto, pe.Filename)
		// message trae la primera línea útil y luego el volcado del parser; el
		// "detail" con el stack trace entero se ignora a propósito.
		msg := jRecortar(colapsar(pe.Message), 300)
		f := finding.Finding{
			Engine:      "pmd",
			RuleKey:     "processing-error",
			Pillar:      finding.Quality,
			Severity:    finding.Error,
			Blocking:    true,
			File:        file,
			Line:        1,
			Message:     "PMD no pudo analizar este archivo: " + msg,
			Why:         "Sin AST no hay análisis: este archivo quedó SIN revisar, y decir lo contrario sería reportar limpio lo que nadie miró.",
			FixHint:     "Casi siempre es sintaxis inválida: corrige lo que señala el mensaje (trae línea y columna) y el archivo vuelve a entrar en el análisis.",
			Verified:    true,
			Source:      finding.Deterministic,
			LineContent: "processing-error " + msg,
		}
		f.ComputeFingerprint()
		findings = append(findings, f)
	}
	return findings, nil
}

// falloProyectoPMD convierte el fallo acotado de UN proyecto en un hallazgo
// bloqueante: ese proyecto quedó sin revisar y el informe tiene que decirlo, ni
// salir en verde ni tirar los proyectos que sí se analizaron. Es el equivalente
// por proyecto del processing-error por archivo.
func falloProyectoPMD(dir string, err error) finding.Finding {
	msg := jRecortar(colapsar(err.Error()), 300)
	f := finding.Finding{
		Engine:      "pmd",
		RuleKey:     "project-error",
		Pillar:      finding.Quality,
		Severity:    finding.Error,
		Blocking:    true,
		File:        dir,
		Line:        1,
		Message:     "PMD no pudo analizar este proyecto: " + msg,
		Why:         "Este proyecto quedó SIN revisar; los demás sí se analizaron y sus hallazgos son válidos.",
		FixHint:     "Corrige la causa que señala el mensaje y el proyecto vuelve a entrar en el análisis.",
		Verified:    true,
		Source:      finding.Deterministic,
		LineContent: "project-error " + msg,
	}
	f.ComputeFingerprint()
	return f
}

// severidadPMD traduce la prioridad de PMD a la política §7.
//
// 1 y 2 son las que PMD reserva para lo que casi siempre es un defecto real
// (BrokenNullCheck: el null check está escrito al revés y va a lanzar NPE;
// DoubleCheckedLocking: el patrón roto de siempre): bloquean, como el lint de
// severidad error de eslint y govet.
//
// 3, 4 y 5 avisan. Son las de criterio (ForLoopCanBeForeach,
// SimplifyBooleanReturns): tienen razón, pero en código existente hay cientos y
// convertirlas en bloqueantes haría el hook inusable el primer día — que es
// como se acaba desinstalando, la misma razón por la que dotnet-build no pasa
// -warnaserror.
func severidadPMD(prioridad int) (finding.Severity, bool) {
	if prioridad >= 1 && prioridad <= 2 {
		return finding.Error, true
	}
	return finding.Warning, false
}

// arregloPMD da la ficha de la regla cuando PMD la trae, que es casi siempre:
// la ficha explica el porqué y trae el ejemplo bueno y el malo, que es mejor
// consejo del que podríamos escribir nosotros para 124 reglas.
func arregloPMD(v pmdViolacion) string {
	if u := strings.TrimSpace(v.ExternalInfoURL); u != "" {
		return "Ficha de la regla (con ejemplo correcto e incorrecto): " + u
	}
	return "Regla " + v.Rule + " del conjunto " + v.RuleSet + " de PMD; corrige lo que señala el mensaje."
}
