// Package pipeline orquesta las etapas del embudo (sección 5).
// Fase 1: etapas 0 (elegibilidad), 1 (secretos), 2 (deterministas) y 7 (consolidación).
package pipeline

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/gobwas/glob"
	"golang.org/x/sync/errgroup"

	"codeguard/internal/config"
	"codeguard/internal/engines"
	"codeguard/internal/engines/gitleaks"
	"codeguard/internal/engines/semgrep"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
)

type Verdict string

const (
	Pass    Verdict = "pass"
	Block   Verdict = "block"
	Skipped Verdict = "skipped"
)

type Result struct {
	Verdict          Verdict           `json:"verdict"`
	Reason           string            `json:"reason,omitempty"`
	BlockingFindings int               `json:"blocking_findings"`
	AdvisoryFindings int               `json:"advisory_findings"`
	Suppressed       int               `json:"suppressed"`
	Degraded         []string          `json:"degraded"`
	Findings         []finding.Finding `json:"findings"`
	ElapsedMs        int64             `json:"elapsed_ms"`
}

type Options struct {
	Config   *config.Config
	Diff     *gitdiff.Diff
	Secrets  engines.Engine   // etapa 1, fail-closed
	Engines  []engines.Engine // etapa 2
	Rulepack string           // ruta al rulepack pinneado
	IsMerge  bool
	IsRevert bool
	Timeout  time.Duration
	// Suppressions: fingerprints de la baseline (§17 paso 4) — hallazgos
	// preexistentes que no deben bloquear. Los secretos NUNCA se suprimen.
	Suppressions map[string]bool
	// DemotedRules: "engine/rule_key" degradadas de bloqueante a aviso por el
	// feedback del equipo (auto-calibración). Los secretos nunca se degradan.
	DemotedRules map[string]bool
}

// Run ejecuta el embudo determinista y devuelve el resultado consolidado.
func Run(ctx context.Context, opt Options) (*Result, error) {
	start := time.Now()
	res := &Result{Verdict: Pass, Degraded: []string{}}
	defer func() { res.ElapsedMs = time.Since(start).Milliseconds() }()

	// ── Etapa 0: elegibilidad ────────────────────────────────────────────
	if opt.Config == nil {
		res.Verdict, res.Reason = Skipped, "repo no enrolado (falta .codeguard/config.yaml)"
		return res, nil
	}
	if opt.IsMerge || opt.IsRevert {
		res.Verdict, res.Reason = Skipped, "merge o revert"
		return res, nil
	}
	files := filterExcluded(opt.Config, opt.Diff.Files)
	if len(files) == 0 {
		res.Verdict, res.Reason = Skipped, "todos los archivos tocados están excluidos"
		return res, nil
	}
	degradeToSecretsOnly := opt.Diff.Lines > opt.Config.MaxDiffLines

	if opt.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opt.Timeout)
		defer cancel()
	}

	in := engines.Input{
		RepoRoot:    opt.Config.RepoRoot,
		Files:       files,
		RulepackDir: opt.Rulepack,
	}

	// ── Etapa 1: secretos (BLOQUEANTE, fail-closed) ──────────────────────
	// Secrets es nil cuando la etapa ya corrió en el proceso del hook (§5).
	if opt.Secrets != nil {
		secretFindings, err := opt.Secrets.Run(ctx, in)
		if err != nil {
			if errors.Is(err, gitleaks.ErrUnavailable) {
				// Única ruta de error que bloquea (sección 14).
				res.Verdict = Block
				res.Reason = fmt.Sprintf("la compuerta de secretos no pudo correr (fail-closed): %v", err)
				return res, nil
			}
			return nil, err
		}
		res.Findings = append(res.Findings, secretFindings...)
	}

	// ── Etapa 2: compuertas deterministas en paralelo ────────────────────
	if degradeToSecretsOnly {
		res.Degraded = append(res.Degraded, "deterministic:diff_too_large")
	} else {
		g, gctx := errgroup.WithContext(ctx)
		results := make([][]finding.Finding, len(opt.Engines))
		failures := make([]error, len(opt.Engines))
		for i, eng := range opt.Engines {
			if !eng.Applies(in) {
				continue
			}
			g.Go(func() error {
				t0 := time.Now()
				fs, err := eng.Run(gctx, in)
				// El desglose por motor es la única forma de saber quién se
				// come el presupuesto: el total ya lo dice ElapsedMs, pero un
				// total gordo sin desglose obliga a adivinar.
				log.Printf("%s: %d hallazgo(s) en %dms", eng.Name(), len(fs), time.Since(t0).Milliseconds())
				if err != nil {
					failures[i] = err // no bloquea: se degrada (sección 14)
					return nil
				}
				results[i] = fs
				return nil
			})
		}
		if err := g.Wait(); err != nil {
			return nil, err
		}
		for i, fs := range results {
			res.Findings = append(res.Findings, fs...)
			if failures[i] == nil {
				continue
			}
			// Un motor NO INSTALADO es un asunto de configuración, no una
			// degradación del análisis: se informa distinto para que un trivy
			// ausente no pinte de naranja cada commit del día.
			if errors.Is(failures[i], semgrep.ErrSinRulepack) {
				// Sin rulepack no hay paridad con el CI, que es la promesa
				// central: se nombra aparte para poder decirlo con claridad.
				res.Degraded = append(res.Degraded, "rulepack-ausente:"+opt.Config.Rulepack)
			} else if isMissingBinary(failures[i]) {
				res.Degraded = append(res.Degraded, "falta:"+opt.Engines[i].Name())
			} else if errors.Is(failures[i], context.DeadlineExceeded) {
				// "No terminó a tiempo" no es "falló". Un motor que se pasa del
				// presupuesto en su primera corrida en frío —staticcheck compila
				// el módulo, eslint arranca node— vuelve a entrar en cuanto el
				// caché está caliente, y decirle "error" al desarrollador lo
				// manda a buscar una avería que no existe. Pasó tras una
				// instalación limpia: staticcheck y eslint aparecieron como
				// error y en la corrida siguiente tardaron 502 ms y 610 ms.
				log.Printf("%s no cupo en el plazo: %v", opt.Engines[i].Name(), failures[i])
				res.Degraded = append(res.Degraded, opt.Engines[i].Name()+":plazo")
			} else {
				// La etiqueta corta viaja al veredicto; el PORQUÉ va al log.
				// Antes el mensaje del motor se tiraba aquí mismo y diagnosticar
				// un "semgrep:error" exigía reproducirlo a mano con suerte.
				log.Printf("%s degradado: %v", opt.Engines[i].Name(), failures[i])
				res.Degraded = append(res.Degraded, opt.Engines[i].Name()+":error")
			}
		}
	}

	// ── Etapa 2b: reglas del playbook sobre el repo y el cambio ──────────
	// No dependen de ningún motor externo ni de la red, así que corren
	// siempre, incluso con el diff degradado a solo-secretos.
	res.Findings = append(res.Findings, revisarLockfiles(opt.Config, files)...)
	res.Findings = append(res.Findings, revisarTamano(opt.Diff, files)...)
	res.Findings = append(res.Findings, revisarComplejidad(opt.Config, files)...)

	// ── Auto-calibración: reglas con exceso de falsos positivos (según el
	// feedback del equipo en ESTE repo) bajan a aviso. gitleaks jamás. ────
	if len(opt.DemotedRules) > 0 {
		for i := range res.Findings {
			f := &res.Findings[i]
			if f.Engine != "gitleaks" && f.Blocking && opt.DemotedRules[f.Engine+"/"+f.RuleKey] {
				f.Blocking = false
				f.Severity = finding.Warning
				f.Why = strings.TrimSpace("Regla degradada a aviso por el feedback del equipo (exceso de falsos positivos aquí). " + f.Why)
			}
		}
	}

	// ── Supresiones de baseline: solo lo nuevo bloquea ──────────────────
	if len(opt.Suppressions) > 0 {
		kept := res.Findings[:0]
		for _, f := range res.Findings {
			// La compuerta de secretos no admite baseline: un secreto viejo
			// sigue siendo un secreto vivo.
			if f.Engine != "gitleaks" && opt.Suppressions[f.Fingerprint] {
				res.Suppressed++
				continue
			}
			kept = append(kept, f)
		}
		res.Findings = kept
	}

	// ── Etapa 7: consolidación ───────────────────────────────────────────
	res.Findings = consolidate(res.Findings)
	for _, f := range res.Findings {
		if f.Blocking {
			res.BlockingFindings++
		} else {
			res.AdvisoryFindings++
		}
	}
	if res.BlockingFindings > 0 {
		res.Verdict = Block
	}
	return res, nil
}

// isMissingBinary distingue "la herramienta no está instalada" de "corrió y
// falló". La distinción importa porque cambia el mensaje: un motor ausente es
// un asunto de configuración ("falta: trivy") y no una degradación del
// análisis, y confundirlos pinta de naranja cada commit del día.
//
// Los dos caminos por los que Go reporta un binario que no está, comprobados
// midiendo en vez de suponiendo:
//   - no está en el PATH  → exec.ErrNotFound
//   - ruta absoluta que no existe → un *fs.PathError con fs.ErrNotExist
//
// Antes esto se cerraba comparando el TEXTO del error ("cannot find the file",
// "el sistema no puede encontrar"), o sea el mensaje que Windows traduce al
// idioma del sistema: en un Windows en francés o alemán la comparación no
// casaba y un motor ausente se reportaba como fallo del análisis. Las dos
// comprobaciones de arriba son del sistema de errores, no del idioma.
func isMissingBinary(err error) bool {
	return errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist)
}

// SoloFaltantes indica si todas las capas degradadas son motores ausentes
// (configuración) y no fallos reales del análisis.
func SoloFaltantes(degraded []string) bool {
	for _, d := range degraded {
		if !strings.HasPrefix(d, "falta:") {
			return false
		}
	}
	return len(degraded) > 0
}

func filterExcluded(cfg *config.Config, files []gitdiff.ChangedFile) []gitdiff.ChangedFile {
	patterns := make([]glob.Glob, 0, len(cfg.Paths.Exclude)+len(cfg.Paths.Generated))
	for _, p := range append(append([]string{}, cfg.Paths.Exclude...), cfg.Paths.Generated...) {
		if g, err := glob.Compile(p, '/'); err == nil {
			patterns = append(patterns, g)
		}
	}
	var kept []gitdiff.ChangedFile
	for _, f := range files {
		excluded := false
		for _, g := range patterns {
			if g.Match(f.Path) {
				excluded = true
				break
			}
		}
		if !excluded {
			kept = append(kept, f)
		}
	}
	return kept
}

// consolidate implementa la etapa 7: dedupe por (archivo, línea, regla) y
// orden por severidad (error > warning > info) y luego por archivo/línea.
func consolidate(fs []finding.Finding) []finding.Finding {
	seen := map[string]bool{}
	out := fs[:0]
	for _, f := range fs {
		key := fmt.Sprintf("%s|%d|%s", f.File, f.Line, f.RuleKey)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	rank := map[finding.Severity]int{finding.Error: 0, finding.Warning: 1, finding.Info: 2}
	sort.SliceStable(out, func(a, b int) bool {
		if out[a].Blocking != out[b].Blocking {
			return out[a].Blocking
		}
		if rank[out[a].Severity] != rank[out[b].Severity] {
			return rank[out[a].Severity] < rank[out[b].Severity]
		}
		if out[a].File != out[b].File {
			return out[a].File < out[b].File
		}
		return out[a].Line < out[b].Line
	})
	return out
}
