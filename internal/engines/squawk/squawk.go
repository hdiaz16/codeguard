// Package squawk adapta el linter de migraciones PostgreSQL (pilar datos,
// sección 6.3.1 — bloqueante por riesgo de caída de producción).
package squawk

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"

	"github.com/gobwas/glob"

	"codeguard/internal/engines"
	"codeguard/internal/engines/proc"
	"codeguard/internal/finding"
)

type Engine struct {
	Binary string // vacío = buscar en PATH
	// MigrationGlobs viene de paths.migrations de la config.
	MigrationGlobs []string
}

func (e *Engine) Name() string { return "squawk" }

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

func (e *Engine) Applies(in engines.Input) bool { return len(e.migrationFiles(in)) > 0 }

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
		return nil, fmt.Errorf("squawk no corrió: %v", runErr)
	}
	if salida.Recortada {
		return nil, fmt.Errorf("squawk devolvió más de %d MB de salida", proc.MaxSalida>>20)
	}
	var violations []violation
	if err := json.Unmarshal(out, &violations); err != nil {
		return nil, fmt.Errorf("salida de squawk ilegible: %v", err)
	}

	findings := make([]finding.Finding, 0, len(violations))
	for _, v := range violations {
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
			FixHint:  arreglo,
			Verified: true,
			Source:   finding.Deterministic,
			// El SQL de la línea puede no estar disponible; el fingerprint usa regla+ruta.
			LineContent: v.Rule,
		}
		f.ComputeFingerprint()
		findings = append(findings, f)
	}
	return findings, nil
}
