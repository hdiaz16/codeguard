// Package engines define la interfaz común de los adaptadores de escáneres
// (sección 18: un adaptador por herramienta).
package engines

import (
	"context"

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
