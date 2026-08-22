package pipeline

import (
	"time"

	"codeguard/internal/capas"
	"codeguard/internal/config"
	"codeguard/internal/engines"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
)

type Verdict string

const (
	Pass    Verdict = "pass"
	Block   Verdict = "block"
	Skipped Verdict = "skipped"
)

const (
	MotivoNoEnrolado   = "repo no enrolado (falta .codeguard/config.yaml)"
	MotivoSinDiff      = "sin diff que analizar"
	MotivoMergeORevert = "merge o revert"
	MotivoTodoExcluido = "todos los archivos tocados están excluidos"
)

func EsDecisionDelEquipo(motivo string) bool {
	switch motivo {
	case MotivoTodoExcluido, MotivoMergeORevert:
		return true
	}
	return false
}

type Result struct {
	Verdict          Verdict           `json:"verdict"`
	Reason           string            `json:"reason,omitempty"`
	BlockingFindings int               `json:"blocking_findings"`
	AdvisoryFindings int               `json:"advisory_findings"`
	Suppressed       int               `json:"suppressed"`
	Degraded         []string          `json:"degraded"`
	Findings         []finding.Finding `json:"findings"`
	ElapsedMs        int64             `json:"elapsed_ms"`
	Capas            []capas.Capa      `json:"capas"`
}

type Options struct {
	Config       *config.Config
	Diff         *gitdiff.Diff
	Secrets      engines.Engine   // etapa 1, fail-closed
	Engines      []engines.Engine // etapa 2
	Rulepack     string           // ruta al rulepack pinneado
	IsMerge      bool
	IsRevert     bool
	Timeout      time.Duration
	Suppressions map[string]bool
	DemotedRules map[string]bool
	Progreso     func(Avance)
}
