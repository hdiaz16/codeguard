package pipeline

import (
	"time"

	"codeguard/internal/capas"
	"codeguard/internal/config"
	"codeguard/internal/engines"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
	"codeguard/internal/rulepack"
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
	// Rulepack es la identidad de las reglas que CORRIERON (W3): versión
	// pinneada, digest del árbol, origen y si el manifiesto verificó. Vacía en
	// corridas sin identidad resoluble o de llamadores viejos — legacy
	// explícito, jamás se re-infiere (t.103).
	Rulepack rulepack.Identity `json:"rulepack"`
	// AislamientoDegradado (W4, t.116): facetas del sandbox que NO se
	// activaron en esta corrida (token-restringido, job, matarile-arbol,
	// limites-ui), deduplicadas entre motores. Canal SEPARADO de Degraded a
	// propósito: los motores corrieron y la garantía de COBERTURA está
	// intacta — lo degradado es el aislamiento, y mezclarlos en SinGarantia
	// pintaría de naranja cada commit de una máquina sin tokens restringidos
	// hasta enseñar a ignorar el color.
	AislamientoDegradado []string `json:"aislamiento_degradado,omitempty"`
}

type Options struct {
	Config  *config.Config
	Diff    *gitdiff.Diff
	Secrets engines.Engine   // etapa 1, fail-closed
	Engines []engines.Engine // etapa 2
	// Rulepack es la RUTA que consumen los motores; RulepackID es la identidad
	// resuelta que se estampa en el Result. Los llamadores de producción pasan
	// las dos desde rulepack.Resolver (Rulepack == RulepackID.Path); los tests
	// que solo analizan pueden dar la ruta sola y el Result queda sin identidad.
	Rulepack     string
	RulepackID   rulepack.Identity
	IsMerge      bool
	IsRevert     bool
	Timeout      time.Duration
	Suppressions map[string]bool
	DemotedRules map[string]bool
	Progreso     func(Avance)
}
