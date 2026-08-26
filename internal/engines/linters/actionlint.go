package linters

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"codeguard/internal/engines"
	"codeguard/internal/engines/contrato"
	"codeguard/internal/finding"
	"codeguard/internal/fsutil"
)

// ActionLint adapta actionlint —el linter de workflows de GitHub Actions— al
// contrato. La cadena de CI es superficie de ataque real y hasta aquí nadie la
// miraba: inyección de shell por `${{ github.event... }}` sin comillas, permisos
// del GITHUB_TOKEN más amplios de lo necesario, `run` con expresiones
// interpoladas, acciones sin pinnear. actionlint las caza con alta certeza (no
// hace nits de estilo), así que sus hallazgos BLOQUEAN (§7).
type ActionLint struct {
	Binary string
	Cache  engines.Cache
}

func (ActionLint) Name() string { return "actionlint" }

// esWorkflow reconoce los archivos que actionlint analiza: YAML bajo
// .github/workflows/ (la ruta viaja con '/' desde el diff). Las composite
// actions (action.yml) quedan fuera: actionlint valida workflows, no acciones.
func esWorkflow(p string) bool {
	p = filepath.ToSlash(p)
	if !strings.HasPrefix(p, ".github/workflows/") && !strings.Contains(p, "/.github/workflows/") {
		return false
	}
	return strings.HasSuffix(p, ".yml") || strings.HasSuffix(p, ".yaml")
}

func (ActionLint) Applies(in engines.Input) bool {
	for _, f := range in.Files {
		if f.Status != "D" && esWorkflow(f.Path) {
			return true
		}
	}
	return false
}

// actionlintError es una entrada del arreglo JSON que emite
// `actionlint -format '{{json .}}'`.
type actionlintError struct {
	Message  string `json:"message"`
	Filepath string `json:"filepath"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
	Kind     string `json:"kind"`
	Snippet  string `json:"snippet"`
}

func (e ActionLint) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	bin := e.Binary
	if bin == "" {
		bin = "actionlint"
	}

	var rutas []string
	for _, f := range in.Files {
		if f.Status != "D" && esWorkflow(f.Path) {
			rutas = append(rutas, f.Path)
		}
	}
	if len(rutas) == 0 {
		return nil, nil
	}
	sanitizadas := fsutil.SanitizarRutas(in.RepoRoot, rutas)
	if len(sanitizadas) == 0 {
		return nil, nil
	}

	// -format '{{json .}}' emite el arreglo de errores; -no-color para que el
	// panel no reciba secuencias ANSI. Se le pasan los workflows TOCADOS, no
	// todo .github/workflows, para no reportar lo que este cambio no tocó.
	args := []string{"-format", "{{json .}}", "-no-color"}
	args = append(args, fsutil.ComoArgumentosCLI(sanitizadas)...)

	salida, fallo, err := runToolConSalida(ctx, "actionlint", in.RepoRoot, bin, args...)
	if err != nil {
		return nil, fmt.Errorf("actionlint no corrió: %w", err)
	}

	findings, parseErr := hallazgosActionLint(in.RepoRoot, salida)
	if parseErr != nil {
		return nil, parseErr
	}

	// Silencio con éxito: actionlint limpio sale con 0 y escribe "[]" o nada.
	// Un exit ≠ 0 sin diagnósticos es "no llegó a analizar" (no está instalado,
	// o un workflow ilegible), y ahí se le pregunta quién es en vez de servir un
	// limpio falso.
	if len(findings) == 0 && fallo {
		if err := contrato.Identidad(ctx, contrato.Version("actionlint", bin, "-version",
			regexp.MustCompile(`\d+\.\d+`),
			"Instala actionlint (https://github.com/rhysd/actionlint): `go install github.com/rhysd/actionlint/cmd/actionlint@latest`.",
		)); err != nil {
			return nil, err
		}
	}
	return findings, nil
}

func hallazgosActionLint(repoRoot, raw string) ([]finding.Finding, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}
	// El template deja el arreglo JSON; si viniera precedido de ruido, se corta
	// desde el primer '['.
	if i := strings.IndexByte(trimmed, '['); i > 0 {
		trimmed = trimmed[i:]
	}
	var errs []actionlintError
	if err := json.Unmarshal([]byte(trimmed), &errs); err != nil {
		return nil, fmt.Errorf("actionlint: salida JSON ilegible: %w", err)
	}

	var findings []finding.Finding
	for _, e := range errs {
		rel := filepath.ToSlash(e.Filepath)
		if filepath.IsAbs(e.Filepath) {
			if r, err := filepath.Rel(repoRoot, e.Filepath); err == nil {
				rel = filepath.ToSlash(r)
			}
		}
		kind := e.Kind
		if kind == "" {
			kind = "actionlint"
		}
		f := finding.Finding{
			Engine:   "actionlint",
			RuleKey:  kind,
			Pillar:   finding.Quality,
			Severity: finding.Error,
			Blocking: true,
			File:     rel,
			Line:     e.Line,
			Message:  e.Message,
			Why:      "actionlint valida los workflows de GitHub Actions con alta certeza: sintaxis, expresiones e inyección de shell son errores reales, no estilo — y la cadena de CI es superficie de ataque.",
			FixHint:  "Corrige lo que señala el mensaje; para inyección, entrecomilla la expresión o pásala por env en vez de interpolarla en `run`.",
			Verified: true,
			Source:   finding.Deterministic,
			// LineContent lo rellena finding.AsignarHuellas con la línea real del
			// workflow (motor nuevo: nace en v2, sin alias legacy que reconstruir).
		}
		f.Normalizar()
		findings = append(findings, f)
	}
	return findings, nil
}
