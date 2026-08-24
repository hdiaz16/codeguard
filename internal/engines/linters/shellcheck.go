package linters

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"codeguard/internal/engines"
	"codeguard/internal/engines/contrato"
	"codeguard/internal/finding"
	"codeguard/internal/fsutil"
)

// ShellCheck adapta shellcheck —el linter de shell— al contrato. Los .sh
// (despliegue, hooks, CI) esconden bugs de comillas y de word-splitting que solo
// se notan el día que un path lleva un espacio. shellcheck los caza; sus errores
// bloquean (§7), sus avisos se dicen sin bloquear. Solo aplica si el cambio toca
// .sh/.bash; degrada a Ausente sin la herramienta.
type ShellCheck struct {
	Binary string
	Cache  engines.Cache
}

func (ShellCheck) Name() string { return "shellcheck" }

func archivosShell(in engines.Input) []string {
	var out []string
	for _, f := range in.Files {
		if f.Status == "D" {
			continue
		}
		p := filepath.ToSlash(f.Path)
		if strings.HasSuffix(p, ".sh") || strings.HasSuffix(p, ".bash") {
			out = append(out, f.Path)
		}
	}
	return out
}

func (ShellCheck) Applies(in engines.Input) bool { return len(archivosShell(in)) > 0 }

// shellcheckDiag es una entrada del arreglo JSON de `shellcheck --format=json`.
type shellcheckDiag struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	Level   string `json:"level"` // error | warning | info | style
	Code    int    `json:"code"`  // 2086 → SC2086
	Message string `json:"message"`
}

func (e ShellCheck) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	bin := e.Binary
	if bin == "" {
		bin = "shellcheck"
	}
	rutas := archivosShell(in)
	sanitizadas := fsutil.SanitizarRutas(in.RepoRoot, rutas)
	if len(sanitizadas) == 0 {
		return nil, nil
	}

	// --format=json emite el arreglo de diagnósticos; --external-sources=false
	// (por defecto) no sigue `source`/`.` fuera de los objetivos, que sería
	// analizar archivos no tocados.
	args := []string{"--format=json"}
	args = append(args, fsutil.ComoArgumentosCLI(sanitizadas)...)

	salida, fallo, err := runToolConSalida(ctx, in.RepoRoot, bin, args...)
	if err != nil {
		return nil, fmt.Errorf("shellcheck no corrió: %w", err)
	}

	findings, parseErr := hallazgosShellCheck(in.RepoRoot, salida)
	if parseErr != nil {
		return nil, parseErr
	}
	// shellcheck sale con 1 cuando encuentra algo (JSON válido igual) y con 0
	// cuando está limpio. Un exit ≠ 0 SIN diagnósticos parseados es "no llegó a
	// analizar": no está instalado, o un objetivo ilegible. Se le pregunta quién
	// es en vez de servir un limpio falso.
	if len(findings) == 0 && fallo {
		if err := contrato.Identidad(ctx, contrato.Version("shellcheck", bin, "--version",
			regexp.MustCompile(`(?i)shellcheck|version`),
			"Instala shellcheck (https://www.shellcheck.net/): `winget install koalaman.shellcheck` o el gestor de tu SO.",
		)); err != nil {
			return nil, err
		}
	}
	return findings, nil
}

func hallazgosShellCheck(repoRoot, raw string) ([]finding.Finding, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "null" || trimmed == "[]" {
		return nil, nil
	}
	if i := strings.IndexByte(trimmed, '['); i > 0 {
		trimmed = trimmed[i:]
	}
	var diags []shellcheckDiag
	if err := json.Unmarshal([]byte(trimmed), &diags); err != nil {
		return nil, fmt.Errorf("shellcheck: salida JSON ilegible: %w", err)
	}

	var findings []finding.Finding
	for _, d := range diags {
		rel := filepath.ToSlash(d.File)
		if filepath.IsAbs(d.File) {
			if r, err := filepath.Rel(repoRoot, d.File); err == nil {
				rel = filepath.ToSlash(r)
			}
		}
		sev, blocking := finding.Info, false
		switch strings.ToLower(d.Level) {
		case "error":
			sev, blocking = finding.Error, true
		case "warning":
			sev = finding.Warning
		}
		f := finding.Finding{
			Engine:   "shellcheck",
			RuleKey:  "SC" + strconv.Itoa(d.Code),
			Pillar:   finding.Quality,
			Severity: sev,
			Blocking: blocking,
			File:     rel,
			Line:     d.Line,
			Message:  d.Message,
			Why:      "shellcheck analiza el shell y demuestra los bugs de comillas y word-splitting: los errores rompen el script; los avisos son deuda que muerde el día que un path lleva un espacio.",
			FixHint:  "Corrige lo que señala; la explicación de la regla está en https://www.shellcheck.net/wiki/SC" + strconv.Itoa(d.Code),
			Verified: true,
			Source:   finding.Deterministic,
			// LineContent lo rellena finding.AsignarHuellas (motor nuevo, v2).
		}
		f.Normalizar()
		findings = append(findings, f)
	}
	return findings, nil
}
