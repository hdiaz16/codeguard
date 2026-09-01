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

// Gosec adapta el analizador de seguridad estático de Go (gosec)
// al contrato engines.Engine (Pilar 4: Cobertura de Élite en Go).
type Gosec struct {
	Binary string
	Cache  engines.Cache
}

func (Gosec) Name() string { return "gosec" }

func (Gosec) Applies(in engines.Input) bool {
	return len(filesWithExt(in, ".go")) > 0
}

type gosecReport struct {
	Issues []gosecIssue `json:"Issues"`
}

type gosecIssue struct {
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	Cwe        struct {
		ID  string `json:"id"`
		URL string `json:"url"`
	} `json:"cwe"`
	RuleID  string `json:"rule_id"`
	Details string `json:"details"`
	File    string `json:"file"`
	Code    string `json:"code"`
	Line    string `json:"line"`
	Column  string `json:"column"`
}

func (g Gosec) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	bin := g.Binary
	if bin == "" {
		bin = "gosec"
	}

	archivos := filesWithExt(in, ".go")
	if len(archivos) == 0 {
		return nil, nil
	}

	var rutasRelativas []string
	for _, f := range archivos {
		rutasRelativas = append(rutasRelativas, f.Path)
	}

	sanitizadas := fsutil.SanitizarRutas(in.RepoRoot, rutasRelativas)
	if len(sanitizadas) == 0 {
		return nil, nil
	}

	args := []string{"-fmt=json", "-terse"}
	args = append(args, paquetesGosec(sanitizadas)...)

	salida, fallo, err := runToolConSalida(ctx, "gosec", in.RepoRoot, bin, args...)
	if err != nil {
		return nil, fmt.Errorf("gosec no corrió: %w", err)
	}

	findings, parseErr := parseGosecJSON(salida, in.RepoRoot)
	if parseErr != nil {
		return nil, parseErr
	}

	if len(findings) == 0 {
		if fallo {
			return nil, fmt.Errorf("gosec salió con error y no produjo diagnósticos: %s", strings.TrimSpace(salida))
		}
		if err := contrato.Identidad(ctx, contrato.Version("gosec", bin, "-version",
			regexp.MustCompile(`(?i)(?:gosec|Version:\s*v?\d+\.\d+)`),
			"Instala gosec con `go install github.com/securego/gosec/v2/cmd/gosec@latest`.",
		)); err != nil {
			return nil, err
		}
	}

	return findings, nil
}

// gosec recibe paquetes de Go, no nombres de archivos. Pasarle main.go parece
// razonable pero lo interpreta como una ruta de importación y devuelve
// "cannot find package" sin analizar una sola línea. Agrupamos los archivos
// ya saneados por su directorio de paquete; el prefijo ./ evita que un nombre
// de directorio que empieza con guion se convierta en una opción.
func paquetesGosec(archivos []string) []string {
	vistos := map[string]bool{}
	var paquetes []string
	for _, archivo := range archivos {
		dir := filepath.ToSlash(filepath.Dir(archivo))
		paquete := "."
		if dir != "." {
			paquete = "./" + strings.TrimPrefix(dir, "./")
		}
		if !vistos[paquete] {
			vistos[paquete] = true
			paquetes = append(paquetes, paquete)
		}
	}
	return paquetes
}

func parseGosecJSON(raw, repoRoot string) ([]finding.Finding, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "{}" {
		return nil, nil
	}

	start := strings.Index(trimmed, "{")
	if start == -1 {
		return nil, fmt.Errorf("gosec: salida no contiene JSON: %q", raw)
	}
	trimmed = trimmed[start:]

	var report gosecReport
	if err := json.Unmarshal([]byte(trimmed), &report); err != nil {
		return nil, fmt.Errorf("gosec: error al decodificar JSON: %w", err)
	}

	var findings []finding.Finding
	for _, issue := range report.Issues {
		relPath := issue.File
		if filepath.IsAbs(relPath) {
			if rel, err := filepath.Rel(repoRoot, relPath); err == nil {
				relPath = rel
			}
		}
		relPath = filepath.ToSlash(relPath)

		lineNum, _ := strconv.Atoi(issue.Line)

		sev := finding.Warning
		blocking := false
		if strings.EqualFold(issue.Severity, "high") {
			sev = finding.Error
			blocking = true
		} else if strings.EqualFold(issue.Severity, "medium") {
			sev = finding.Warning
		} else {
			sev = finding.Info
		}

		cweStr := ""
		if issue.Cwe.ID != "" {
			cweStr = " [CWE-" + issue.Cwe.ID + "]"
		}
		porQue, arreglo := retroalimentacionSeguridad("Gosec", issue.RuleID, issue.Cwe.ID, issue.Details)

		f := finding.Finding{
			Engine:      "gosec",
			RuleKey:     issue.RuleID,
			Pillar:      finding.Security,
			Severity:    sev,
			Blocking:    blocking,
			File:        relPath,
			Line:        lineNum,
			EndLine:     lineNum,
			Message:     issue.Details + cweStr,
			Why:         porQue,
			FixHint:     arreglo,
			LineContent: strings.TrimSpace(issue.Code),
			Source:      finding.Deterministic,
		}
		f.Normalizar()
		findings = append(findings, f)
	}

	return findings, nil
}
