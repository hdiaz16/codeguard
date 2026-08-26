package linters

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"codeguard/internal/engines"
	"codeguard/internal/engines/proc"
	"codeguard/internal/finding"
	"codeguard/internal/fsutil"
)

// PSAnalyzer adapta PSScriptAnalyzer —el linter de PowerShell— al contrato. Los
// scripts .ps1 son superficie real (instaladores, CI, automatización con
// privilegios) y hasta aquí nadie los miraba. Solo aplica si el cambio toca
// .ps1; degrada a Ausente sin pwsh o sin el módulo.
type PSAnalyzer struct {
	Binary string // vacío = pwsh, con caída a powershell
	Cache  engines.Cache
}

func (PSAnalyzer) Name() string { return "psscriptanalyzer" }

func (PSAnalyzer) Applies(in engines.Input) bool {
	return len(filesWithExt(in, ".ps1")) > 0
}

// scriptPSSA es FIJO: no interpola ninguna ruta del diff (eso sería inyección
// de PowerShell). Las rutas viajan por la variable de entorno CG_PSSA_TARGETS,
// separadas por LF —un carácter que jamás aparece en una ruta—, y aquí se leen
// como DATOS, nunca como código. Emite un arreglo JSON compacto.
const scriptPSSA = `$ErrorActionPreference='Stop'; ` +
	`$paths = $env:CG_PSSA_TARGETS -split [char]10 | Where-Object { $_ }; ` +
	`$out = foreach ($p in $paths) { Invoke-ScriptAnalyzer -Path $p -Severity Warning,Error -ErrorAction SilentlyContinue }; ` +
	`@($out | Select-Object RuleName,Severity,Line,Column,Message,ScriptPath) | ConvertTo-Json -Depth 4 -Compress`

type pssaDiag struct {
	RuleName   string `json:"RuleName"`
	Severity   int    `json:"Severity"` // 0 Information, 1 Warning, 2 Error, 3 ParseError
	Line       int    `json:"Line"`
	Column     int    `json:"Column"`
	Message    string `json:"Message"`
	ScriptPath string `json:"ScriptPath"`
}

func (e PSAnalyzer) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	bin := e.Binary
	if bin == "" {
		bin = "pwsh"
		if _, err := exec.LookPath(bin); err != nil {
			bin = "powershell" // Windows PowerShell 5.1: PSScriptAnalyzer también corre ahí
		}
	}

	var rutas []string
	for _, f := range filesWithExt(in, ".ps1") {
		rutas = append(rutas, f.Path)
	}
	sanitizadas := fsutil.SanitizarRutas(in.RepoRoot, rutas)
	if len(sanitizadas) == 0 {
		return nil, nil
	}

	cmd := exec.CommandContext(ctx, bin, "-NoProfile", "-NonInteractive", "-Command", scriptPSSA)
	cmd.Dir = in.RepoRoot
	// El entorno se arma con la lista blanca del perfil (W4), MÁS dos cosas: los
	// objetivos (dato, no código) y el PSModulePath —que la lista blanca no deja
	// pasar— para que pwsh encuentre el módulo PSScriptAnalyzer. Sin él, el
	// módulo no carga y el motor se veería «sin herramienta» teniéndola.
	cmd.Env = proc.EntornoDeMotor("psscriptanalyzer", proc.PerfilBasico,
		"CG_PSSA_TARGETS="+strings.Join(sanitizadas, "\n"),
		"PSModulePath="+os.Getenv("PSModulePath"))

	salida, runErr := proc.Correr(ctx, cmd, proc.MaxSalida)
	if runErr != nil && len(salida.Stdout) == 0 {
		return nil, fmt.Errorf("psscriptanalyzer no corrió (%s): %w", bin, runErr)
	}
	if salida.Recortada {
		return nil, fmt.Errorf("psscriptanalyzer devolvió más de %d MB de salida", proc.MaxSalida>>20)
	}

	findings, err := hallazgosPSSA(in.RepoRoot, salida.Stdout)
	if err != nil {
		return nil, err
	}
	// Sin hallazgos y con error de proceso: o falta el módulo, o un .ps1 tiene
	// algo que ni el analizador pudo leer. Se degrada con nombre en vez de servir
	// un limpio sobre lo que no se miró.
	if len(findings) == 0 && runErr != nil {
		return nil, fmt.Errorf("psscriptanalyzer terminó con error y sin diagnósticos "+
			"(¿falta el módulo? `Install-Module PSScriptAnalyzer -Scope CurrentUser`): %s",
			strings.TrimSpace(string(salida.Stdout)))
	}
	return findings, nil
}

func hallazgosPSSA(repoRoot string, raw []byte) ([]finding.Finding, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}
	// ConvertTo-Json emite un objeto suelto cuando hay UN solo diagnóstico y un
	// arreglo cuando hay varios; @(...) fuerza arreglo, pero se acepta cualquiera
	// de las dos formas por robustez.
	var diags []pssaDiag
	if trimmed[0] == '[' {
		if err := json.Unmarshal([]byte(trimmed), &diags); err != nil {
			return nil, fmt.Errorf("psscriptanalyzer: salida JSON ilegible: %w", err)
		}
	} else {
		var uno pssaDiag
		if err := json.Unmarshal([]byte(trimmed), &uno); err != nil {
			return nil, fmt.Errorf("psscriptanalyzer: salida JSON ilegible: %w", err)
		}
		diags = []pssaDiag{uno}
	}

	// PSScriptAnalyzer devuelve ScriptPath ABSOLUTO y canonicalizado. En Windows
	// eso puede diferir del repoRoot en la forma corta 8.3 (HECTOR~1 vs «Hector
	// Diaz»), y un filepath.Rel crudo produciría una ruta llena de «..». Se
	// canonicalizan los dos lados con EvalSymlinks (resuelve el 8.3) antes de
	// relativizar; si aun así escapa del repo, se deja el absoluto en vez de una
	// ruta basura.
	canonRoot := repoRoot
	if r, err := filepath.EvalSymlinks(repoRoot); err == nil {
		canonRoot = r
	}
	var findings []finding.Finding
	for _, d := range diags {
		rel := filepath.ToSlash(d.ScriptPath)
		if filepath.IsAbs(d.ScriptPath) {
			abs := d.ScriptPath
			if a, err := filepath.EvalSymlinks(abs); err == nil {
				abs = a
			}
			if r, err := filepath.Rel(canonRoot, abs); err == nil && !strings.HasPrefix(r, "..") {
				rel = filepath.ToSlash(r)
			}
		}
		sev, blocking := finding.Warning, false
		if d.Severity >= 2 { // Error (2) o ParseError (3): un script que no parsea o un bug real
			sev, blocking = finding.Error, true
		}
		f := finding.Finding{
			Engine:   "psscriptanalyzer",
			RuleKey:  d.RuleName,
			Pillar:   finding.Quality,
			Severity: sev,
			Blocking: blocking,
			File:     rel,
			Line:     d.Line,
			Message:  d.Message,
			Why:      "PSScriptAnalyzer analiza el AST de PowerShell: los errores (sintaxis, bugs reales) bloquean; los avisos (estilo, prácticas) se dicen sin bloquear.",
			FixHint:  "Corrige lo que señala la regla; su ficha está en https://learn.microsoft.com/powershell/utility-modules/psscriptanalyzer/rules/" + d.RuleName,
			Verified: true,
			Source:   finding.Deterministic,
			// LineContent lo rellena finding.AsignarHuellas (motor nuevo, v2).
		}
		f.Normalizar()
		findings = append(findings, f)
	}
	return findings, nil
}
