// Package trivy adapta el escáner de dependencias vulnerables (sección 6.2.5).
// Corre solo cuando cambió un manifiesto o lockfile. Política §7: CVE crítico
// advierte en local y bloquea en CI (la DB local puede estar desactualizada).
package trivy

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"codeguard/internal/engines"
	"codeguard/internal/engines/proc"
	"codeguard/internal/finding"
)

type Engine struct {
	Binary string
	// BlockCritical: true en CI (la DB está recién actualizada), false en local.
	BlockCritical bool
	// SkipDBUpdate: true en el camino del hook; el daemon/CI refrescan la DB.
	SkipDBUpdate bool
}

func (e *Engine) Name() string { return "trivy" }

// manifests reconoce manifiestos y lockfiles de los ecosistemas soportados.
var manifests = map[string]bool{
	"package.json": true, "package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true,
	"go.mod": true, "go.sum": true,
	"requirements.txt": true, "poetry.lock": true, "pipfile.lock": true, "uv.lock": true,
	"pom.xml": true, "build.gradle": true, "build.gradle.kts": true, "gradle.lockfile": true,
	"packages.lock.json": true, "pubspec.lock": true,
}

func (e *Engine) changedManifests(in engines.Input) []string {
	var out []string
	for _, f := range in.Files {
		if f.Status == "D" {
			continue
		}
		base := strings.ToLower(path.Base(f.Path))
		if manifests[base] || strings.HasSuffix(base, ".csproj") {
			out = append(out, f.Path)
		}
	}
	return out
}

func (e *Engine) Applies(in engines.Input) bool { return len(e.changedManifests(in)) > 0 }

type trivyReport struct {
	Results []struct {
		Target          string `json:"Target"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Severity         string `json:"Severity"`
			Title            string `json:"Title"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

func (e *Engine) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	bin := e.Binary
	if bin == "" {
		bin = "trivy"
	}
	args := []string{"fs", "--scanners", "vuln", "--format", "json", "--quiet"}
	if e.SkipDBUpdate {
		args = append(args, "--skip-db-update")
	}
	args = append(args, in.RepoRoot)

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = in.RepoRoot
	cmd.Env = proc.Entorno()
	salida, runErr := proc.Correr(ctx, cmd, proc.MaxSalida)
	out := salida.Stdout
	if runErr != nil && len(out) == 0 {
		return nil, fmt.Errorf("trivy no corrió: %v", runErr)
	}
	if salida.Recortada {
		return nil, fmt.Errorf("trivy devolvió más de %d MB de salida", proc.MaxSalida>>20)
	}
	var report trivyReport
	if err := json.Unmarshal(out, &report); err != nil {
		return nil, fmt.Errorf("salida de trivy ilegible: %v", err)
	}

	var findings []finding.Finding
	for _, r := range report.Results {
		for _, v := range r.Vulnerabilities {
			critical := v.Severity == "CRITICAL"
			sev := finding.Warning
			if critical {
				sev = finding.Error
			}
			fix := "Sin versión corregida publicada todavía; evalúa mitigar o sustituir la dependencia."
			if v.FixedVersion != "" {
				fix = fmt.Sprintf("Actualiza %s de %s a %s.", v.PkgName, v.InstalledVersion, v.FixedVersion)
			}
			f := finding.Finding{
				Engine:      "trivy",
				RuleKey:     v.VulnerabilityID,
				Pillar:      finding.Security,
				Severity:    sev,
				Blocking:    critical && e.BlockCritical,
				File:        filepath.ToSlash(r.Target),
				Line:        1,
				Message:     fmt.Sprintf("%s en %s@%s: %s", v.VulnerabilityID, v.PkgName, v.InstalledVersion, v.Title),
				Why:         "OWASP A03 2025 (cadena de suministro): una dependencia con CVE conocido es superficie de ataque directa.",
				FixHint:     fix,
				Verified:    true,
				Source:      finding.Deterministic,
				LineContent: v.PkgName + "@" + v.InstalledVersion,
			}
			f.ComputeFingerprint()
			findings = append(findings, f)
		}
	}
	return findings, nil
}
