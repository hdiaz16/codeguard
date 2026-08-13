package linters

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"codeguard/internal/engines"
	"codeguard/internal/finding"
)

// DotnetFormat implementa la compuerta de formato para C# (§7: BLOQUEA).
// Requiere el SDK de .NET; si falta con archivos .cs tocados, el orquestador
// registra la capa como degradada.
type DotnetFormat struct {
	// Cache por MÓDULO, no por archivo: `dotnet format` se invoca una vez sobre
	// el repo entero y decide con la configuración (.editorconfig) y los
	// proyectos, no archivo a archivo.
	//
	// Faltaba, y es de los caros: lanza el SDK de .NET, que arranca MSBuild.
	// La clave lleva el contenido de los .cs, los .csproj/.sln y el
	// .editorconfig — cambiar una regla de estilo en el .editorconfig cambia el
	// veredicto sin tocar una sola línea de C#, y sin eso en la clave el caché
	// serviría el resultado de la configuración anterior.
	Cache engines.Cache
}

func (DotnetFormat) Name() string { return "dotnet-format" }

func (DotnetFormat) Applies(in engines.Input) bool {
	return len(filesWithExt(in, ".cs")) > 0
}

type dnfReport []struct {
	FilePath    string `json:"FilePath"`
	FileChanges []struct {
		LineNumber        int    `json:"LineNumber"`
		FormatDescription string `json:"FormatDescription"`
	} `json:"FileChanges"`
}

func (e DotnetFormat) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	if _, err := exec.LookPath("dotnet"); err != nil {
		return nil, fmt.Errorf("SDK de .NET no disponible: %w", err)
	}
	clave := claveDotnetFormat(in.RepoRoot)
	if e.Cache != nil && clave != "" {
		if fs, ok := e.Cache.Leer([]string{clave})[clave]; ok {
			return fs, nil
		}
	}
	report := filepath.Join(os.TempDir(), "codeguard-dnf.json")
	defer os.Remove(report)

	// El reporte JSON evita parsear la salida humana del comando.
	_, err := runTool(ctx, in.RepoRoot, "dotnet", "format", "--verify-no-changes", "--report", report)
	if err != nil {
		return nil, fmt.Errorf("dotnet format no corrió: %w", err)
	}
	raw, err := os.ReadFile(report)
	if err != nil {
		return nil, nil // sin reporte = sin cambios requeridos
	}
	var rep dnfReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, fmt.Errorf("reporte de dotnet format ilegible: %v", err)
	}
	var findings []finding.Finding
	for _, file := range rep {
		for _, ch := range file.FileChanges {
			f := finding.Finding{
				Engine:      "dotnet-format",
				RuleKey:     "dotnet-format",
				Pillar:      finding.Quality,
				Severity:    finding.Error,
				Blocking:    true,
				File:        relTo(in.RepoRoot, file.FilePath),
				Line:        ch.LineNumber,
				Message:     ch.FormatDescription,
				Why:         "El formato inconsistente genera diffs ruidosos y discusiones sin valor.",
				FixHint:     "Ejecuta `dotnet format` (es auto-corregible).",
				Verified:    true,
				Source:      finding.Deterministic,
				LineContent: ch.FormatDescription,
			}
			f.ComputeFingerprint()
			findings = append(findings, f)
		}
	}

	if e.Cache != nil && clave != "" {
		e.Cache.Guardar(map[string][]finding.Finding{clave: findings})
	}
	return findings, nil
}

// claveDotnetFormat identifica una comprobación de formato: el contenido de
// todo lo que `dotnet format` mira. Vacía = no cacheable.
//
// El .editorconfig entra a propósito: es donde vive el estilo, así que cambiar
// una regla ahí cambia el veredicto sin tocar una línea de C#. Dejarlo fuera
// haría que el caché siguiera aplicando el estilo anterior — una regla nueva
// que no se aplica a nada ya analizado.
func claveDotnetFormat(repoRoot string) string {
	huella := engines.HuellaModulo(repoRoot, ".", func(rel string) bool {
		base := strings.ToLower(path.Base(rel))
		return base == ".editorconfig" ||
			strings.HasSuffix(base, ".cs") ||
			strings.HasSuffix(base, ".csproj") ||
			strings.HasSuffix(base, ".sln") ||
			strings.HasSuffix(base, ".props") ||
			strings.HasSuffix(base, ".targets")
	})
	if huella == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(huella))
	return "dotnet-format:" + hex.EncodeToString(sum[:])
}
