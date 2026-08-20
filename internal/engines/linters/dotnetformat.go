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
	// Los proyectos se le dicen EXPLÍCITAMENTE, y esto no es cosmético.
	//
	// Antes se invocaba `dotnet format` en la raíz del repo, a secas. En un
	// repo con el .csproj fuera de la raíz —el layout src/, que es el normal—
	// `dotnet format` no encuentra workspace, revienta con una excepción de
	// MSBuildWorkspaceFinder, sale con 1 y NO escribe el reporte. Y como
	// runTool tolera los códigos de salida no cero, el motor llegaba a
	// `os.ReadFile(report)`, fallaba, y hacía `return nil, nil`: "sin reporte =
	// sin cambios requeridos". O sea, LIMPIO.
	//
	// Traducido: en cualquier repo de C# con estructura estándar, la compuerta
	// de formato llevaba dando el visto bueno sin haber mirado un solo archivo.
	// Se destapó en la verificación de extremo a extremo, con el SDK instalado
	// y un .csproj delante: dotnet-build cazaba su error y dotnet-format decía
	// que todo bien.
	//
	// Se reutiliza el mismo descubrimiento que dotnet-build: subir desde cada
	// .cs tocado hasta el .csproj más cercano.
	proyectos := DotnetBuild{}.proyectos(in)
	if len(proyectos) == 0 {
		return nil, fmt.Errorf("no encuentro ningún .csproj para los .cs tocados")
	}

	tmpReport, err := os.CreateTemp("", "codeguard-dnf-*.json")
	if err != nil {
		return nil, fmt.Errorf("no se pudo crear archivo temporal para reporte: %w", err)
	}
	report := tmpReport.Name()
	_ = tmpReport.Close()
	defer os.Remove(report)

	var rep dnfReport
	for _, proy := range proyectos {
		_ = os.Remove(report)
		// El reporte JSON evita parsear la salida humana del comando.
		salida, err := runTool(ctx, in.RepoRoot, "dotnet", "format", proy,
			"--verify-no-changes", "--no-restore", "--report", report)
		if err != nil {
			return nil, fmt.Errorf("dotnet format no corrió: %w", err)
		}
		raw, err := os.ReadFile(report)
		if err != nil {
			// Sin reporte NO es "limpio": es "no pude mirar". La distinción es
			// justo la que faltaba, y devolver un error degrada la capa de
			// forma visible en vez de firmar un visto bueno vacío.
			return nil, fmt.Errorf("dotnet format no dejó reporte para %s (%s)", proy, recorteDNF(salida))
		}
		var parcial dnfReport
		if err := json.Unmarshal(raw, &parcial); err != nil {
			return nil, fmt.Errorf("reporte de dotnet format ilegible: %v", err)
		}
		rep = append(rep, parcial...)
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

// recorteDNF deja un trozo legible de la salida para el mensaje de error.
//
// Importa porque el fallo típico —dotnet format sin workspace— escribe una
// traza de excepción de varias líneas: sin recortar, el aviso al desarrollador
// se convierte en un muro que nadie lee.
func recorteDNF(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i > 0 {
		s = s[:i]
	}
	if len(s) > 160 {
		s = s[:157] + "…"
	}
	if s == "" {
		return "sin salida"
	}
	return s
}
