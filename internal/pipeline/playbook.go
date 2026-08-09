package pipeline

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"codeguard/internal/config"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
)

// Este archivo implementa las reglas del playbook que no son propiedades del
// código sino del repositorio y del cambio: si las dependencias quedan fijadas
// y si el cambio es revisable. Semgrep no las puede ver porque no miran
// dentro de un archivo, sino la relación entre archivos.

// manifiestos empareja cada declaración de dependencias con el archivo que
// fija las versiones resueltas.
var manifiestos = []struct {
	Manifiesto string
	Lockfiles  []string
	Comando    string
}{
	{"package.json", []string{"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb"}, "npm install"},
	{"requirements.txt", []string{"requirements.lock", "requirements.txt.lock"}, "pip-compile"},
	{"pyproject.toml", []string{"poetry.lock", "uv.lock", "pdm.lock"}, "poetry lock"},
	{"Gemfile", []string{"Gemfile.lock"}, "bundle install"},
	{"composer.json", []string{"composer.lock"}, "composer update"},
	{"go.mod", []string{"go.sum"}, "go mod tidy"},
	{"Cargo.toml", []string{"Cargo.lock"}, "cargo update"},
}

// revisarLockfiles comprueba que un cambio de dependencias venga acompañado de
// su lockfile.
//
// Sin lockfile, dos desarrolladores que instalan el mismo día pueden acabar
// con versiones distintas, y el CI con una tercera. Es también la puerta por
// la que entra una versión maliciosa recién publicada: sin versiones fijadas,
// el siguiente `install` la trae sin que nadie lo decida.
func revisarLockfiles(cfg *config.Config, files []gitdiff.ChangedFile) []finding.Finding {
	tocado := map[string]bool{}
	for _, f := range files {
		if f.Status != "D" {
			tocado[f.Path] = true
		}
	}

	var out []finding.Finding
	for _, f := range files {
		if f.Status == "D" {
			continue
		}
		base := path.Base(f.Path)
		dir := path.Dir(f.Path)
		for _, m := range manifiestos {
			if base != m.Manifiesto {
				continue
			}
			// ¿Se tocó algún lockfile hermano en el mismo commit?
			actualizado := false
			existe := ""
			for _, lock := range m.Lockfiles {
				ruta := path.Join(dir, lock)
				if dir == "." {
					ruta = lock
				}
				if tocado[ruta] {
					actualizado = true
					break
				}
				if existe == "" {
					if _, err := os.Stat(filepath.Join(cfg.RepoRoot, filepath.FromSlash(ruta))); err == nil {
						existe = lock
					}
				}
			}
			if actualizado {
				break
			}

			// Sin lockfile en el repo es un problema mayor que tenerlo desfasado.
			var fnd finding.Finding
			if existe == "" {
				fnd = finding.Finding{
					Severity: finding.Error,
					Blocking: true,
					Message:  fmt.Sprintf("%s cambió y el proyecto no tiene lockfile", base),
					Why: "Sin lockfile cada instalación resuelve versiones por su cuenta: tu máquina, " +
						"la de tu compañero y el CI pueden acabar con dependencias distintas, y una " +
						"versión maliciosa recién publicada entra sola en el siguiente install.",
					FixHint: fmt.Sprintf("Ejecuta `%s` y versiona el lockfile que genere (%s).",
						m.Comando, strings.Join(m.Lockfiles, " o ")),
				}
			} else {
				fnd = finding.Finding{
					Severity: finding.Warning,
					Blocking: false,
					Message:  fmt.Sprintf("%s cambió pero %s no", base, existe),
					Why: "El lockfile deja de reflejar lo declarado, así que la instalación " +
						"reproducible ya no reproduce este cambio.",
					FixHint: fmt.Sprintf("Ejecuta `%s` y añade %s al commit.", m.Comando, existe),
				}
			}
			fnd.Engine = "playbook"
			fnd.RuleKey = "lockfile-desincronizado"
			if existe == "" {
				fnd.RuleKey = "lockfile-ausente"
			}
			fnd.Pillar = finding.Security
			fnd.File = f.Path
			fnd.Line = 1
			fnd.Verified = true
			fnd.Source = finding.Deterministic
			fnd.LineContent = fnd.RuleKey
			fnd.ComputeFingerprint()
			out = append(out, fnd)
			break
		}
	}
	return out
}

// LimiteCambioRevisable: por encima de este tamaño la calidad de la revisión
// cae en picado — quien revisa deja de leer y empieza a hojear. Es un aviso,
// nunca un bloqueo: hay cambios legítimamente grandes (una migración generada,
// un renombrado masivo) y decidirlo es del autor, no del agente (P4).
const LimiteCambioRevisable = 400

func revisarTamano(d *gitdiff.Diff, files []gitdiff.ChangedFile) []finding.Finding {
	if d == nil || d.Lines <= LimiteCambioRevisable {
		return nil
	}
	archivo := "."
	if len(files) > 0 {
		archivo = files[0].Path
	}
	f := finding.Finding{
		Engine:   "playbook",
		RuleKey:  "cambio-demasiado-grande",
		Pillar:   finding.Quality,
		Severity: finding.Warning,
		Blocking: false,
		File:     archivo,
		Line:     1,
		Message: fmt.Sprintf("El cambio toca %d líneas en %d archivos (el límite revisable son %d)",
			d.Lines, len(files), LimiteCambioRevisable),
		Why: "Por encima de ~400 líneas la revisión deja de encontrar defectos: " +
			"quien revisa pasa de leer a hojear y aprueba por confianza.",
		FixHint: "Si el cambio admite partirse, sepáralo en commits que se puedan revisar " +
			"por separado. Si es generado o mecánico, dilo en el mensaje del commit para " +
			"que quien revise sepa qué mirar.",
		Verified:    true,
		Source:      finding.Deterministic,
		LineContent: "cambio-demasiado-grande",
	}
	f.ComputeFingerprint()
	return []finding.Finding{f}
}
