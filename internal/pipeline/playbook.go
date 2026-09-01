package pipeline

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"codeguard/internal/config"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
	"codeguard/internal/migraciones"
)

// migracionSinVigilar devuelve la etiqueta de degradación cuando el commit
// cambia el esquema y la compuerta de migraciones no lo estaba mirando.
//
// Sólo se queja de archivos que PARECEN migraciones. Una consulta de sqlc o un
// modelo de dbt fuera de `paths.migrations` es lo correcto, y avisar de ellos
// en cada commit convertiría esto en ruido que se aprende a ignorar — que es
// otra forma de no avisar.
//
// Con otro motor declarado no se dice nada: squawk sólo entiende PostgreSQL,
// así que ahí la lista vacía no es un descuido sino una consecuencia, y mandar
// al dev a editar `paths.migrations` no le arreglaría nada.
func migracionSinVigilar(cfg *config.Config, files []gitdiff.ChangedFile) string {
	if cfg == nil || !cfg.Paths.MigracionesEnPostgres() {
		return ""
	}
	globs := migraciones.Compilar(cfg.Paths.Migrations)
	var fuera []string
	for _, f := range files {
		if f.Status == "D" || !migraciones.Parece(f.Path) {
			continue
		}
		if !migraciones.CasaAlguno(globs, migraciones.Normalizar(f.Path)) {
			fuera = append(fuera, f.Path)
		}
	}
	if len(fuera) == 0 {
		return ""
	}
	// La etiqueta corta viaja al veredicto; los archivos concretos, al log,
	// igual que el resto de degradaciones.
	log.Printf("migraciones fuera de paths.migrations (%d): %s",
		len(fuera), strings.Join(fuera, ", "))
	return "squawk:migracion-sin-vigilar"
}

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
	return revisarLockfilesEn(cfg, cfg.RepoRoot, files)
}

func revisarLockfilesEn(cfg *config.Config, repoRoot string, files []gitdiff.ChangedFile) []finding.Finding {
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
					// Sólo «no existe» cuenta como que no hay lockfile. Cualquier
					// otro error de Stat —permisos, una unidad de red dormida, un
					// nombre que el FS no admite— NO prueba que falte, y aquí el
					// precio de equivocarse es un hallazgo BLOQUEANTE que le dice
					// al dev «tu proyecto no tiene lockfile» teniéndolo delante, y
					// lo manda a correr un install que no arregla nada: acusar en
					// falso sin salida más que el bypass, que es lo contrario de
					// lo que este bloque razona doce líneas más abajo. Ante la
					// duda se asume que está, igual que hace el registro de
					// proyectos cuando el Stat de un repo falla por algo que no
					// sea la ausencia.
					_, err := os.Stat(filepath.Join(repoRoot, filepath.FromSlash(ruta)))
					if err == nil || !errors.Is(err, fs.ErrNotExist) {
						existe = lock
					}
				}
			}
			if actualizado {
				break
			}

			// Un manifiesto que no declara ninguna dependencia externa no puede
			// tener lockfile: no hay nada que fijar. Exigírselo es un bloqueo
			// sin salida —`go mod tidy` corre limpio y no genera go.sum— que
			// sólo deja al dev la opción del bypass. Sin dependencias tampoco
			// hay riesgo: no existe versión que pueda resolverse distinto.
			if existe == "" && sinDependencias(repoRoot, f.Path, m.Manifiesto) {
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
			out = append(out, fnd)
			break
		}
	}
	return out
}

// sinDependencias dice si un manifiesto declara cero dependencias externas.
//
// Sólo afirma que sí cuando puede comprobarlo leyendo el archivo: ante uno
// ilegible, o un formato que no sabe interpretar, devuelve false y el hallazgo
// se mantiene. La regla existe para proteger la instalación reproducible;
// relajarla por una corazonada sería peor que el falso positivo.
func sinDependencias(repoRoot, rel, manifiesto string) bool {
	raw, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(rel)))
	if err != nil {
		return false
	}
	switch manifiesto {
	case "go.mod":
		return goModSinRequires(raw)
	case "package.json":
		return packageJSONSinDeps(raw)
	}
	return false
}

// goModSinRequires: un go.mod sin ninguna directiva require sólo usa la
// biblioteca estándar, y `go mod tidy` no genera go.sum para él.
func goModSinRequires(raw []byte) bool {
	enBloque := false
	for _, linea := range strings.Split(string(raw), "\n") {
		l := strings.TrimSpace(linea)
		if i := strings.Index(l, "//"); i >= 0 {
			l = strings.TrimSpace(l[:i])
		}
		if l == "" {
			continue
		}
		if enBloque {
			if l == ")" {
				enBloque = false
				continue
			}
			return false // una entrada dentro de require ( … )
		}
		resto, esRequire := strings.CutPrefix(l, "require")
		if !esRequire {
			continue
		}
		switch resto = strings.TrimSpace(resto); {
		case resto == "(":
			enBloque = true
		case resto != "":
			return false // require en una línea
		}
	}
	return true
}

// packageJSONSinDeps: un package.json que sólo trae scripts o metadatos no
// tiene nada que fijar. Es el caso de los repos que usan npm como lanzador
// de tareas y no como gestor de paquetes.
func packageJSONSinDeps(raw []byte) bool {
	var pkg struct {
		Dependencies         map[string]any `json:"dependencies"`
		DevDependencies      map[string]any `json:"devDependencies"`
		PeerDependencies     map[string]any `json:"peerDependencies"`
		OptionalDependencies map[string]any `json:"optionalDependencies"`
	}
	if err := json.Unmarshal(raw, &pkg); err != nil {
		return false
	}
	return len(pkg.Dependencies)+len(pkg.DevDependencies)+
		len(pkg.PeerDependencies)+len(pkg.OptionalDependencies) == 0
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
		Identidad:   finding.IdentidadSemantica,
	}
	return []finding.Finding{f}
}
