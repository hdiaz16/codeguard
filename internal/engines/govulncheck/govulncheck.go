// Package govulncheck adapta el analizador de alcanzabilidad de Go (F1b del
// plan Motor avanzado). Trivy responde "¿está el CVE en tu go.sum?";
// govulncheck construye el grafo de llamadas y responde la pregunta que
// importa: "¿tu código EJECUTA la función vulnerable?". Aquí sólo se reportan
// los hallazgos con símbolo alcanzado — la mera presencia ya la dice trivy, y
// repetirla con otro nombre sería ruido.
//
// El binario lo construye el toolchain de Go del desarrollador (go install),
// así que no entra en motores.json: sus fuentes las verifica GOSUMDB, igual
// que pip verifica los motores de Python.
package govulncheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"codeguard/internal/engines"
	"codeguard/internal/engines/proc"
	"codeguard/internal/finding"
)

type Engine struct {
	Binary string
	// BlockReachable: true en CI (política §7, como el CVE crítico de trivy):
	// una vulnerabilidad cuyo código de verdad se llama bloquea allí; en local
	// avisa, porque la base de vulnerabilidades local puede estar vieja.
	BlockReachable bool
	// SoloManifiestos: true en el camino del hook. El análisis recorre el
	// módulo completo (segundos, no milisegundos), así que en local sólo corre
	// cuando cambian las dependencias (go.mod/go.sum) — el momento en que la
	// alcanzabilidad suele cambiar. El CI corre con cualquier .go tocado.
	SoloManifiestos bool
}

func (e *Engine) Name() string { return "govulncheck" }

func (e *Engine) Applies(in engines.Input) bool { return len(e.modulos(in)) > 0 }

// modulos devuelve los directorios de módulo (relativos a la raíz; "." si es
// la propia raíz) que este cambio obliga a analizar. La detección es por
// archivos CAMBIADOS: de cada uno se sube hasta el go.mod más cercano, que en
// un monorepo (backend/go.mod + frontend/) no está en la raíz.
func (e *Engine) modulos(in engines.Input) []string {
	dirs := map[string]bool{}
	for _, f := range in.Files {
		if f.Status == "D" {
			continue
		}
		base := strings.ToLower(path.Base(f.Path))
		esManifiesto := base == "go.mod" || base == "go.sum"
		if e.SoloManifiestos && !esManifiesto {
			continue
		}
		if !esManifiesto && !strings.HasSuffix(base, ".go") {
			continue
		}
		if dir, ok := moduloDe(in.RepoRoot, f.Path); ok {
			dirs[dir] = true
		}
	}
	out := make([]string, 0, len(dirs))
	for d := range dirs {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// moduloDe sube desde el archivo hasta el go.mod más cercano, sin salirse de
// la raíz del repo.
func moduloDe(repoRoot, rel string) (string, bool) {
	dir := path.Dir(rel)
	for {
		abs := filepath.Join(repoRoot, filepath.FromSlash(dir), "go.mod")
		if st, err := os.Stat(abs); err == nil && !st.IsDir() {
			return dir, true
		}
		if dir == "." || dir == "/" {
			return "", false
		}
		dir = path.Dir(dir)
	}
}

// ── el flujo -json ──────────────────────────────────────────────────────────
// govulncheck -json emite una secuencia de objetos: config, progress, osv (la
// ficha completa de cada vulnerabilidad mencionada) y finding. Cada hallazgo
// llega en niveles de precisión crecientes: módulo (está en tus dependencias),
// paquete (importas el paquete afectado) y símbolo (tu código llama a la
// función vulnerable — traza con función y posición). Sólo el último prueba
// alcanzabilidad. El flujo siempre sale con código 0; un código distinto es
// fallo operativo, no "encontré algo".

type envoltura struct {
	OSV     *fichaOSV `json:"osv"`
	Finding *hallazgo `json:"finding"`
}

type fichaOSV struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
}

type hallazgo struct {
	OSV          string  `json:"osv"`
	FixedVersion string  `json:"fixed_version"`
	Trace        []marco `json:"trace"`
}

type marco struct {
	Module   string    `json:"module"`
	Version  string    `json:"version"`
	Package  string    `json:"package"`
	Function string    `json:"function"`
	Position *posicion `json:"position"`
}

type posicion struct {
	Filename string `json:"filename"`
	Line     int    `json:"line"`
}

func (e *Engine) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	bin := e.Binary
	if bin == "" {
		bin = "govulncheck"
	}
	var out []finding.Finding
	for _, dir := range e.modulos(in) {
		fs, err := e.correrModulo(ctx, bin, in.RepoRoot, dir)
		if err != nil {
			return nil, err
		}
		out = append(out, fs...)
	}
	return out, nil
}

func (e *Engine) correrModulo(ctx context.Context, bin, repoRoot, dir string) ([]finding.Finding, error) {
	cmd := exec.CommandContext(ctx, bin, "-json", "./...")
	cmd.Dir = filepath.Join(repoRoot, filepath.FromSlash(dir))
	cmd.Env = proc.Entorno()
	salida, runErr := proc.Correr(ctx, cmd, proc.MaxSalida)
	if runErr != nil {
		var exit *exec.ExitError
		detalle := ""
		if errors.As(runErr, &exit) && len(salida.Stderr) > 0 {
			detalle = ": " + recorte(salida.Stderr)
		}
		return nil, fmt.Errorf("govulncheck falló en %s: %v%s", dir, runErr, detalle)
	}
	if salida.Recortada {
		return nil, fmt.Errorf("govulncheck devolvió más de %d MB de salida", proc.MaxSalida>>20)
	}
	return interpretar(salida.Stdout, dir, e.BlockReachable)
}

func interpretar(raw []byte, dir string, bloquea bool) ([]finding.Finding, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	resumen := map[string]string{}
	var crudos []hallazgo
	for {
		var env envoltura
		if err := dec.Decode(&env); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("salida de govulncheck ilegible: %v", err)
		}
		if env.OSV != nil {
			resumen[env.OSV.ID] = env.OSV.Summary
		}
		if env.Finding != nil {
			crudos = append(crudos, *env.Finding)
		}
	}

	var out []finding.Finding
	for _, h := range crudos {
		// Nivel módulo o paquete: presencia sin llamada — territorio de trivy.
		if len(h.Trace) == 0 || h.Trace[0].Function == "" {
			continue
		}
		vuln := h.Trace[0]
		simbolo := vuln.Package + "." + vuln.Function

		file, line := path.Join(dir, "go.mod"), 1
		if u := marcoUsuario(h.Trace); u != nil {
			rel := filepath.ToSlash(u.Position.Filename)
			if !path.IsAbs(rel) && dir != "." {
				rel = path.Join(dir, rel)
			}
			file, line = rel, u.Position.Line
		}

		fix := "Sin versión corregida publicada todavía; evalúa mitigar o sustituir la dependencia."
		switch {
		case h.FixedVersion == "":
		case vuln.Module == "stdlib":
			fix = fmt.Sprintf("Actualiza el toolchain de Go a %s.", strings.TrimPrefix(h.FixedVersion, "v"))
		default:
			fix = fmt.Sprintf("Actualiza %s de %s a %s.", vuln.Module, vuln.Version, h.FixedVersion)
		}

		f := finding.Finding{
			Engine:      "govulncheck",
			RuleKey:     h.OSV,
			Pillar:      finding.Security,
			Severity:    finding.Error,
			Blocking:    bloquea,
			File:        file,
			Line:        line,
			Message:     fmt.Sprintf("%s alcanzable: el código llama a %s (%s@%s). %s", h.OSV, simbolo, vuln.Module, vuln.Version, resumen[h.OSV]),
			Why:         "Cadena de suministro (OWASP A03 2025) con prueba de alcanzabilidad: no es sólo que la dependencia tenga un CVE — el grafo de llamadas demuestra que este código ejecuta la función vulnerable.",
			FixHint:     fix,
			Verified:    true,
			Source:      finding.Deterministic,
			LineContent: vuln.Module + "@" + vuln.Version + " " + simbolo,
		}
		f.ComputeFingerprint()
		out = append(out, f)
	}
	return out, nil
}

// marcoUsuario es el último marco de la traza con posición: la traza va de la
// función vulnerable (en la dependencia) hacia afuera, así que el último marco
// posicionado es el punto del código propio desde el que se llega a ella.
func marcoUsuario(trace []marco) *marco {
	for i := len(trace) - 1; i >= 0; i-- {
		if trace[i].Position != nil {
			return &trace[i]
		}
	}
	return nil
}

func recorte(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}
