package govulncheck

import (
	"context"
	"errors"
	"fmt"
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
	// Cache: módulo sin cambios = mismos hallazgos, sin re-analizar. La clave
	// lleva el día UTC porque el análisis consulta la base de vulnerabilidades
	// del día: un acierto de ayer escondería los CVEs publicados hoy.
	Cache engines.Cache
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
func (e *Engine) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	bin := e.Binary
	if bin == "" {
		bin = "govulncheck"
	}
	var out []finding.Finding
	for _, dir := range e.modulos(in) {
		// La clave se calcula SÓLO si hay caché que la use: claveModulo pasa por
		// HuellaModulo, que recorre y hashea todos los .go y manifiestos del
		// módulo, y sin caché ese trabajo se tiraba entero a la basura.
		clave := ""
		if e.Cache != nil {
			clave = e.claveModulo(in.RepoRoot, dir)
			if clave != "" {
				if fs, ok := e.Cache.Leer([]string{clave})[clave]; ok {
					out = append(out, fs...)
					continue
				}
			}
		}
		fs, err := e.correrModulo(ctx, bin, in.RepoRoot, dir)
		if err != nil {
			return nil, err
		}
		// clave != "" implica e.Cache != nil: sólo se asigna dentro de esa rama.
		if clave != "" {
			e.Cache.Guardar(map[string][]finding.Finding{clave: fs})
		}
		out = append(out, fs...)
	}
	return out, nil
}

// claveModulo identifica un análisis completo: el contenido del módulo (los
// .go y manifiestos rastreados) más el día UTC — la frescura de la base de
// vulnerabilidades es parte del resultado. Vacía = no cacheable.
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
		// %w y no %v: el centinela (binario ausente, plazo agotado) tiene que
		// llegar entero al orquestador, que clasifica con errors.Is.
		return nil, fmt.Errorf("govulncheck falló en %s: %w%s", dir, runErr, detalle)
	}
	if salida.Recortada {
		return nil, fmt.Errorf("govulncheck devolvió más de %d MB de salida", proc.MaxSalida>>20)
	}
	return interpretar(salida.Stdout, repoRoot, dir, e.BlockReachable)
}

// interpretar lee el flujo de govulncheck, y ADEMÁS exige que el flujo exista.
//
// EL SILENCIO QUE ERA UN ✓ VERDE. Un módulo sin vulnerabilidades no produce
// ninguna envoltura "finding", así que el bucle salía por io.EOF en la primera
// vuelta y el motor devolvía (nil, nil): «analizado, sin CVEs alcanzables». Con
// stdout VACÍO daba exactamente lo mismo, y stdout vacío es lo que deja una
// herramienta que no analizó nada.
//
// Aquí la señal no había que inventarla ni preguntarla: govulncheck ABRE su flujo
// presentándose. Medido sobre un módulo limpio con una sola dependencia:
//
//	393 983 bytes, código 0, y el primer mensaje es
//	{"config":{…,"scanner_name":"govulncheck","scanner_version":"v1.6.0",…}}
//
// Stdout vacío con código 0 es IMPOSIBLE en la herramienta de verdad. Y como la
// cabecera trae su nombre, la misma comprobación que demuestra que analizó
// demuestra que quien analizó era govulncheck — sin lanzar un proceso extra para
