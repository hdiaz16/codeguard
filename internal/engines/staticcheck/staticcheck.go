// Package staticcheck adapta el analizador semántico de Go (F2b del plan
// Motor avanzado). govet caza los patrones que el equipo de Go considera
// errores casi seguros; staticcheck va más hondo: construye la forma SSA del
// programa y demuestra bugs sobre el flujo real de valores — un valor asignado
// que jamás se lee, una comparación que nunca puede ser cierta. No es un
// parecido textual como el de un grep sofisticado: es un hecho del programa
// compilado.
//
// El binario lo construye el toolchain de Go del desarrollador (go install),
// así que no entra en motores.json: sus fuentes las verifica GOSUMDB, igual
// que con govulncheck.
package staticcheck

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	// Cache: módulo sin cambios + mismos paquetes pedidos = mismos hallazgos.
	// La clave lleva la lista de paquetes porque el análisis es del
	// subconjunto tocado, no de ./... — otro subconjunto es otro resultado.
	Cache engines.Cache
}

func (e *Engine) Name() string { return "staticcheck" }

func (e *Engine) Applies(in engines.Input) bool { return len(e.modulos(in)) > 0 }

// modulos agrupa los archivos .go cambiados por su módulo (el go.mod más
// cercano subiendo directorios, que en un monorepo no está en la raíz) y
// devuelve, por módulo, los patrones de paquete a analizar relativos a ese
// go.mod. Se analizan SOLO los paquetes tocados, no ./... completo:
// staticcheck compila lo que analiza y en el hook el presupuesto son 30 s
// compartidos entre todos los motores.
func (e *Engine) modulos(in engines.Input) map[string][]string {
	porModulo := map[string]map[string]bool{}
	for _, f := range in.Files {
		if f.Status == "D" || !strings.HasSuffix(strings.ToLower(f.Path), ".go") {
			continue
		}
		mod, ok := moduloDe(in.RepoRoot, f.Path)
		if !ok {
			continue
		}
		// El paquete es el directorio del archivo, relativo al go.mod.
		rel := path.Dir(f.Path)
		if mod != "." {
			if rel == mod {
				rel = "."
			} else {
				rel = strings.TrimPrefix(rel, mod+"/")
			}
		}
		pkg := "./"
		if rel != "." {
			pkg = "./" + rel
		}
		if porModulo[mod] == nil {
			porModulo[mod] = map[string]bool{}
		}
		porModulo[mod][pkg] = true
	}
	out := make(map[string][]string, len(porModulo))
	for mod, set := range porModulo {
		pkgs := make([]string, 0, len(set))
		for p := range set {
			pkgs = append(pkgs, p)
		}
		sort.Strings(pkgs)
		out[mod] = pkgs
	}
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

// ── la salida -f json ───────────────────────────────────────────────────────
// staticcheck -f json emite UN objeto por línea con el problema y su posición.
// Los paths de location llegan ABSOLUTOS, construidos sobre el directorio de
// trabajo TAL CUAL lo recibió el proceso: con alias 8.3 (HECTOR~1) si el cwd
// venía así, largos si venía completo. La severidad depende del flag
// -fail: con la invocación por defecto todo problema real llega como "error";
// "ignored" marca los suprimidos con //lint:ignore. Un error de compilación
// NO llega por stderr: llega como un pseudo-problema con code "compile" y el
// proceso sale con 1 — el mismo código con el que sale cuando encuentra algo
// (señal legítima, como semgrep). Un código mayor que 1 sí es fallo operativo.

type problema struct {
	Code     string   `json:"code"`
	Severity string   `json:"severity"`
	Location posicion `json:"location"`
	End      posicion `json:"end"`
	Message  string   `json:"message"`
}

type posicion struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}

func (e *Engine) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	bin := e.Binary
	if bin == "" {
		bin = "staticcheck"
	}
	mods := e.modulos(in)
	dirs := make([]string, 0, len(mods))
	for d := range mods {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	var out []finding.Finding
	for _, dir := range dirs {
		clave := claveModulo(in.RepoRoot, dir, mods[dir])
		if e.Cache != nil && clave != "" {
			if fs, ok := e.Cache.Leer([]string{clave})[clave]; ok {
				out = append(out, fs...)
				continue
			}
		}
		fs, err := e.correrModulo(ctx, bin, in.RepoRoot, dir, mods[dir])
		if err != nil {
			return nil, err
		}
		if e.Cache != nil && clave != "" {
			e.Cache.Guardar(map[string][]finding.Finding{clave: fs})
		}
		out = append(out, fs...)
	}
	return out, nil
}

// claveModulo identifica un análisis: el contenido del módulo (los .go y
// manifiestos rastreados — la compilación depende de todos, no solo de los
// tocados) más los paquetes pedidos. Vacía = no cacheable.
func claveModulo(repoRoot, dir string, paquetes []string) string {
	huella := engines.HuellaModulo(repoRoot, dir, func(rel string) bool {
		base := strings.ToLower(path.Base(rel))
		return base == "go.mod" || base == "go.sum" || strings.HasSuffix(base, ".go")
	})
	if huella == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(huella + "|" + strings.Join(paquetes, ",")))
	return "staticcheck:" + hex.EncodeToString(sum[:])
}

func (e *Engine) correrModulo(ctx context.Context, bin, repoRoot, dir string, paquetes []string) ([]finding.Finding, error) {
	args := append([]string{"-f", "json"}, paquetes...)
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = filepath.Join(repoRoot, filepath.FromSlash(dir))
	cmd.Env = proc.Entorno()
	salida, runErr := proc.Correr(ctx, cmd, proc.MaxSalida)
	if salida.Recortada {
		return nil, fmt.Errorf("staticcheck devolvió más de %d MB de salida", proc.MaxSalida>>20)
	}
	if runErr != nil {
		var exit *exec.ExitError
		// Salir con 1 es "encontré algo": la respuesta está en el JSON de
		// stdout. Cualquier otra cosa —no arrancó, código mayor que 1— es
		// fallo operativo y el motor se degrada.
		if !errors.As(runErr, &exit) || exit.ExitCode() != 1 {
			detalle := ""
			if len(salida.Stderr) > 0 {
				detalle = ": " + recorte(salida.Stderr)
			}
			// %w: el orquestador clasifica la degradación con errors.Is, así
			// que el centinela (binario ausente, plazo agotado) tiene que
			// llegar entero. Con %v se perdía y todo salía como ":error".
			return nil, fmt.Errorf("staticcheck falló en %s: %w%s", dir, runErr, detalle)
		}
	}
	// Para recortar los paths absolutos hay que probar las dos formas del
	// directorio del módulo: staticcheck reporta el path tal como ve su
	// directorio de trabajo, y en Windows ese puede ser un alias 8.3
	// (HECTOR~1 en vez del nombre completo) o su forma canónica larga,
	// según quién arrancara el proceso.
	bases := []string{cmd.Dir}
	if canon, err := filepath.EvalSymlinks(cmd.Dir); err == nil && canon != cmd.Dir {
		bases = append(bases, canon)
	}
	return interpretar(salida.Stdout, dir, bases...)
}

func interpretar(raw []byte, dir string, bases ...string) ([]finding.Finding, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var out []finding.Finding
	for {
		var p problema
		if err := dec.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("salida de staticcheck ilegible: %v", err)
		}
		// El paquete no compila: sin programa no hay SSA que analizar. No es
		// un hallazgo sino análisis imposible — se degrada el motor con el
		// detalle, y el error real ya lo habrán señalado gofmt o govet.
		if p.Code == "compile" {
			return nil, fmt.Errorf("staticcheck no pudo compilar %s: %s", dir, recorte([]byte(p.Message)))
		}
		var sev finding.Severity
		var bloquea bool
		switch p.Severity {
		case "error":
			// Política §7: lint de severidad error bloquea, como govet.
			sev, bloquea = finding.Error, true
		case "ignored":
			// Suprimido con //lint:ignore en el propio código: se respeta.
			continue
		default:
			// "warning" (y cualquier severidad futura): avisa sin bloquear.
			sev, bloquea = finding.Warning, false
		}
		f := finding.Finding{
			Engine:      "staticcheck",
			RuleKey:     p.Code,
			Pillar:      finding.Quality,
			Severity:    sev,
			Blocking:    bloquea,
			File:        relativizar(p.Location.File, bases, dir),
			Line:        p.Location.Line,
			Message:     p.Message,
			Why:         fmt.Sprintf("staticcheck (%s) analiza la forma SSA del programa: el bug se demuestra sobre el flujo real de valores, no por parecido textual.", p.Code),
			FixHint:     fmt.Sprintf("Corrige lo que señala el mensaje; la ficha completa de la regla está en https://staticcheck.dev/docs/checks#%s.", p.Code),
			Verified:    true,
			Source:      finding.Deterministic,
			LineContent: p.Message,
		}
		if p.End.Line > p.Location.Line {
			f.EndLine = p.End.Line
		}
		f.ComputeFingerprint()
		out = append(out, f)
	}
	return out, nil
}

// relativizar convierte el path absoluto que reporta staticcheck en uno
// relativo a la raíz del repo con separador /: se recorta el directorio del
// módulo probando cada base (comparando sin distinguir mayúsculas, que es
// como comparan los paths de Windows) y se antepone el módulo cuando no es
// la raíz. Un path absoluto que no cuelga de ninguna base se deja tal cual:
// mejor uno raro que uno inventado.
func relativizar(file string, bases []string, dir string) string {
	f := filepath.ToSlash(file)
	recortado := false
	for _, b := range bases {
		base := filepath.ToSlash(b)
		if base != "" && len(f) > len(base)+1 && f[len(base)] == '/' &&
			strings.EqualFold(f[:len(base)], base) {
			f, recortado = f[len(base)+1:], true
			break
		}
	}
	if !recortado && (path.IsAbs(f) || filepath.IsAbs(filepath.FromSlash(f)) || (len(f) > 1 && f[1] == ':')) {
		return f
	}
	if dir != "." {
		return path.Join(dir, f)
	}
	return f
}

func recorte(b []byte) string {
	s := strings.Join(strings.Fields(string(b)), " ")
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}
