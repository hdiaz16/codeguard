package linters

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"codeguard/internal/engines"
	"codeguard/internal/finding"
)

// Tsc implementa la compuerta de compilación de tipos para TS (§7: BLOQUEA).
// Usa --incremental para que las corridas calientes queden en presupuesto
// (spike S5). En Windows el CLI de npm es npx.cmd, no un .exe — de ahí la
// resolución explícita.
//
// El tsconfig.json se busca SUBIENDO desde cada archivo tocado, no solo en la
// raíz: en el monorepo corporativo típico (backend/go.mod +
// frontend/tsconfig.json) la versión anterior no encontraba nada y la
// compuerta de tipos llevaba enrolada sin correr JAMÁS — en silencio, que es
// la clase de fallo que más caro cuesta descubrir.
type Tsc struct {
	// Cache: mismo proyecto TS (fuentes + tsconfig + lockfile) = los mismos
	// errores de tipos. tsc compila el proyecto completo aunque el cambio sea
	// de un archivo; sin esto, cada informe en un monorepo con frontend paga
	// la compilación entera.
	Cache engines.Cache
}

func (Tsc) Name() string { return "tsc" }

func (e Tsc) Applies(in engines.Input) bool { return len(e.proyectos(in)) > 0 }

// proyectos agrupa los .ts/.tsx cambiados por su tsconfig.json más cercano
// (relativo a la raíz; "." si es la propia raíz).
func (Tsc) proyectos(in engines.Input) []string {
	dirs := map[string]bool{}
	for _, f := range append(filesWithExt(in, ".ts"), filesWithExt(in, ".tsx")...) {
		if dir, ok := tsconfigDe(in.RepoRoot, f.Path); ok {
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

// tsconfigDe sube desde el archivo hasta el tsconfig.json más cercano, sin
// salirse de la raíz del repo ni entrar a node_modules.
func tsconfigDe(repoRoot, rel string) (string, bool) {
	if strings.Contains(rel, "node_modules/") {
		return "", false
	}
	dir := path.Dir(rel)
	for {
		abs := filepath.Join(repoRoot, filepath.FromSlash(dir), "tsconfig.json")
		if st, err := os.Stat(abs); err == nil && !st.IsDir() {
			return dir, true
		}
		if dir == "." || dir == "/" {
			return "", false
		}
		dir = path.Dir(dir)
	}
}

// claveProyecto identifica una compilación: las fuentes TS del proyecto, su
// tsconfig y el lockfile (el estado real de node_modules más allá del
// lockfile es un punto ciego asumido y documentado).
func claveProyecto(repoRoot, dir string) string {
	huella := engines.HuellaModulo(repoRoot, dir, func(rel string) bool {
		base := strings.ToLower(path.Base(rel))
		switch base {
		case "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml":
			return true
		}
		if strings.HasPrefix(base, "tsconfig") && strings.HasSuffix(base, ".json") {
			return true
		}
		return strings.HasSuffix(base, ".ts") || strings.HasSuffix(base, ".tsx") ||
			strings.HasSuffix(base, ".mts") || strings.HasSuffix(base, ".cts")
	})
	if huella == "" {
		return ""
	}
	return "tsc:" + dir + ":" + huella
}

// formato --pretty false: src/mod7.ts(19,14): error TS2322: mensaje
var tscLine = regexp.MustCompile(`^(.+?)\((\d+),\d+\): error (TS\d+): (.+)$`)

func (e Tsc) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	var out []finding.Finding
	for _, dir := range e.proyectos(in) {
		clave := ""
		if e.Cache != nil {
			if clave = claveProyecto(in.RepoRoot, dir); clave != "" {
				if fs, ok := e.Cache.Leer([]string{clave})[clave]; ok {
					out = append(out, fs...)
					continue
				}
			}
		}
		fs, err := correrProyecto(ctx, in.RepoRoot, dir)
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

func correrProyecto(ctx context.Context, repoRoot, dir string) ([]finding.Finding, error) {
	abs := filepath.Join(repoRoot, filepath.FromSlash(dir))
	bin := "npx"
	if _, err := os.Stat(filepath.Join(abs, "node_modules", ".bin", "tsc.cmd")); err == nil {
		bin = filepath.Join(abs, "node_modules", ".bin", "tsc.cmd")
	}
	var out string
	var err error
	if bin == "npx" {
		out, err = runTool(ctx, abs, "npx.cmd", "--no-install", "tsc", "--noEmit", "--incremental", "--pretty", "false")
	} else {
		out, err = runTool(ctx, abs, bin, "--noEmit", "--incremental", "--pretty", "false")
	}
	if err != nil {
		return nil, fmt.Errorf("tsc no corrió en %s: %w", dir, err)
	}
	var findings []finding.Finding
	for _, line := range strings.Split(out, "\n") {
		m := tscLine.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		lineNo, _ := strconv.Atoi(m[2])
		// tsc reporta relativo a SU proyecto; el hallazgo viaja relativo al repo.
		file := filepath.ToSlash(m[1])
		if dir != "." && !path.IsAbs(file) {
			file = path.Join(dir, file)
		}
		f := finding.Finding{
			Engine:      "tsc",
			RuleKey:     m[3],
			Pillar:      finding.Quality,
			Severity:    finding.Error,
			Blocking:    true,
			File:        file,
			Line:        lineNo,
			Message:     m[4],
			Why:         "Un error de tipos es un error de compilación: el CI lo rechazará igual.",
			FixHint:     "Corrige el tipo señalado; el mensaje de tsc indica el tipo esperado y el recibido.",
			Verified:    true,
			Source:      finding.Deterministic,
			LineContent: m[3] + " " + m[4],
		}
		f.ComputeFingerprint()
		findings = append(findings, f)
	}
	return findings, nil
}
