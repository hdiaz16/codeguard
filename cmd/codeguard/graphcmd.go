package main

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"codeguard/internal/codegraph"
	"codeguard/internal/gitdiff"
	"codeguard/internal/ipc"
)

// codeguard graph: el grafo de dependencias REAL del repo, extraído del
// compilador (Go) o de los imports (TS/JS), como Mermaid listo para Obsidian.
// Un diagrama extraído del código nunca miente; uno dibujado a mano, siempre.

func graphCmd() *cobra.Command {
	var out string
	var deep bool
	cmd := &cobra.Command{
		Use:   "graph",
		Short: "Grafo del repo: --deep abre el explorador interactivo a nivel de función",
		RunE: func(cmd *cobra.Command, args []string) error {
			repoRoot, err := gitdiff.RepoRoot(".")
			if err != nil {
				return err
			}

			// La detección es por archivos rastreados, igual que en el
			// explorador del daemon: mirar manifiestos en la raíz dejaba fuera
			// a los monorepos (backend/go.mod + frontend/package.json), que
			// son el layout corporativo más común.
			dirsGo, hayTS := stacksDe(repoRoot)

			// ── modo profundo: función→función, función→consulta, WebGL ──
			if deep {
				if len(dirsGo) == 0 && !hayTS {
					return fmt.Errorf("el modo --deep soporta Go y TypeScript/JS y no encontré archivos de ninguno")
				}
				// Primero se le pide al agente que lo abra en SU ventana:
				// el explorador vive en el escritorio, no en un navegador.
				if _, err := ipc.Call(&ipc.Request{
					Command: "open-graph", RepoRoot: repoRoot, DeadlineMs: 3000,
				}, 4*time.Second); err == nil {
					fmt.Println("explorador abierto en la ventana del agente")
					return nil
				}
				// Antes había aquí una copia del explorador que se escribía a
				// disco y se abría en el navegador. Se eliminó por dos motivos:
				// el explorador vive en el escritorio, no en una pestaña, y esa
				// copia se quedó atrás —arrastraba el fallo del lienzo en blanco
				// mucho después de estar corregido en la buena.
				cg, err := codegraph.Build(repoRoot)
				if err != nil {
					return err
				}
				fmt.Printf("el agente no está corriendo, así que no hay dónde dibujarlo.\n")
				fmt.Printf("El grafo de este repo son %d funciones y %d relaciones.\n\n",
					len(cg.Nodes), len(cg.Edges))
				fmt.Println("Arranca el agente y vuelve a intentarlo:")
				fmt.Println("  codeguard daemon        (o reinicia sesión: arranca solo)")
				return nil
			}

			// Un monorepo aporta TODOS sus stacks al mismo grafo: cada módulo
			// Go por su go.mod (esté donde esté) más los imports de TS/JS.
			edges := map[string]bool{}
			var modos []string
			for _, dir := range dirsGo {
				e, gerr := goEdges(repoRoot, dir)
				if gerr != nil {
					return gerr
				}
				for k := range e {
					edges[k] = true
				}
			}
			if len(dirsGo) > 0 {
				modos = append(modos, "Go (go list)")
			}
			if hayTS {
				e, terr := tsEdges(repoRoot)
				if terr != nil {
					return terr
				}
				for k := range e {
					edges[k] = true
				}
				modos = append(modos, "TypeScript/JavaScript (imports)")
			}
			if len(modos) == 0 {
				return fmt.Errorf("no reconocí el stack: no hay archivos Go ni TS/JS rastreados")
			}
			mode := strings.Join(modos, " + ")
			regen := "codeguard graph"
			if len(edges) == 0 {
				return fmt.Errorf("no encontré dependencias internas que graficar")
			}

			// destino: el vault de Obsidian del repo si existe; docs/ si no
			if out == "" {
				if dirExistsIn(repoRoot, "docs/obsidian") {
					out = "docs/obsidian/Grafo de dependencias.md"
				} else {
					out = "docs/grafo-dependencias.md"
				}
			}
			outAbs := filepath.Join(repoRoot, filepath.FromSlash(out))
			if err := os.MkdirAll(filepath.Dir(outAbs), 0o755); err != nil {
				return err
			}

			var sorted []string
			for e := range edges {
				sorted = append(sorted, e)
			}
			sort.Strings(sorted)
			const maxEdges = 80
			truncated := 0
			if len(sorted) > maxEdges {
				truncated = len(sorted) - maxEdges
				sorted = sorted[:maxEdges]
			}

			var b strings.Builder
			fmt.Fprintf(&b, "# Grafo de dependencias\n\n")
			fmt.Fprintf(&b, "Extraído del código real — modo: %s. Regenerar: `%s`\n\n", mode, regen)
			b.WriteString("```mermaid\nflowchart LR\n")
			for _, e := range sorted {
				parts := strings.SplitN(e, "|", 2)
				fmt.Fprintf(&b, "    %s[\"%s\"] --> %s[\"%s\"]\n",
					nodeID(parts[0]), parts[0], nodeID(parts[1]), parts[1])
			}
			b.WriteString("```\n")
			if truncated > 0 {
				fmt.Fprintf(&b, "\n> ⚠️ %d aristas más omitidas por legibilidad (límite %d).\n", truncated, maxEdges)
			}
			if err := os.WriteFile(outAbs, []byte(b.String()), 0o644); err != nil {
				return err
			}
			fmt.Printf("grafo generado: %s (%d aristas, modo %s)\n", out, len(sorted), mode)
			fmt.Println("ábrelo en Obsidian: el Mermaid renderiza solo")
			return nil
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "ruta de salida (default: docs/obsidian/ o docs/)")
	cmd.Flags().BoolVar(&deep, "deep", false, "explorador interactivo a nivel de función (WebGL)")
	return cmd
}

// stacksDe detecta los stacks del repo por sus ARCHIVOS RASTREADOS, no por
// manifiestos en la raíz. Devuelve los directorios que contienen un go.mod
// (relativos a la raíz; "." si es la propia raíz) y si hay código TS/JS.
func stacksDe(repoRoot string) (dirsGo []string, hayTS bool) {
	rutas, err := gitdiff.Rastreados(repoRoot)
	if err != nil {
		return nil, false
	}
	for _, r := range rutas {
		switch {
		case path.Base(r) == "go.mod" && !strings.Contains(r, "spikes/"):
			dirsGo = append(dirsGo, path.Dir(r))
		case strings.Contains(r, "node_modules/"):
			// vendorizado: no cuenta como stack propio
		case strings.HasSuffix(r, ".ts") || strings.HasSuffix(r, ".tsx") ||
			strings.HasSuffix(r, ".js") || strings.HasSuffix(r, ".jsx"):
			hayTS = true
		}
	}
	sort.Strings(dirsGo)
	return dirsGo, hayTS
}

// ── Go: la verdad del compilador ────────────────────────────────────────────
// dir es el directorio del go.mod, relativo a la raíz ("." si es la raíz):
// en un monorepo cada módulo aporta sus aristas, prefijadas con su carpeta
// para que backend/internal y frontend/internal no se confundan.
func goEdges(repoRoot, dir string) (map[string]bool, error) {
	moduloDir := filepath.Join(repoRoot, filepath.FromSlash(dir))
	raw, err := os.ReadFile(filepath.Join(moduloDir, "go.mod"))
	if err != nil {
		return nil, err
	}
	module := ""
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "module ") {
			module = strings.TrimSpace(strings.TrimPrefix(line, "module "))
			break
		}
	}
	c := exec.Command("go", "list", "-f", "{{.ImportPath}}: {{range .Imports}}{{.}} {{end}}", "./...")
	c.Dir = moduloDir
	outB, err := c.Output()
	if err != nil {
		return nil, fmt.Errorf("go list falló en %s: %w", dir, err)
	}
	prefijar := func(rel string) string {
		if dir == "." {
			return shorten(rel)
		}
		return shorten(path.Join(dir, rel))
	}
	edges := map[string]bool{}
	for _, line := range strings.Split(string(outB), "\n") {
		from, deps, ok := strings.Cut(line, ": ")
		if !ok || !strings.HasPrefix(from, module) {
			continue
		}
		fromShort := prefijar(strings.TrimPrefix(strings.TrimPrefix(from, module), "/"))
		for _, dep := range strings.Fields(deps) {
			if !strings.HasPrefix(dep, module+"/") {
				continue
			}
			toShort := prefijar(strings.TrimPrefix(dep, module+"/"))
			if fromShort != toShort && fromShort != "" && toShort != "" {
				edges[fromShort+"|"+toShort] = true
			}
		}
	}
	return edges, nil
}

// ── TS/JS: imports relativos y con alias @/ (Next.js), a nivel de carpeta ────
var importRe = regexp.MustCompile(`(?m)(?:from\s+|require\()\s*['"]((?:\.{1,2}|@)/[^'"]+)['"]`)

func tsEdges(repoRoot string) (map[string]bool, error) {
	rutas, err := gitdiff.Rastreados(repoRoot, "*.ts", "*.tsx", "*.js", "*.jsx")
	if err != nil {
		return nil, err
	}
	edges := map[string]bool{}
	for _, rel := range rutas {
		if strings.Contains(rel, "node_modules/") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(rel)))
		if err != nil {
			continue
		}
		fromPkg := shorten(path.Dir(rel))
		for _, m := range importRe.FindAllStringSubmatch(string(raw), -1) {
			var target string
			if strings.HasPrefix(m[1], "@/") {
				// alias estándar de Next/Vite: "@/x" = "src/x" (o raíz)
				target = "src/" + strings.TrimPrefix(m[1], "@/")
				if !dirExistsIn(repoRoot, "src") {
					target = strings.TrimPrefix(m[1], "@/")
				}
			} else {
				target = path.Clean(path.Join(path.Dir(rel), m[1]))
			}
			toPkg := shorten(path.Dir(target))
			// si el import apunta a un índice de carpeta, la carpeta es el destino
			if !strings.Contains(path.Base(target), ".") {
				toPkg = shorten(target)
			}
			if fromPkg != toPkg && fromPkg != "" && toPkg != "" && toPkg != "." {
				edges[fromPkg+"|"+toPkg] = true
			}
		}
	}
	return edges, nil
}

// shorten agrupa a máximo 3 niveles para que el grafo respire.
func shorten(p string) string {
	p = strings.TrimPrefix(filepath.ToSlash(p), "./")
	parts := strings.Split(p, "/")
	if len(parts) > 3 {
		parts = parts[:3]
	}
	return strings.Join(parts, "/")
}

var idClean = regexp.MustCompile(`[^a-zA-Z0-9]`)

func nodeID(s string) string { return "n_" + idClean.ReplaceAllString(s, "_") }

func dirExistsIn(root, rel string) bool {
	st, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel)))
	return err == nil && st.IsDir()
}
