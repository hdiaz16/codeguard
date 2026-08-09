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

	"github.com/spf13/cobra"

	"codeguard/internal/codegraph"
	"codeguard/internal/gitdiff"
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

			// ── modo profundo: función→función, función→consulta, WebGL ──
			if deep {
				if !fileExistsIn(repoRoot, "go.mod") {
					return fmt.Errorf("el modo --deep hoy soporta Go (busqué go.mod); TS/Python vienen después")
				}
				fmt.Println("analizando el AST del repo…")
				cg, err := codegraph.BuildGo(repoRoot)
				if err != nil {
					return err
				}
				dir := filepath.Join(repoRoot, "docs", "explorador")
				page, err := codegraph.WriteExplorer(cg, dir)
				if err != nil {
					return err
				}
				fmt.Printf("explorador generado: %d funciones, %d relaciones\n", len(cg.Nodes), len(cg.Edges))
				fmt.Printf("  %s\n", page)
				exec.Command("cmd", "/c", "start", "", page).Start()
				return nil
			}

			var edges map[string]bool
			var mode, regen string
			switch {
			case fileExistsIn(repoRoot, "go.mod"):
				mode = "Go (go list)"
				regen = "codeguard graph  (usa go list bajo el capó)"
				edges, err = goEdges(repoRoot)
			case fileExistsIn(repoRoot, "package.json"):
				mode = "TypeScript/JavaScript (imports)"
				regen = "codeguard graph  (parsea los imports relativos)"
				edges, err = tsEdges(repoRoot)
			default:
				return fmt.Errorf("no reconocí el stack (busqué go.mod o package.json)")
			}
			if err != nil {
				return err
			}
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

// ── Go: la verdad del compilador ────────────────────────────────────────────
func goEdges(repoRoot string) (map[string]bool, error) {
	raw, err := os.ReadFile(filepath.Join(repoRoot, "go.mod"))
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
	c.Dir = repoRoot
	outB, err := c.Output()
	if err != nil {
		return nil, fmt.Errorf("go list falló: %w", err)
	}
	edges := map[string]bool{}
	for _, line := range strings.Split(string(outB), "\n") {
		from, deps, ok := strings.Cut(line, ": ")
		if !ok || !strings.HasPrefix(from, module) {
			continue
		}
		fromShort := shorten(strings.TrimPrefix(strings.TrimPrefix(from, module), "/"))
		for _, dep := range strings.Fields(deps) {
			if !strings.HasPrefix(dep, module+"/") {
				continue
			}
			toShort := shorten(strings.TrimPrefix(dep, module+"/"))
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
	c := exec.Command("git", "ls-files", "*.ts", "*.tsx", "*.js", "*.jsx")
	c.Dir = repoRoot
	outB, err := c.Output()
	if err != nil {
		return nil, err
	}
	edges := map[string]bool{}
	for _, rel := range strings.Split(strings.TrimSpace(string(outB)), "\n") {
		rel = filepath.ToSlash(strings.TrimSpace(rel))
		if rel == "" || strings.Contains(rel, "node_modules/") {
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

func fileExistsIn(root, rel string) bool {
	_, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel)))
	return err == nil
}
func dirExistsIn(root, rel string) bool {
	st, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel)))
	return err == nil && st.IsDir()
}
