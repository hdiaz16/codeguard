package main

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"codeguard/internal/config"
	"codeguard/internal/gitdiff"
	"codeguard/internal/registry"
)

// codeguard init: enrola un repo detectando lenguajes, migraciones y
// exclusiones. Nadie escribe YAML a mano; la config se versiona y el resto
// del equipo la recibe con git pull.

var extToLang = map[string]string{
	".go": "go", ".ts": "typescript", ".tsx": "typescript", ".js": "javascript",
	".jsx": "javascript", ".py": "python", ".cs": "csharp", ".java": "java",
	".kt": "kotlin", ".dart": "dart", ".sql": "sql",
}

func initCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Enrola este repo: detecta lenguajes y genera .codeguard/config.yaml + hooks + baseline",
		RunE: func(cmd *cobra.Command, args []string) error {
			repoRoot, err := gitdiff.RepoRoot(".")
			if err != nil {
				return fmt.Errorf("no estás dentro de un repo git: %w", err)
			}
			cfgPath := filepath.Join(repoRoot, filepath.FromSlash(config.RelPath))
			if _, err := os.Stat(cfgPath); err == nil && !force {
				return fmt.Errorf("el repo ya está enrolado (%s existe); usa --force para regenerar", config.RelPath)
			}

			// ── detección sobre los archivos rastreados ──
			out, err := exec.Command("git", "-C", repoRoot, "ls-files").Output()
			if err != nil {
				return err
			}
			langCount := map[string]int{}
			migrationDirs := map[string]bool{}
			hasNode, hasDotnet := false, false
			for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				p := filepath.ToSlash(strings.TrimSpace(line))
				if p == "" {
					continue
				}
				if lang, ok := extToLang[strings.ToLower(path.Ext(p))]; ok {
					langCount[lang]++
				}
				low := strings.ToLower(p)
				if strings.HasSuffix(low, ".sql") && strings.Contains(low, "migration") {
					migrationDirs[path.Dir(p)+"/*.sql"] = true
				}
				if path.Base(low) == "package.json" {
					hasNode = true
				}
				if strings.HasSuffix(low, ".csproj") || strings.HasSuffix(low, ".sln") {
					hasDotnet = true
				}
			}
			var langs []string
			for l, n := range langCount {
				if n >= 2 { // un archivo suelto no define el stack
					langs = append(langs, l)
				}
			}
			// Pero si NINGUNO llega a dos, el repo es nuevo o pequeño, no
			// ambiguo: enrolarlo con lo que haya es mejor que negarse. Antes
			// esto dejaba fuera a cualquier proyecto recién empezado, con un
			// mensaje que además culpaba al lenguaje y no al conteo.
			if len(langs) == 0 {
				for l := range langCount {
					langs = append(langs, l)
				}
			}
			sort.Strings(langs)
			if len(langs) == 0 {
				return fmt.Errorf("no encontré ningún archivo de un lenguaje soportado " +
					"(go, python, typescript/javascript, c#, java, sql) entre los archivos rastreados por git.\n" +
					"Si el repo aún no tiene código, haz un primer commit y vuelve a ejecutar `codeguard init`")
			}
			var migrations []string
			for d := range migrationDirs {
				migrations = append(migrations, d)
			}
			sort.Strings(migrations)

			excludes := []string{"**/*.log", "**/*.db", "**/*.exe", "bin/**"}
			if hasNode {
				excludes = append(excludes, "**/node_modules/**", "**/.next/**", "**/dist/**")
			}
			if hasDotnet {
				excludes = append(excludes, "**/obj/**", "**/*.g.cs", "**/*.designer.cs")
			}
			sort.Strings(excludes)

			// ── plantilla de la organización: si el instalador dejó una junto
			// al binario, manda ella (endpoint/modelos del equipo) ──
			llmBlock := defaultLLMBlock
			if exe, err := os.Executable(); err == nil {
				if raw, err := os.ReadFile(filepath.Join(filepath.Dir(exe), "org-llm.yaml")); err == nil {
					llmBlock = strings.TrimRight(string(raw), "\n")
				}
			}

			yaml := fmt.Sprintf(`version: 1
rulepack: "2026.08.2"

languages: [%s]

paths:
  exclude: [%s]
  migrations: [%s]
  sensitive: []          # marca aquí rutas de auth/pagos/PII: suben el riesgo
  generated: []

# Complejidad ciclomática por función a partir de la cual se avisa.
# Nunca bloquea: partir una función es decisión de quien la escribe.
max_complexity: 15

gates:
  secrets: block
  format: block
  compile: block
  lint_error: block
  semgrep_error: block
  migration_unsafe: block
  cve_critical: warn_local_block_ci
  llm: never_block

risk:
  threshold: 35
  weights:
    touches_migration: 30
    touches_sensitive: 25
    ai_generated: 20
    touches_security_config: 20
    adds_dependency: 15
    touches_query: 15
    many_files: 10
    tests_only: -20
    docs_only: -40

ui:
  max_visible_findings: 7
  auto_open_panel: on_block

%s

max_diff_lines: 2000
`, strings.Join(langs, ", "), quoteList(excludes), quoteList(migrations), llmBlock)

			if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(cfgPath, []byte(yaml), 0o644); err != nil {
				return err
			}
			fmt.Printf("config generada: %s\n", config.RelPath)
			fmt.Printf("  lenguajes detectados: %s\n", strings.Join(langs, ", "))
			if len(migrations) > 0 {
				fmt.Printf("  migraciones: %s\n", strings.Join(migrations, ", "))
			}

			// ── hooks + baseline: enrolamiento completo en un comando ──
			fmt.Println("\ninstalando hooks…")
			if err := installCmd().RunE(cmd, nil); err != nil {
				return err
			}
			fmt.Println("\ngenerando baseline (los hallazgos preexistentes no bloquearán)…")
			if err := baselineCmd().RunE(cmd, nil); err != nil {
				return err
			}
			// registrar el proyecto: aparece en el panel y el explorador desde
			// el momento del init, sin esperar al primer commit.
			registry.Add(repoRoot, filepath.Base(repoRoot), strings.Join(langs, ","))

			fmt.Println("\nLISTO. Versiona .codeguard/ y .githooks/ para que el equipo quede enrolado con git pull.")
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "regenerar aunque ya exista config")
	return cmd
}

const defaultLLMBlock = `llm:
  provider: "azure-foundry"
  endpoint: "https://TU-RECURSO.services.ai.azure.com/openai/v1"
  api_key_env: "FOUNDRY_API_KEY"
  model: "FW-Kimi-K3"
  model_fast: "gpt-5.6-sol"
  timeout_ms: 20000
  max_diff_tokens: 12000
  # 0 = sin límite. Con un tope, hacen falta las tarifas de abajo para poder
  # convertir tokens en dinero; sin ellas el tope no se puede aplicar.
  monthly_budget_usd: 0
  price_in_per_mtok: 0
  price_out_per_mtok: 0`

func quoteList(items []string) string {
	quoted := make([]string, len(items))
	for i, s := range items {
		quoted[i] = `"` + s + `"`
	}
	return strings.Join(quoted, ", ")
}
