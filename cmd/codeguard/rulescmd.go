package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"codeguard/internal/config"
	"codeguard/internal/gitdiff"
	"codeguard/internal/llm"
)

// Diferenciador: las convenciones escritas del equipo (CLAUDE.md, etc.) se
// convierten en reglas Semgrep ejecutables. La documentación deja de ser
// letra muerta y se vuelve compuerta.

const rulesPrompt = `Eres un experto en Semgrep. Te entrego las convenciones escritas de un equipo de desarrollo.
Tu tarea: identificar las convenciones VERIFICABLES MECÁNICAMENTE sobre el código y proponer reglas Semgrep.

Devuelve SOLO un objeto JSON con la estructura exacta de un archivo de reglas Semgrep:
{"rules":[{"id":"kebab-case","languages":["typescript"],"severity":"WARNING","message":"...","patterns":[...],"metadata":{"pillar":"quality|security|data","why":"...","fix_hint":"..."}}]}

Reglas estrictas:
- Solo reglas expresables en Semgrep con precisión alta. Las convenciones vagas ("código limpio") se OMITEN.
- severity WARNING salvo riesgo real de seguridad/datos = ERROR. Textos message/why/fix_hint en español.
- Usa "pattern", "patterns", "pattern-either", "pattern-inside", "pattern-not", "pattern-regex" según convenga — sintaxis Semgrep válida.
- Máximo 5 reglas, las de mayor valor. Piensa poco y responde directo. Si nada es verificable: {"rules":[]}.
- Sin explicaciones ni razonamiento: SOLO el JSON.`

// extractJSON rescata el objeto JSON aunque un modelo razonador haya
// mezclado prosa: toma del primer '{' al último '}'.
func extractJSON(content string) string {
	i := strings.Index(content, "{")
	j := strings.LastIndex(content, "}")
	if i < 0 || j <= i {
		return ""
	}
	return content[i : j+1]
}

func rulesCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "rules",
		Short: "Gestión de reglas de la casa",
	}
	root.AddCommand(&cobra.Command{
		Use:   "suggest",
		Short: "Propone reglas Semgrep a partir de las convenciones escritas del repo (CLAUDE.md...)",
		RunE: func(cmd *cobra.Command, args []string) error {
			repoRoot, err := gitdiff.RepoRoot(".")
			if err != nil {
				return err
			}
			cfg, err := config.Load(repoRoot)
			if err != nil || cfg == nil {
				return fmt.Errorf("el repo no está enrolado (falta %s)", config.RelPath)
			}
			client := llm.New(cfg.LLM)
			if client == nil {
				return fmt.Errorf("sin endpoint/API key del modelo (%s no definida)", cfg.LLM.APIKeyEnv)
			}

			// Recolectar las convenciones escritas del repo.
			var docs strings.Builder
			found := []string{}
			for _, name := range []string{"CLAUDE.md", "CONVENTIONS.md", "CONTRIBUTING.md", ".cursorrules", "docs/conventions.md"} {
				raw, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(name)))
				if err != nil {
					continue
				}
				found = append(found, name)
				fmt.Fprintf(&docs, "\n=== %s ===\n%s\n", name, string(raw))
			}
			if len(found) == 0 {
				return fmt.Errorf("no encontré convenciones escritas (CLAUDE.md, CONVENTIONS.md, CONTRIBUTING.md, .cursorrules)")
			}
			fmt.Printf("leyendo convenciones de: %s\n", strings.Join(found, ", "))
			fmt.Println("consultando al modelo…")

			// Generar reglas es tarea de fondo, no de commit: margen amplio.
			res, err := client.Complete(context.Background(), cfg.LLM.Fast(), rulesPrompt,
				docs.String(), 170*time.Second, 9000)
			if err != nil {
				return fmt.Errorf("el modelo no respondió: %w", err)
			}
			// JSON es YAML válido: Semgrep lee el archivo tal cual. Validamos
			// que sea JSON bien formado con la llave "rules" antes de escribir.
			raw := extractJSON(res.Content)
			var probe struct {
				Rules []map[string]any `json:"rules"`
			}
			if raw == "" || json.Unmarshal([]byte(raw), &probe) != nil {
				dbg := filepath.Join(repoRoot, ".codeguard", "rules-debug.txt")
				_ = os.WriteFile(dbg, []byte(res.Content), 0o644) // volcado de diagnóstico; el error ya se devuelve abajo
				return fmt.Errorf("el modelo no devolvió reglas utilizables (respuesta cruda en %s)", dbg)
			}
			pretty, _ := json.MarshalIndent(probe, "", "  ")
			yaml := string(pretty)
			fmt.Printf("el modelo propuso %d regla(s)\n", len(probe.Rules))

			out := filepath.Join(repoRoot, ".codeguard", "proposed-rules.yaml")
			header := "# Reglas PROPUESTAS por el modelo a partir de las convenciones escritas del repo.\n" +
				"# REVISAR ANTES DE ADOPTAR: mover las buenas al rulepack de la casa y borrar este archivo.\n" +
				"# Nada de aquí se aplica automáticamente.\n\n"
			if err := os.WriteFile(out, []byte(header+yaml+"\n"), 0o644); err != nil {
				return err
			}
			fmt.Printf("propuestas escritas en %s (%d tokens del modelo)\n", out, res.Usage.CompletionTokens)
			fmt.Println("revísalas y mueve las que valgan al rulepack — nada se aplica solo")
			return nil
		},
	})
	return root
}
