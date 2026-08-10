package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"codeguard/internal/baseline"
	"codeguard/internal/config"
	"codeguard/internal/daemon"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
	"codeguard/internal/pipeline"
)

// codeguard report: informe de hallazgos ESCRITO PARA UN AGENTE DE CÓDIGO
// (Claude Code, Gemini CLI, Codex...). Versionado, con instrucciones precisas
// y — lo importante — re-ejecutable: al volver a correrlo marca como resueltos
// los que ya no aparecen, y solo se declara COMPLETADO cuando no queda ninguno.

const reportFile = ".codeguard/HALLAZGOS.md"

var fpRe = regexp.MustCompile(`<!--\s*fp:([0-9a-f]{64})\s*-->`)

func reportCmd() *cobra.Command {
	var incluirAvisos bool
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Genera .codeguard/HALLAZGOS.md para que un agente de código los resuelva",
		Long: "Escanea el repo completo y escribe un informe con instrucciones precisas.\n" +
			"Re-ejecutarlo marca como RESUELTOS los hallazgos que ya no existen.",
		RunE: func(cmd *cobra.Command, args []string) error {
			repoRoot, err := gitdiff.RepoRoot(".")
			if err != nil {
				return err
			}
			cfg, err := config.Load(repoRoot)
			if err != nil {
				return err
			}
			if cfg == nil {
				return fmt.Errorf("el repo no está enrolado: corre `codeguard init`")
			}

			// hallazgos previos (para saber cuáles se resolvieron)
			previos := leerFingerprintsPrevios(filepath.Join(repoRoot, filepath.FromSlash(reportFile)))

			out, err := exec.Command("git", "-C", repoRoot, "ls-files").Output()
			if err != nil {
				return err
			}
			var files []gitdiff.ChangedFile
			for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				if line != "" {
					files = append(files, gitdiff.ChangedFile{Path: filepath.ToSlash(line), Status: "M"})
				}
			}
			fmt.Printf("escaneando %d archivos…\n", len(files))

			// La baseline se le PASA al pipeline, no sólo se cuenta: el informe
			// afirma que sus hallazgos "impiden hacer commit", y un hallazgo
			// baselineado no impide nada. Sin esto el informe mandaba al agente
			// a corregir deuda ya aceptada, mezclada con lo que sí bloquea, y
			// encima declaraba en el pie que la había suprimido.
			supr := baseline.Load(repoRoot)

			res, err := pipeline.Run(context.Background(), pipeline.Options{
				Config:       cfg,
				Diff:         &gitdiff.Diff{Files: files},
				Secrets:      nil, // los secretos se atienden en el acto, no por informe
				Engines:      daemon.Engines(cfg, false),
				Rulepack:     daemon.RulepackDir(repoRoot, cfg.Rulepack),
				Timeout:      15 * time.Minute,
				Suppressions: supr,
			})
			if err != nil {
				return err
			}

			// clasificar
			var bloq, avisos []finding.Finding
			actuales := map[string]bool{}
			for _, f := range res.Findings {
				actuales[f.Fingerprint] = true
				if f.Blocking {
					bloq = append(bloq, f)
				} else if incluirAvisos {
					avisos = append(avisos, f)
				}
			}
			var resueltos []string
			for fp, desc := range previos {
				if !actuales[fp] {
					resueltos = append(resueltos, desc)
				}
			}
			sort.Strings(resueltos)

			// res.Suppressed, no len(supr): lo que la baseline calló EN ESTE
			// escaneo. El tamaño del archivo incluye fingerprints de código que
			// ya no existe, así que anunciaba supresiones que no ocurrieron.
			md := construirInforme(cfg, res, bloq, avisos, resueltos, res.Suppressed, incluirAvisos)
			dest := filepath.Join(repoRoot, filepath.FromSlash(reportFile))
			_ = os.MkdirAll(filepath.Dir(dest), 0o755) // best-effort: el WriteFile de abajo dará el error real
			if err := os.WriteFile(dest, []byte(md), 0o644); err != nil {
				return err
			}

			fmt.Printf("\ninforme: %s\n", reportFile)
			fmt.Printf("  bloqueantes pendientes: %d\n", len(bloq))
			if incluirAvisos {
				fmt.Printf("  avisos: %d\n", len(avisos))
			}
			if len(resueltos) > 0 {
				fmt.Printf("  RESUELTOS desde el informe anterior: %d\n", len(resueltos))
			}
			if len(bloq) == 0 {
				fmt.Println("\n  ✅ COMPLETADO: no quedan bloqueantes")
			} else {
				fmt.Println("\n  entrégale el archivo a tu agente: \"resuelve .codeguard/HALLAZGOS.md\"")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&incluirAvisos, "avisos", false, "incluir también los hallazgos no bloqueantes")
	return cmd
}

func leerFingerprintsPrevios(path string) map[string]string {
	out := map[string]string{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	var ultimoTitulo string
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "### ") {
			ultimoTitulo = strings.TrimSpace(strings.TrimPrefix(line, "###"))
			ultimoTitulo = strings.TrimPrefix(ultimoTitulo, "✅ RESUELTO — ")
		}
		if m := fpRe.FindStringSubmatch(line); m != nil {
			out[m[1]] = ultimoTitulo
		}
	}
	return out
}

func construirInforme(cfg *config.Config, res *pipeline.Result, bloq, avisos []finding.Finding,
	resueltos []string, supr int, incluirAvisos bool) string {

	var b strings.Builder
	fecha := time.Now().Format("2006-01-02 15:04")
	completado := len(bloq) == 0

	fmt.Fprintf(&b, "# Hallazgos de CodeGuard\n\n")
	if completado {
		fmt.Fprintf(&b, "> ## ✅ COMPLETADO — no quedan hallazgos bloqueantes\n>\n")
		fmt.Fprintf(&b, "> Generado el %s · rulepack `%s`\n\n", fecha, cfg.Rulepack)
	} else {
		fmt.Fprintf(&b, "> **Estado: %d bloqueante(s) pendiente(s)** · generado el %s · rulepack `%s`\n\n",
			len(bloq), fecha, cfg.Rulepack)
	}

	b.WriteString(`## Instrucciones para el agente de código

Eres el agente encargado de resolver estos hallazgos. Reglas de trabajo:

1. **Atiende primero los BLOQUEANTES** — impiden hacer commit y el CI también los rechaza.
2. **Un hallazgo, un cambio, una verificación.** No agrupes correcciones no relacionadas.
3. **No suprimas la regla para callar el hallazgo** (nada de ` + "`// nolint`" + `, ` + "`# noqa`" + `,
   ` + "`@ts-ignore`" + ` ni añadir el fingerprint a la baseline). Corrige la causa.
4. **Verifica cada corrección** ejecutando lo que corresponda:
   - formato: ` + "`gofmt -w <archivo>`" + ` / ` + "`ruff format <archivo>`" + ` / ` + "`dotnet format`" + `
   - tipos: ` + "`npx tsc --noEmit`" + `
   - lint: ` + "`go vet ./...`" + ` / ` + "`ruff check <archivo>`" + `
5. **Al terminar, ejecuta ` + "`codeguard report`" + ` otra vez.** El informe se regenera:
   lo resuelto pasa a la sección "✅ Resueltos" y, cuando no quede ningún
   bloqueante, el encabezado dirá **COMPLETADO**. Ese es el criterio de terminado —
   no tu impresión de haber terminado.
6. Si un hallazgo te parece un falso positivo, **no lo silencies**: anótalo en la
   sección "Discrepancias" al final y sigue con los demás.

`)

	if len(bloq) > 0 {
		fmt.Fprintf(&b, "---\n\n## ⛔ Bloqueantes (%d)\n\n", len(bloq))
		for i, f := range bloq {
			escribirHallazgo(&b, i+1, f)
		}
	}

	if incluirAvisos && len(avisos) > 0 {
		fmt.Fprintf(&b, "---\n\n## ⚠️ Avisos (%d) — opcionales, no bloquean\n\n", len(avisos))
		for i, f := range avisos {
			escribirHallazgo(&b, i+1, f)
		}
	}

	if len(resueltos) > 0 {
		fmt.Fprintf(&b, "---\n\n## ✅ Resueltos desde el informe anterior (%d)\n\n", len(resueltos))
		for _, t := range resueltos {
			fmt.Fprintf(&b, "- [x] %s\n", t)
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, `---

## Discrepancias

<!-- El agente anota aquí lo que considere falso positivo, con su razón.
     Un humano decide después: corregir la regla o aceptar el hallazgo. -->

---

## Contexto

- Deuda preexistente suprimida por la baseline: **%d** (no bloquea; solo lo nuevo bloquea)
- Capas que no corrieron en este escaneo: %s
- Este informe lo genera `+"`codeguard report`"+` y se versiona con el repo.
`, supr, listaOVacio(res.Degraded))

	return b.String()
}

func escribirHallazgo(b *strings.Builder, n int, f finding.Finding) {
	pilar := map[finding.Pillar]string{
		finding.Security: "seguridad", finding.Quality: "calidad", finding.Data: "datos",
	}[f.Pillar]
	fmt.Fprintf(b, "### %d. `%s` — %s:%d\n", n, f.RuleKey, f.File, f.Line)
	fmt.Fprintf(b, "<!-- fp:%s -->\n\n", f.Fingerprint)
	fmt.Fprintf(b, "- [ ] **Pendiente** · pilar **%s** · motor `%s` · severidad `%s`\n\n", pilar, f.Engine, f.Severity)
	fmt.Fprintf(b, "**Qué detectó:** %s\n\n", f.Message)
	if f.Why != "" {
		fmt.Fprintf(b, "**Por qué importa:** %s\n\n", f.Why)
	}
	if f.FixHint != "" {
		fmt.Fprintf(b, "**Cómo resolverlo:** %s\n\n", f.FixHint)
	}
	fmt.Fprintf(b, "**Archivo:** `%s` · **línea:** %d\n\n", f.File, f.Line)
}

func listaOVacio(xs []string) string {
	if len(xs) == 0 {
		return "ninguna"
	}
	return "`" + strings.Join(xs, "`, `") + "`"
}
