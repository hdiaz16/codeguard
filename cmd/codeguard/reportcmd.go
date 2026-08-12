package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
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
	var incluirAvisos, incluirDeuda bool
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

			// hallazgos previos (para saber cuáles se resolvieron) y las
			// discrepancias anotadas, que sobreviven a la regeneración
			previos := leerFingerprintsPrevios(filepath.Join(repoRoot, filepath.FromSlash(reportFile)))
			discrepancias := leerDiscrepanciasPrevias(filepath.Join(repoRoot, filepath.FromSlash(reportFile)))

			rutas, err := gitdiff.Rastreados(repoRoot)
			if err != nil {
				return err
			}
			var files []gitdiff.ChangedFile
			for _, r := range rutas {
				// El informe no se analiza a sí mismo: cada corrida lo
				// reescribe, y ese cambio perpetuo invalidaba su entrada de
				// caché — semgrep pagaba su arranque completo en cada informe
				// solo para mirar la salida del informe anterior.
				if r == reportFile {
					continue
				}
				files = append(files, gitdiff.ChangedFile{Path: r, Status: "M"})
			}
			files = conHuellas(repoRoot, files)
			fmt.Printf("escaneando %d archivos…\n", len(files))

			// El caché por archivo (§9) es lo que separa el primer informe
			// (todo se analiza) del segundo (solo lo que cambió desde entonces).
			cache, cerrarCache := abrirCache(repoRoot, cfg)
			defer cerrarCache()

			// La baseline NO se le pasa al pipeline: el informe la aplica él
			// mismo, porque necesita las dos mitades. Los hallazgos nuevos van
			// a "bloqueantes" (impiden commitear, el agente los corrige); los
			// baselineados son deuda aceptada — no bloquean, pero el agente los
			// ENCONTRÓ, y hasta ahora no existía ninguna superficie donde un
			// humano pudiera revisarlos: quedaban como fingerprints en
			// baseline.txt, hallados pero invisibles.
			supr := baseline.Load(repoRoot)

			res, err := pipeline.Run(context.Background(), pipeline.Options{
				Config:   cfg,
				Diff:     &gitdiff.Diff{Files: files},
				Secrets:  nil, // los secretos se atienden en el acto, no por informe
				Engines:  daemon.Engines(cfg, false, cache),
				Rulepack: daemon.RulepackDir(repoRoot, cfg.Rulepack),
				Timeout:  15 * time.Minute,
			})
			if err != nil {
				return err
			}

			// clasificar: nuevo-bloqueante / nuevo-aviso / deuda baselineada.
			// "actuales" incluye TAMBIÉN la deuda: un hallazgo baselineado que
			// desaparece del código cuenta como resuelto, no como fantasma.
			var bloq, avisos, deuda []finding.Finding
			actuales := map[string]bool{}
			for _, f := range res.Findings {
				actuales[f.Fingerprint] = true
				switch {
				case supr[f.Fingerprint]:
					deuda = append(deuda, f)
				case f.Blocking:
					bloq = append(bloq, f)
				case incluirAvisos:
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

			md := construirInforme(cfg, res, bloq, avisos, resueltos, deuda, incluirAvisos, incluirDeuda, discrepancias)
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
			if len(deuda) > 0 {
				if incluirDeuda {
					fmt.Printf("  deuda aceptada (baseline): %d — detallada en el informe\n", len(deuda))
				} else {
					fmt.Printf("  deuda aceptada (baseline): %d — revísala con `codeguard report --deuda`\n", len(deuda))
				}
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
	cmd.Flags().BoolVar(&incluirDeuda, "deuda", false, "detallar la deuda aceptada por la baseline (hallada pero suprimida)")
	return cmd
}

// leerDiscrepanciasPrevias rescata lo que el agente anotó en la sección
// "Discrepancias" del informe anterior.
//
// El informe INSTRUYE al agente a anotar ahí los falsos positivos "para que
// un humano decida después" — y acto seguido cada `codeguard report`
// reconstruía el archivo entero y borraba la anotación antes de que ningún
// humano la viera. Las dos mitades del contrato se contradecían.
func leerDiscrepanciasPrevias(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	texto := strings.ReplaceAll(string(raw), "\r\n", "\n")
	const marca = "\n## Discrepancias\n"
	inicio := strings.Index(texto, marca)
	if inicio < 0 {
		return ""
	}
	cuerpo := texto[inicio+len(marca):]
	if fin := strings.Index(cuerpo, "\n---"); fin >= 0 {
		cuerpo = cuerpo[:fin]
	}
	cuerpo = strings.TrimSpace(cuerpo)
	// El comentario-guía de la plantilla no es una anotación: se descarta para
	// no acumular copias de sí mismo en cada regeneración.
	if strings.HasPrefix(cuerpo, "<!--") {
		if cierre := strings.Index(cuerpo, "-->"); cierre >= 0 {
			cuerpo = strings.TrimSpace(cuerpo[cierre+3:])
		}
	}
	return cuerpo
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
	resueltos []string, deuda []finding.Finding, incluirAvisos, incluirDeuda bool, discrepancias string) string {

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
   - tipos: ` + "`npx tsc --noEmit`" + ` / ` + "`mypy <archivo>`" + `
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

	// La deuda aceptada, cuando se pide: el agente la ENCONTRÓ y la baseline la
	// calla en el commit —correcto: sólo lo nuevo bloquea—, pero sin esta
	// sección no existía superficie donde un humano pudiera revisarla. Quedaba
	// como fingerprints en baseline.txt: hallada pero invisible.
	if incluirDeuda && len(deuda) > 0 {
		ordenada := make([]finding.Finding, len(deuda))
		copy(ordenada, deuda)
		sort.Slice(ordenada, func(i, j int) bool {
			if ordenada[i].File != ordenada[j].File {
				return ordenada[i].File < ordenada[j].File
			}
			return ordenada[i].Line < ordenada[j].Line
		})
		fmt.Fprintf(&b, "---\n\n## 📋 Deuda aceptada por la baseline (%d) — no bloquea\n\n", len(ordenada))
		b.WriteString("Hallazgos que ya existían al enrolar el repo. Se revisan al ritmo del equipo;\n" +
			"al corregir uno, quita su línea de `.codeguard/baseline.txt` (o regenera la\n" +
			"baseline) para que vuelva a vigilarse como nuevo.\n\n")
		for _, f := range ordenada {
			fmt.Fprintf(&b, "- `%s` — `%s:%d` · %s <!-- fp:%s -->\n",
				f.RuleKey, f.File, f.Line, f.Message, f.Fingerprint)
		}
		b.WriteString("\n")
	}

	b.WriteString("---\n\n## Discrepancias\n\n")
	if discrepancias != "" {
		// Lo anotado sobrevive a la regeneración: el informe le pide al agente
		// escribir aquí sus falsos positivos "para que un humano decida", y la
		// versión anterior los borraba en la siguiente corrida.
		b.WriteString(discrepancias + "\n\n")
	} else {
		b.WriteString("<!-- El agente anota aquí lo que considere falso positivo, con su razón.\n" +
			"     Un humano decide después: corregir la regla o aceptar el hallazgo. -->\n\n")
	}

	pistaDeuda := ""
	if !incluirDeuda && len(deuda) > 0 {
		pistaDeuda = " — detállala con `codeguard report --deuda`"
	}
	fmt.Fprintf(&b, `---

## Contexto

- Deuda preexistente suprimida por la baseline: **%d** (no bloquea; solo lo nuevo bloquea)%s
- Capas que no corrieron en este escaneo: %s
- Este informe lo genera `+"`codeguard report`"+` y se versiona con el repo.
`, len(deuda), pistaDeuda, listaOVacio(res.Degraded))

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
