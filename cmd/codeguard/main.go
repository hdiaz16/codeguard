// codeguard — binario único (ADR-03): el mismo que corre en local y en CI.
// Fase 1: subcomando `ci` con el pipeline determinista y salida SARIF.
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"codeguard/internal/baseline"
	"codeguard/internal/config"
	"codeguard/internal/daemon"
	glengine "codeguard/internal/engines/gitleaks"
	"codeguard/internal/engines/proc"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
	"codeguard/internal/pipeline"
	"codeguard/internal/sarif"
	"codeguard/internal/store"
)

// version la inyecta build-dist con -X main.version desde setup.iss — una
// sola fuente de verdad. "dev" delata un binario compilado a mano.
var version = "dev"

func main() {
	// Lo primero: el PATH del registro puede traer motores que este proceso no
	// ve. Un hook lanzado desde una terminal o un editor que arrancaron antes
	// de instalar el agente no encuentra gitleaks, y la compuerta de secretos
	// es fail-closed: BLOQUEA el commit pidiendo que se instale algo que ya
	// está instalado.
	proc.RefrescarPATH()
	// Y el resto de variables del usuario: aquí vive la clave del modelo, y sin
	// esto `codeguard config --probar` decía "la variable no tiene valor" con la
	// clave sentada en el registro desde hacía días.
	proc.RefrescarVariables()
	// El caché de resultados lleva la versión en su clave: al actualizar el
	// agente, lo que analizó el binario viejo deja de darse por bueno.
	daemon.Version = version

	root := &cobra.Command{
		Use:           "codeguard",
		Short:         "Análisis de código pre-commit con paridad hacia el CI",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(ciCmd(), versionCmd(), hookCmd(), installCmd(), repairCmd(), daemonCmd(),
		baselineCmd(), statsCmd(), rulesCmd(), initCmd(), graphCmd(), reportCmd(), statusCmd(),
		enginesCmd(), configCmd(), forgetCmd(), syncCmd())
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "codeguard:", err)
		os.Exit(2)
	}
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Versión del binario",
		Run: func(*cobra.Command, []string) {
			fmt.Println("codeguard", version)
		},
	}
}

func ciCmd() *cobra.Command {
	var base, head, format, out, repoDir string
	var shadow bool

	cmd := &cobra.Command{
		Use:   "ci",
		Short: "Analiza el rango base..head (modo CI / sombra)",
		RunE: func(cmd *cobra.Command, args []string) error {
			repoRoot, err := gitdiff.RepoRoot(repoDir)
			if err != nil {
				return err
			}
			cfg, err := config.Load(repoRoot)
			if err != nil {
				return err
			}

			var diff *gitdiff.Diff
			if cfg != nil {
				if diff, err = gitdiff.Range(repoRoot, base, head); err != nil {
					return err
				}
			} else {
				diff = &gitdiff.Diff{}
			}

			rulepack := ""
			if cfg != nil {
				rulepack = filepath.Join(repoRoot, "rulepacks", cfg.Rulepack)
				if _, statErr := os.Stat(rulepack); statErr != nil {
					// rulepack distribuido junto al binario (repos que no vendorean reglas)
					if exe, exeErr := os.Executable(); exeErr == nil {
						alt := filepath.Join(filepath.Dir(exe), "rulepacks", cfg.Rulepack)
						if _, altErr := os.Stat(alt); altErr == nil {
							rulepack = alt
						}
					}
				}
			}

			inCI := os.Getenv("GITHUB_ACTIONS") == "true"
			res, err := pipeline.Run(context.Background(), pipeline.Options{
				Config:  cfg,
				Diff:    diff,
				Secrets: &glengine.Engine{Mode: "range", Base: base, Head: head},
				// Sin caché: el runner del CI es efímero y nunca acertaría.
				Engines:      daemon.Engines(cfg, inCI, nil),
				Rulepack:     rulepack,
				Timeout:      5 * time.Minute,
				Suppressions: baseline.Load(repoRoot),
			})
			if err != nil {
				return err
			}

			printSummary(res)

			if format == "sarif" && out != "" {
				if err := sarif.Write(out, version, res.Findings); err != nil {
					return fmt.Errorf("escribiendo SARIF: %w", err)
				}
				fmt.Printf("SARIF: %s (%d resultados)\n", out, len(res.Findings))
			}

			if cfg != nil {
				if err := persist(repoRoot, cfg, res, len(diff.Files)); err != nil {
					// La telemetría nunca tumba el análisis (P4).
					fmt.Fprintln(os.Stderr, "aviso: no se pudo persistir el run:", err)
				}
			}

			// Modo sombra (fase 1): registra todo, nunca falla el job.
			if !shadow {
				if res.Verdict == pipeline.Block {
					os.Exit(1)
				}
				// Y una capa que NO MIRÓ tampoco es un job verde. Medido: el
				// mismo `db.Query("… " + id)` sale con exit 1 si el rulepack
				// está y con exit 0 si falta, imprimiendo "capas degradadas"
				// que ningún CI lee. El porqué de qué entra y qué no está en
				// pipeline.SinGarantia.
				if rotas := pipeline.SinGarantia(res.Degraded); len(rotas) > 0 {
					fmt.Println("codeguard: NO PUEDO GARANTIZAR ESTE COMMIT —",
						strings.Join(rotas, ", "))
					fmt.Println("  Estas capas no llegaron a mirar, así que un problema suyo pasaría sin verse.")
					// Un plazo agotado manda a un sitio distinto que un rulepack
					// ausente, y decirlo ahorra una tarde: el primero suele ser
					// contención del runner y se arregla reintentando el job; el
					// segundo es configuración y no se arregla solo. Sin esta
					// distinción, quien lea el log se pone a buscar un bug en el
					// código donde sólo hubo una máquina ocupada.
					porPlazo := false
					for _, r := range rotas {
						if strings.HasSuffix(r, ":plazo") {
							porPlazo = true
						}
					}
					if porPlazo {
						fmt.Println("  Hay capas que no terminaron en el plazo (5 min): suele ser un runner " +
							"lento o cargado. REINTENTA EL JOB antes de buscar nada en el código.")
					}
					fmt.Println("  Arregla el runner (rulepack y motores) o usa `--shadow` si aceptas registrar sin bloquear.")
					os.Exit(1)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&base, "base", "", "commit base")
	cmd.Flags().StringVar(&head, "head", "HEAD", "commit head")
	cmd.Flags().StringVar(&format, "format", "sarif", "formato de salida (sarif)")
	cmd.Flags().StringVar(&out, "out", "", "archivo de salida")
	cmd.Flags().StringVar(&repoDir, "repo", ".", "directorio dentro del repo")
	cmd.Flags().BoolVar(&shadow, "shadow", false, "modo sombra: registra pero nunca falla el job")
	_ = cmd.MarkFlagRequired("base")
	return cmd
}

func printSummary(res *pipeline.Result) {
	switch res.Verdict {
	case pipeline.Skipped:
		fmt.Println("codeguard: análisis omitido —", res.Reason)
		return
	case pipeline.Block:
		if res.Reason != "" {
			fmt.Println("codeguard: BLOQUEADO —", res.Reason)
		} else {
			fmt.Printf("codeguard: BLOQUEADO — %d problema(s) bloqueante(s), %d aviso(s)\n",
				res.BlockingFindings, res.AdvisoryFindings)
		}
	default:
		fmt.Printf("codeguard: OK — 0 bloqueantes, %d aviso(s)\n", res.AdvisoryFindings)
	}
	if len(res.Degraded) > 0 {
		fmt.Println("capas degradadas:", strings.Join(res.Degraded, ", "))
	}
	for _, f := range res.Findings {
		mark := "aviso "
		if f.Blocking {
			mark = "BLOQUEA"
		}
		// Mismo saneado que en el hook y por lo mismo: el mensaje sale del YAML
		// de la regla, que puede venir del rulepack vendoreado en el repo que se
		// está analizando. Aquí encima el texto acaba en el log del CI, que es
		// donde se mira cuando algo ya salió mal.
		fmt.Printf("  [%s] %s %s:%d  %s\n", mark, f.RuleKey, f.File, f.Line, mensajeDeHallazgo(f.Message))
	}
	_ = finding.Finding{}
}

func persist(repoRoot string, cfg *config.Config, res *pipeline.Result, filesChanged int) error {
	return persistRun(repoRoot, cfg, res, filesChanged, false, store.NewULID())
}

func persistWith(repoRoot string, cfg *config.Config, res *pipeline.Result, filesChanged int, bypassed bool) error {
	return persistRun(repoRoot, cfg, res, filesChanged, bypassed, store.NewULID())
}

// dirDatos devuelve el directorio donde vive la BD de runs, con un único
// invariante: SIEMPRE una ruta absoluta.
//
// Antes la comprobación era `dbDir == filepath.Join("", "codeguard")`, que vale
// "codeguard", así que atrapaba exactamente el caso LOCALAPPDATA="" y ninguno
// más. Medido: con "   " sale `   \codeguard` y con un valor relativo sale
// `datos\local\codeguard`; los dos son relativos y los dos se colaban. Y como
// el directorio de trabajo durante un commit ES el repo que se está analizando,
// la BD y su carpeta se creaban dentro del repo del usuario, que se encuentra
// archivos que no creó y que git le ofrece añadir al commit siguiente.
//
// (El de los espacios no llegaba a escribir, pero por accidente: Windows
// rechaza un componente hecho sólo de espacios, así que fallaba el MkdirAll y la
// telemetría se perdía en silencio. Escapar de la guarda y que te salve el
// sistema operativo no es lo mismo que estar protegido.)
//
// El arreglo es comprobar la propiedad que se quiere en vez de deducirla
// comparando contra una cadena construida — el mismo razonamiento indirecto que
// causó H007 (config) y N001 (ejecución de código). Se usa filepath.IsAbs, igual
// que config.RutaLLMLocal e instalacion.DirMotores, para no inventar una tercera
// forma de decir lo mismo.
//
// Lo que cambia respecto a esos dos es el DESENLACE, y a propósito: ellos
// devuelven "" y su llamador no hace nada, porque leer una config equivocada o
// ejecutar un binario equivocado es peor que no hacerlo. Aquí el destino son
// datos de telemetría, que nunca tumban el análisis (P4), y este sitio ya había
// elegido el temporal para el runner sin LOCALAPPDATA. Se conserva esa elección,
// que además es la que ya usan registry.go y store.go para lo mismo: perder el
// historial de runs es un fastidio, no un fallo de seguridad. Sólo se devuelve
// error si ni siquiera el temporal es absoluto, porque entonces no queda ningún
// sitio válido y escribir igualmente sería volver a meterse en el repo.
func dirDatos() (string, error) {
	if dir := filepath.Join(os.Getenv("LOCALAPPDATA"), "codeguard"); filepath.IsAbs(dir) {
		return dir, nil
	}
	dir := filepath.Join(os.TempDir(), "codeguard")
	if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("no hay ningún directorio absoluto donde guardar la "+
			"base de datos: LOCALAPPDATA=%q y el temporal del sistema es %q",
			os.Getenv("LOCALAPPDATA"), os.TempDir())
	}
	return dir, nil
}

// persistRun guarda el run con el ID dado — el hook pasa el mismo run id que
// viaja en el trailer Codeguard-Run-Id, para que BD y trailer coincidan.
func persistRun(repoRoot string, cfg *config.Config, res *pipeline.Result, filesChanged int, bypassed bool, runID string) error {
	dbDir, err := dirDatos()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dbDir, 0o755); err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(dbDir, "codeguard.db"))
	if err != nil {
		return err
	}
	defer st.Close()

	remote := gitRemote(repoRoot)
	repoID := store.RepoIDDe(repoRoot, remote)
	if err := st.UpsertRepo(repoID, remote, filepath.Base(repoRoot)); err != nil {
		return err
	}
	env := "local"
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		env = "ci"
	}
	return st.SaveRun(store.RunMeta{
		RunID:       runID,
		RepoID:      repoID,
		Branch:      gitBranch(repoRoot),
		RulepackVer: cfg.Rulepack,
		ConfigHash:  cfg.Hash,
		Environment: env,
		Bypassed:    bypassed,
	}, res, filesChanged)
}

func gitRemote(repoRoot string) string {
	out, err := gitCmd("-C", repoRoot, "remote", "get-url", "origin").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func gitBranch(repoRoot string) string {
	out, err := gitCmd("-C", repoRoot, "rev-parse", "--abbrev-ref", "HEAD").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}
