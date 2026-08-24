// codeguard — binario único (ADR-03): el mismo que corre en local y en CI.
// Fase 1: subcomando `ci` con el pipeline determinista y salida SARIF.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
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
	rulepackpkg "codeguard/internal/rulepack"
	"codeguard/internal/sarif"
	"codeguard/internal/shadow"
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
		enginesCmd(), configCmd(), forgetCmd(), syncCmd(), daemonStopCmd(), doctorCmd(),
		confiarCmd(), lockCmd())
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

			// Paridad ANTES de analizar (W6 Q4): si este runner no corresponde a
			// lo que el repo fijó en .codeguard.lock —otra versión de codeguard,
			// otro rulepack, otra baseline o política—, el análisis no tendría la
			// paridad que el CI promete. El CI lo rechaza aquí; en modo sombra no
			// (la sombra registra, jamás falla el job).
			if cfg != nil && !shadow {
				if err := rechazarSkewDeLock(repoRoot, cfg); err != nil {
					return err
				}
			}

			var diff *gitdiff.Diff
			if cfg != nil {
				if diff, err = gitdiff.Range(repoRoot, base, head); err != nil {
					return err
				}
			} else {
				diff = &gitdiff.Diff{}
			}

			// La resolución es la MISMA que la del daemon y el hook
			// (rulepack.Resolver): hasta 2026-08-23 este comando inlineaba su
			// propia copia con el orden INVERTIDO (repo primero), y con eso el
			// repo analizado decidía qué reglas se le aplicaban EN CI — el
			// ataque que la resolución canónica cierra desde su comentario.
			var rulepackID rulepackpkg.Identity
			if cfg != nil {
				var rulepackErr error
				rulepackID, rulepackErr = rulepackpkg.Resolver(repoRoot, cfg.Rulepack)
				if rulepackErr != nil && !errors.Is(rulepackErr, rulepackpkg.ErrNoEncontrado) {
					fmt.Println("aviso:", rulepackErr)
				}
			}

			inCI := os.Getenv("GITHUB_ACTIONS") == "true"
			res, err := pipeline.Run(context.Background(), pipeline.Options{
				Config:  cfg,
				Diff:    diff,
				Secrets: &glengine.Engine{Mode: "range", Base: base, Head: head},
				// Sin caché: el runner del CI es efímero y nunca acertaría.
				Engines:      daemon.Engines(cfg, inCI, nil),
				Rulepack:     rulepackID.Path,
				RulepackID:   rulepackID,
				Timeout:      5 * time.Minute,
				Suppressions: baseline.LoadOrWarn(repoRoot),
			})
			if err != nil {
				return err
			}

			// EL veredicto se deriva UNA vez (outcome.go); de aquí en adelante
			// este comando solo LEE. Antes había dos impresores que competían
			// —printSummary y el bloque de garantía— y el orden en que quedaron
			// hacía que el log dijera «OK — 0 bloqueantes» y tres líneas después
			// «NO PUEDO GARANTIZAR ESTE COMMIT» con exit 1 (el agujero que la
			// cabecera de garantia.go documentaba). Con un impresor único no hay
			// orden que mantener.
			outcome := pipeline.Finalizar(res, "", nil)
			printSummary(os.Stdout, outcome, res.Findings)
			if res.Rulepack.Digest != "" {
				// La línea de PARIDAD: el mismo pin con el mismo digest aquí y en
				// el hook es la prueba de que local y CI midieron con las mismas
				// reglas — el caso medido (misma versión, 130 vs 161 reglas) es
				// exactamente lo que esta línea deja ver.
				fmt.Printf("rulepack: %s digest %.12s (%s)\n", res.Rulepack.Version, res.Rulepack.Digest, res.Rulepack.Source)
			}

			if format == "sarif" && out != "" {
				if err := sarif.Write(out, version, res.Findings); err != nil {
					return fmt.Errorf("escribiendo SARIF: %w", err)
				}
				fmt.Printf("SARIF: %s (%d resultados)\n", out, len(res.Findings))
			}

			if cfg != nil {
				if err := persist(repoRoot, cfg, res, outcome, len(diff.Files)); err != nil {
					// La telemetría nunca tumba el análisis (P4).
					fmt.Fprintln(os.Stderr, "aviso: no se pudo persistir el run:", err)
				}
			}

			// Modo sombra (fase 1): registra todo, nunca falla el job. La VERDAD
			// ya quedó impresa arriba también en sombra; lo único que la sombra
			// desactiva es el código de salida.
			if !shadow {
				if outcome.Estado == pipeline.Bloqueado {
					os.Exit(1)
				}
				// Y una capa que NO MIRÓ tampoco es un job verde. Medido: el
				// mismo `db.Query("… " + id)` sale con exit 1 si el rulepack
				// está y con exit 0 si falta. El porqué de qué entra y qué no
				// está en pipeline.SinGarantia, ya resuelto en GarantiaRota.
				if len(outcome.GarantiaRota) > 0 {
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

// printSummary es EL impresor del veredicto de CI, y lee AnalysisOutcome —
// nunca re-deriva (regla del consejo, turnos 61-68). La primera línea es el
// veredicto de verdad: un análisis con la garantía rota ya no puede abrir con
// «OK», que era la mentira medida en la cabecera de garantia.go.
//
// El invariante de render (turno 67): si la garantía está rota, se nombra
// SIEMPRE — también cuando el estado es Bloqueado. Sin eso, el dev arregla el
// bloqueante, commitea de nuevo, y la compuerta que no miró le llega como
// sorpresa en el segundo intento.
func printSummary(w io.Writer, o pipeline.AnalysisOutcome, findings []finding.Finding) {
	switch o.Estado {
	case pipeline.Omitido:
		fmt.Fprintln(w, "codeguard: análisis omitido —", o.Razon)
		return
	case pipeline.Bloqueado:
		if o.Razon != "" {
			fmt.Fprintln(w, "codeguard: BLOQUEADO —", o.Razon)
		} else {
			fmt.Fprintf(w, "codeguard: BLOQUEADO — %d problema(s) bloqueante(s), %d aviso(s)\n",
				o.Bloqueantes, o.Avisos)
		}
	case pipeline.Degradado:
		fmt.Fprintf(w, "codeguard: SIN GARANTÍA — el análisis quedó incompleto "+
			"(%d bloqueante(s), %d aviso(s) en lo que SÍ se miró)\n", o.Bloqueantes, o.Avisos)
	case pipeline.Fallido:
		fmt.Fprintf(w, "codeguard: el análisis FALLÓ (%s) — %s\n", o.FalloEn, o.Fallo)
		return
	default: // Limpio y ConAvisos: la única rama donde «OK» es verdad.
		fmt.Fprintf(w, "codeguard: OK — 0 bloqueantes, %d aviso(s)\n", o.Avisos)
	}
	if len(o.GarantiaRota) > 0 {
		fmt.Fprintln(w, "codeguard: NO PUEDO GARANTIZAR ESTE COMMIT —",
			strings.Join(o.GarantiaRota, ", "))
		fmt.Fprintln(w, "  Estas capas no llegaron a mirar, así que un problema suyo pasaría sin verse.")
		// Un plazo agotado manda a un sitio distinto que un rulepack ausente, y
		// decirlo ahorra una tarde: el primero suele ser contención del runner y
		// se arregla reintentando el job; el segundo es configuración y no se
		// arregla solo. Sin esta distinción, quien lea el log se pone a buscar
		// un bug en el código donde sólo hubo una máquina ocupada.
		for _, r := range o.GarantiaRota {
			if strings.HasSuffix(r, ":plazo") {
				fmt.Fprintln(w, "  Hay capas que no terminaron en el plazo (5 min): suele ser un runner "+
					"lento o cargado. REINTENTA EL JOB antes de buscar nada en el código.")
				break
			}
		}
	}
	if len(o.Degradadas) > 0 {
		fmt.Fprintln(w, "capas degradadas:", strings.Join(o.Degradadas, ", "))
	}
	for _, f := range findings {
		mark := "aviso "
		if f.Blocking {
			mark = "BLOQUEA"
		}
		// Mismo saneado que en el hook y por lo mismo: el mensaje sale del YAML
		// de la regla, que puede venir del rulepack vendoreado en el repo que se
		// está analizando. Aquí encima el texto acaba en el log del CI, que es
		// donde se mira cuando algo ya salió mal.
		fmt.Fprintf(w, "  [%s] %s %s:%d  %s\n", mark, f.RuleKey, f.File, f.Line, mensajeDeHallazgo(f.Message))
	}
}

// El outcome viaja POR PARÁMETRO hasta SaveRun y no se re-deriva aquí, a
// propósito: por la ruta del daemon el veredicto tipado viene del cable
// (p.ej. failed:pipeline) y el Result reconstruido solo sabe decir "skipped"
// legacy — re-derivar en este punto persistiría la mentira que el cable
// acababa de corregir. Quien no tenga un outcome mejor, deriva con
// pipeline.Finalizar en SU punto y lo pasa.
func persist(repoRoot string, cfg *config.Config, res *pipeline.Result, outcome pipeline.AnalysisOutcome, filesChanged int) error {
	return persistRun(repoRoot, cfg, res, outcome, filesChanged, false, store.NewULID())
}

func persistWith(repoRoot string, cfg *config.Config, res *pipeline.Result, outcome pipeline.AnalysisOutcome, filesChanged int, bypassed bool) error {
	return persistRun(repoRoot, cfg, res, outcome, filesChanged, bypassed, store.NewULID())
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
func persistRun(repoRoot string, cfg *config.Config, res *pipeline.Result, outcome pipeline.AnalysisOutcome, filesChanged int, bypassed bool, runID string) error {
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
		RunID:              runID,
		RepoID:             repoID,
		Branch:             gitBranch(repoRoot),
		RulepackVer:        cfg.Rulepack,
		ConfigHash:         cfg.Hash,
		Environment:        env,
		Bypassed:           bypassed,
		RiskFormulaVersion: shadow.RiskFormulaVersion,
		RiskConfigHash:     shadow.RiskConfigHash(cfg),
	}, res, outcome, filesChanged)
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
