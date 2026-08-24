package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"codeguard/internal/gitdiff"
	"codeguard/internal/store"
)

func statsCmd() *cobra.Command {
	var allRepos bool
	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Precisión por regla según el feedback del equipo (la palanca de calibración)",
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := store.Open(store.DefaultPath())
			if err != nil {
				return err
			}
			defer st.Close()

			repoID := ""
			if !allRepos {
				root, err := gitdiff.RepoRoot(".")
				if err != nil {
					// repoID vacío significa GLOBAL (todos los repos): seguir
					// aquí mostraría las estadísticas de todos disfrazadas de
					// las del repo actual, y el usuario no pidió --all. Un error
					// ambiguo no se convierte en «todo bien». (No se distingue
					// "no es repo" de "git roto" por el tipo de error: gitdiff.run
					// envuelve con %v y rompe la cadena de errors.As; el mensaje
					// cubre ambos y muestra la causa real.)
					return fmt.Errorf("no se pudo determinar el repositorio actual "+
						"(¿estás dentro de un repo git?); usa --all para las estadísticas globales: %v", err)
				}
				// Con el respaldo de RepoIDDe: sin él, un repo sin remote
				// buscaba bajo la cadena vacía y `stats` decía "sin hallazgos
				// registrados todavía" con la base llena.
				repoID = store.RepoIDDe(root, gitRemote(root))
			}

			// ── El avance hacia el umbral del §17 se dice primero: la poda
			// sin volumen es adivinar con ceremonia. ──
			prog, err := st.ProgresoCalibracion(repoID)
			if err != nil {
				return err
			}
			if prog.Hallazgos == 0 {
				fmt.Println("sin hallazgos registrados todavía — la sombra los acumula con cada commit")
				return nil
			}
			dias := 0
			if d, err1 := time.Parse(time.RFC3339, prog.Desde); err1 == nil {
				if h, err2 := time.Parse(time.RFC3339, prog.Hasta); err2 == nil {
					dias = int(h.Sub(d).Hours()/24) + 1
				}
			}
			fmt.Printf("calibración §17: %d hallazgos registrados en %d día(s), %d voto(s)\n",
				prog.Hallazgos, dias, prog.Votos)
			switch {
			case dias < 14 || prog.Hallazgos < 500:
				fmt.Printf("  umbral para la primera poda: 14 días y 500 hallazgos — aún no; sigue commiteando\n\n")
			case prog.Votos < 50:
				fmt.Printf("  hay volumen, faltan VOTOS: los botones útil/falso positivo del panel son la palanca\n\n")
			default:
				fmt.Printf("  umbral alcanzado: esta tabla ya soporta decisiones de poda\n\n")
			}

			// ── Emisiones por regla, con la precisión de los votos que tenga ──
			emisiones, err := st.Emisiones(repoID)
			if err != nil {
				return err
			}
			stats, err := st.RuleStats(repoID)
			if err != nil {
				return err
			}
			votos := map[string]store.RuleStat{}
			for _, s := range stats {
				votos[s.Engine+"/"+s.RuleKey] = s
			}
			// El estado sale de DemotedRules —el MISMO criterio que aplica el
			// daemon— y no de una copia local. La copia que había aquí llevaba
			// los umbrales cableados a mano (drift garantizado el día que
			// cambiaran) y le faltaba la exención de gitleaks del pipeline
			// (pipeline.go: los secretos jamás se degradan): stats podía
			// anunciar «DEGRADADA a aviso» de una regla que iba a seguir
			// bloqueando cada commit.
			degradadas, err := st.DemotedRules(repoID, store.MinVotosDemocion, store.MaxTasaFPDemocion)
			if err != nil {
				return err
			}

			fmt.Printf("%-12s %-32s %9s %6s %4s %9s  %s\n", "MOTOR", "REGLA", "EMITIDOS", "ÚTIL", "FP", "PRECISIÓN", "ESTADO")
			for _, e := range emisiones {
				clave := e.Engine + "/" + e.RuleKey
				v := votos[clave]
				total := v.Useful + v.FalsePos
				precision, estado := "—", "sin votos"
				if total > 0 {
					p := float64(v.Useful) / float64(total) * 100
					precision = fmt.Sprintf("%.0f%%", p)
					switch {
					case degradadas[clave] && e.Engine == "gitleaks":
						estado = "votos de sobra para degradarla, y NO se degrada: los secretos siempre bloquean"
					case degradadas[clave]:
						estado = "DEGRADADA a aviso (auto-calibración)"
					case p < 80:
						estado = "vigilar (bajo el estándar de 80%)"
					default:
						estado = ""
					}
				}
				fmt.Printf("%-12s %-32s %9d %6d %4d %9s  %s\n",
					e.Engine, e.RuleKey, e.Total, v.Useful, v.FalsePos, precision, estado)
			}
			fmt.Printf("\nregla del sistema: ≥%d votos y >%.0f%% de falsos positivos en el repo → deja de bloquear sola (gitleaks exento: un secreto siempre bloquea)\n",
				store.MinVotosDemocion, store.MaxTasaFPDemocion*100)
			return nil
		},
	}
	cmd.Flags().BoolVar(&allRepos, "all", false, "agregar el feedback de todos los repos")
	return cmd
}
