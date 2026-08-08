package main

import (
	"fmt"

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
				if root, err := gitdiff.RepoRoot("."); err == nil {
					repoID = store.CanonicalRepoID(gitRemote(root))
				}
			}
			stats, err := st.RuleStats(repoID)
			if err != nil {
				return err
			}
			if len(stats) == 0 {
				fmt.Println("sin feedback todavía — los botones útil/falso positivo del panel alimentan esta tabla")
				return nil
			}
			fmt.Printf("%-14s %-32s %6s %6s %9s  %s\n", "MOTOR", "REGLA", "ÚTIL", "FP", "PRECISIÓN", "ESTADO")
			for _, s := range stats {
				total := s.Useful + s.FalsePos
				precision := float64(s.Useful) / float64(total) * 100
				estado := ""
				switch {
				case total >= 5 && float64(s.FalsePos)/float64(total) > 0.20:
					estado = "DEGRADADA a aviso (auto-calibración)"
				case precision < 80:
					estado = "vigilar (bajo el estándar de 80%)"
				}
				fmt.Printf("%-14s %-32s %6d %6d %8.0f%%  %s\n", s.Engine, s.RuleKey, s.Useful, s.FalsePos, precision, estado)
			}
			fmt.Println("\nregla del sistema: ≥5 votos y >20% de falsos positivos en el repo → deja de bloquear sola")
			return nil
		},
	}
	cmd.Flags().BoolVar(&allRepos, "all", false, "agregar el feedback de todos los repos")
	return cmd
}
