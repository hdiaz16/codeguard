package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"codeguard/internal/baseline"
	"codeguard/internal/config"
	"codeguard/internal/daemon"
	"codeguard/internal/gitdiff"
	"codeguard/internal/pipeline"
)

func baselineCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "baseline",
		Short: "Escanea el repo completo y suprime los hallazgos preexistentes (solo lo nuevo bloqueará)",
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
				return fmt.Errorf("el repo no está enrolado: falta %s", config.RelPath)
			}

			// Todos los archivos rastreados como si estuvieran modificados.
			rutas, err := gitdiff.Rastreados(repoRoot)
			if err != nil {
				return err
			}
			var files []gitdiff.ChangedFile
			for _, r := range rutas {
				files = append(files, gitdiff.ChangedFile{Path: r, Status: "M"})
			}
			files = conHuellas(repoRoot, files)
			fmt.Printf("escaneando %d archivos con la capa determinista completa…\n", len(files))

			cache, cerrarCache := abrirCache(repoRoot, cfg)
			defer cerrarCache()

			res, err := pipeline.Run(context.Background(), pipeline.Options{
				Config:   cfg,
				Diff:     &gitdiff.Diff{Files: files},
				Secrets:  nil, // los secretos no se baselinan jamás
				Engines:  daemon.Engines(cfg, false, cache),
				Rulepack: daemon.RulepackDir(repoRoot, cfg.Rulepack),
				Timeout:  10 * time.Minute,
			})
			if err != nil {
				return err
			}
			n, err := baseline.Write(repoRoot, res.Findings)
			if err != nil {
				return err
			}
			fmt.Printf("baseline escrita: %s (%d hallazgos suprimidos)\n", baseline.RelPath, n)
			if len(res.Degraded) > 0 {
				fmt.Println("aviso — capas que no corrieron y NO quedaron en la baseline:", strings.Join(res.Degraded, ", "))
			}
			fmt.Println("versiónala en el repo para que el CI y todo el equipo supriman lo mismo")
			return nil
		},
	}
}
