package main

import (
	"context"
	"fmt"
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
			// Lo que se acepta se ENSEÑA antes de aceptarlo.
			//
			// Aceptar una baseline es decir "todo esto deja de bloquear para
			// siempre", y hasta aquí el comando lo hacía con un número al final
			// —"198 hallazgos suprimidos"— sin decir de qué. Lo señaló el agente
			// que trabaja en bds.portal: entre los 195 que iba a aceptar había
			// una llave de API escribiéndose en los registros, que se arregla
			// borrando una línea. Aceptarla habría sido enterrarla, y en un
			// minuto de trabajo se resolvía. Un resumen que hay que ir a buscar
			// a otro comando es un resumen que nadie mira.
			mostrarLoQueSeAcepta(res.Findings)

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

// mostrarLoQueSeAcepta desglosa la deuda por pilar y saca a la luz los
// hallazgos de seguridad uno por uno.
//
// El desglose por pilar es contexto; la lista de seguridad es el punto. Un
// hallazgo de seguridad que entra a la baseline deja de bloquear para siempre,
// y algunos se arreglan en un minuto —una línea que sobra, una llamada que no
// debía estar—. La diferencia entre "deuda aceptada a conciencia" y "problema
// enterrado" es exactamente si alguien los vio antes de firmar.
func mostrarLoQueSeAcepta(fs []finding.Finding) {
	if len(fs) == 0 {
		return
	}
	porPilar := map[finding.Pillar]int{}
	var seguridad []finding.Finding
	for _, f := range fs {
		porPilar[f.Pillar]++
		if f.Pillar == finding.Security {
			seguridad = append(seguridad, f)
		}
	}
	fmt.Println("\nvas a aceptar como deuda:")
	for _, p := range []finding.Pillar{finding.Security, finding.Data, finding.Quality} {
		if porPilar[p] > 0 {
			fmt.Printf("  %-10s %d\n", string(p), porPilar[p])
		}
	}

	if len(seguridad) == 0 {
		return
	}
	sort.Slice(seguridad, func(a, b int) bool {
		if seguridad[a].File != seguridad[b].File {
			return seguridad[a].File < seguridad[b].File
		}
		return seguridad[a].Line < seguridad[b].Line
	})
	fmt.Printf("\nlos %d de SEGURIDAD, uno por uno — revísalos antes de enterrarlos:\n", len(seguridad))
	const tope = 20
	for i, f := range seguridad {
		if i == tope {
			fmt.Printf("  … y %d más (el informe completo: codeguard report --avisos)\n", len(seguridad)-tope)
			break
		}
		fmt.Printf("  %s:%d  [%s] %s\n", f.File, f.Line, f.RuleKey, f.Message)
	}
	fmt.Println("\nSi alguno se arregla en un minuto, arréglalo AHORA y vuelve a correr esto:")
	fmt.Println("lo que entre aquí deja de bloquear para siempre, en tu máquina y en el CI.")
}
