package main

import (
	"bufio"
	"context"
	"errors"
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
	"codeguard/internal/rulepack"
)

func baselineCmd() *cobra.Command {
	var si, soloRenovar bool
	cmd := &cobra.Command{
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

			cache, cerrarCache := abrirCache(repoRoot, repoRoot, cfg)
			defer cerrarCache()

			rulepackID, rulepackErr := rulepack.Resolver(repoRoot, cfg.Rulepack)
			if rulepackErr != nil && !errors.Is(rulepackErr, rulepack.ErrNoEncontrado) {
				fmt.Println("aviso:", rulepackErr)
			}
			res, err := pipeline.Run(context.Background(), pipeline.Options{
				Config:     cfg,
				Diff:       &gitdiff.Diff{Files: files},
				Secrets:    nil, // los secretos no se baselinan jamás
				Engines:    daemon.Engines(cfg, false, cache),
				Rulepack:   rulepackID.Path,
				RulepackID: rulepackID,
				Timeout:    10 * time.Minute,
			})
			if err != nil {
				return err
			}
			if soloRenovar {
				// Migración v1→v2 SIN re-admitir nada: solo reescribe entradas
				// existentes cuya correspondencia es inequívoca. Un hallazgo
				// nuevo jamás entra por aquí — sigue bloqueando.
				r, err := baseline.Renovar(repoRoot, res.Findings)
				if err != nil {
					return err
				}
				fmt.Printf("baseline renovada: %d migradas a v2, %d ya estaban en v2\n", r.Migradas, r.YaMigradas)
				for _, l := range r.Desaparecidas {
					fmt.Printf("  retirada (la deuda ya no existe o no se pudo re-casar): %s\n", l)
				}
				for _, l := range r.Conservadas {
					fmt.Printf("  CONSERVADA como v1 — varias ocurrencias comparten esta huella (el caso #9):\n    %s\n"+
						"    decide tú: distingue las ocurrencias en el código, o déjala (suprime hasta el fin de la ventana dual)\n", l)
				}
				for _, l := range r.Desconocidas {
					fmt.Printf("  formato desconocido, conservada sin tocar: %s\n", l)
				}
				return nil
			}

			// Lo que se acepta se ENSEÑA antes de aceptarlo.
			//
			// Aceptar una baseline es decir "todo esto deja de bloquear para
			// siempre", y hasta aquí el comando lo hacía con un número al final
			// —"198 hallazgos suprimidos"— sin decir de qué. Lo señaló el agente
			// que trabaja en portal-cliente: entre los 195 que iba a aceptar había
			// una llave de API escribiéndose en los registros, que se arregla
			// borrando una línea. Aceptarla habría sido enterrarla, y en un
			// minuto de trabajo se resolvía. Un resumen que hay que ir a buscar
			// a otro comando es un resumen que nadie mira.
			mostrarLoQueSeAcepta(res.Findings)

			if !si && len(res.Findings) > 0 {
				fmt.Print("\n¿Escribir baseline y suprimir estos hallazgos preexistentes? [S/n]: ")
				// Fail-closed medido el 2026-08-23: la versión anterior trataba
				// el ERROR de lectura como un sí — un `echo n | codeguard
				// baseline` (pipe, sin terminal) escribió 161 supresiones. Sin
				// respuesta legible no hay consentimiento: solo Enter o un sí
				// explícito escriben; para el uso sin terminal existe --si.
				linea, err := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
				resp := strings.TrimSpace(strings.ToLower(linea))
				if err != nil && resp == "" {
					return fmt.Errorf("baseline no escrita: no se pudo leer la respuesta (¿sin terminal?); usa --si para aceptar sin preguntar")
				}
				if resp != "" && resp != "s" && resp != "si" && resp != "sí" {
					return fmt.Errorf("operación cancelada por el usuario: baseline no escrita")
				}
			}

			n, ambiguos, err := baseline.Write(repoRoot, res.Findings)
			if err != nil {
				return err
			}
			fmt.Printf("baseline escrita: %s (%d hallazgos suprimidos)\n", baseline.RelPath, n)
			if ambiguos > 0 {
				fmt.Printf("aviso — %d hallazgo(s) AMBIGUOS quedaron FUERA: comparten huella con otra ocurrencia\n"+
					"  (mismo texto y mismo contexto) y aceptar uno suprimiría al otro en silencio.\n"+
					"  Seguirán a la vista; distingue las ocurrencias en el código si quieres aceptarlas.\n", ambiguos)
			}
			if rotas := pipeline.Finalizar(res, "", nil).GarantiaRota; len(rotas) > 0 {
				fmt.Println("aviso — capas que no corrieron y NO quedaron en la baseline:", strings.Join(rotas, ", "))
			}
			fmt.Println("versiónala en el repo para que el CI y todo el equipo supriman lo mismo")
			return nil
		},
	}
	cmd.Flags().BoolVarP(&si, "si", "y", false, "aceptar y escribir la baseline sin confirmación interactiva")
	cmd.Flags().BoolVar(&soloRenovar, "solo-renovar", false, "migrar las entradas v1 a huellas v2 sin aceptar nada nuevo (lo ambiguo queda para decisión humana)")
	return cmd
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

	// Los BLOQUEANTES se nombran uno a uno, cualquiera que sea su pilar.
	//
	// El conteo por pilar tapaba lo que importa: un validador midió un repo
	// donde `init --force` aceptaba 17 hallazgos de datos, y de esos 17 había
	// CUATRO que existen para frenar daño —ban-drop-column, ban-drop-table,
	// adding-required-field, require-concurrent-index-creation— mezclados con
	// doce de higiene repetida (lock_timeout, statement_timeout…). La línea
	// «data 17» los presentaba igual. La palabra "deuda" tapaba un DROP COLUMN
	// exactamente igual que un timeout que falta, y a partir de ese momento
	// ninguno de los cuatro vuelve a frenar un commit.
	var bloqueantes []finding.Finding
	for _, f := range fs {
		if f.Blocking {
			bloqueantes = append(bloqueantes, f)
		}
	}
	if len(bloqueantes) > 0 {
		sort.Slice(bloqueantes, func(a, b int) bool {
			if bloqueantes[a].File != bloqueantes[b].File {
				return bloqueantes[a].File < bloqueantes[b].File
			}
			return bloqueantes[a].Line < bloqueantes[b].Line
		})
		fmt.Printf("\n%d de ellos son BLOQUEANTES y no volverán a frenar un commit:\n", len(bloqueantes))
		const tope = 15
		for i, f := range bloqueantes {
			if i == tope {
				fmt.Printf("  … y %d más (el informe completo: codeguard report --avisos)\n", len(bloqueantes)-tope)
				break
			}
			fmt.Printf("  [%s] %s:%d\n", f.RuleKey, f.File, f.Line)
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
		// El mismo texto ajeno que en el hook: mensaje de regla, rulepack que
		// puede ser el vendoreado en el repo.
		fmt.Printf("  %s:%d  [%s] %s\n", f.File, f.Line, f.RuleKey, mensajeDeHallazgo(f.Message))
	}
	fmt.Println("\nSi alguno se arregla en un minuto, arréglalo AHORA y vuelve a correr esto:")
	fmt.Println("lo que entre aquí deja de bloquear para siempre, en tu máquina y en el CI.")
}
