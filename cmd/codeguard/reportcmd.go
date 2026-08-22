package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"codeguard/internal/baseline"
	"codeguard/internal/config"
	"codeguard/internal/daemon"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
	"codeguard/internal/pipeline"
)

const reportFile = ".codeguard/HALLAZGOS.md"

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
			previos, err := leerFingerprintsPrevios(filepath.Join(repoRoot, filepath.FromSlash(reportFile)))
			if err != nil {
				// El informe anterior no se pudo leer entero: sin sus
				// fingerprints no se puede decir qué se resolvió, así que esta
				// corrida no declara RESUELTO nada (fail-closed) y lo avisa.
				// No se aborta el comando: el informe se reescribe entero más
				// abajo, así que la próxima corrida ya parte de un archivo sano.
				fmt.Printf("  ⚠️  no se pudo leer el informe anterior (%v): esta corrida no marcará resueltos\n", err)
			}
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
			// Una baseline ilegible NO se degrada aquí: el informe la aplica él
			// mismo para separar bloqueantes de deuda, y con una baseline
			// parcial presentaría deuda aceptada como bloqueante — el informe
			// mentiría en las dos direcciones a la vez. Se falla y se dice.
			supr, err := baseline.Load(repoRoot)
			if err != nil {
				return err
			}

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
			// «RESUELTO» SÓLO SE PUEDE DECIR SI ALGUIEN MIRÓ.
			//
			// Un hallazgo se declaraba resuelto por AUSENCIA: estaba en el
			// informe anterior y no está en éste. Pero una capa degradada
			// produce exactamente esa ausencia sin que nadie haya tocado el
			// código, así que el informe marcaba con casilla `[x]` bugs que
			// siguen ahí enteros.
			//
			// MEDIDO en un repo de juguete, tres corridas: con staticcheck
			// instalado salían U1000 y SA4006 como pendientes; renombrando su
			// binario, las DOS aparecían bajo «✅ Resueltos desde el informe
			// anterior», en el mismo documento que un párrafo más arriba admite
			// que esa capa no corrió. Y de regalo, el conteo de deuda
			// baselineada caía a 0 por el mismo camino.
			//
			// Lo lee un humano por la mañana, pero sobre todo lo lee un AGENTE
			// que decide si queda trabajo: darle por cerrado lo que nadie
			// revisó es la peor mentira que puede contar este archivo.
			//
			// El daño medido es acotado —al restaurar la capa vuelven a
			// aparecer, porque cada corrida reescanea de verdad y no arrastra
			// un registro acumulativo— pero dura todo el ciclo en que la capa
			// está rota, y es indefinido si nadie vuelve a correr el informe.
			//
			// Se calla ENTERA la sección en vez de filtrarla capa por capa, y
			// es deliberado: los fingerprints previos no dicen de qué motor
			// salieron, así que filtrar exigiría adivinarlo por el texto. Entre
			// adivinar y callar, se calla — y se dice por qué, que es lo que
			// convierte un hueco en información.
			resueltos, noSePuedeDecirResuelto := calcularResueltos(previos, actuales, res.Degraded)

			md := construirInforme(cfg, res, bloq, avisos, resueltos, noSePuedeDecirResuelto, deuda, incluirAvisos, incluirDeuda, discrepancias)
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
			// Lo que no se revisó se dice ANTES del veredicto, no en una línea
			// suelta después: leído en ese orden, "no quedan bloqueantes" ya no
			// se puede confundir con "está limpio".
			capas := explicarCapas(res.Degraded)
			for _, c := range capas {
				fmt.Println("\n  ⚠️  " + textoPlano(c))
			}
			switch {
			case len(bloq) == 0 && len(capas) == 0:
				fmt.Println("\n  ✅ COMPLETADO: no quedan bloqueantes")
			case len(bloq) == 0:
				fmt.Println("\n  ⚠️  PARCIAL: sin bloqueantes en lo que sí se revisó, pero el")
				fmt.Println("      análisis está incompleto. Esto NO es un visto bueno.")
			default:
				fmt.Println("\n  entrégale el archivo a tu agente: \"resuelve .codeguard/HALLAZGOS.md\"")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&incluirAvisos, "avisos", false, "incluir también los hallazgos no bloqueantes")
	cmd.Flags().BoolVar(&incluirDeuda, "deuda", false, "detallar la deuda aceptada por la baseline (hallada pero suprimida)")
	return cmd
}

