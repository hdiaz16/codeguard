package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"codeguard/internal/gitdiff"
	"codeguard/internal/ipc"
	"codeguard/internal/store"
)

// codeguard doctor ([31] del plan, turnos 86-93): OBSERVA las postcondiciones
// reales del enrolamiento y de la máquina — no repara nada (doctor observa;
// init/install reconcilian). Es la misma lista de verdades que `status`
// (chequeosDelRepo) más lo que status no miraba: el daemon por el pipe y el
// esquema de la BD sin migrarla.
//
// --json existe para el instalador y para flota, y nace VERSIONADO
// ("schema": 1) con estados cerrados — la lección de WireOutcome: un formato
// sin versión es un formato que un día se malinterpreta en silencio.
// --global omite los chequeos de repo: el instalador no corre dentro de uno.

type chequeoDoctor struct {
	Nombre  string `json:"nombre"`
	OK      bool   `json:"ok"`
	Detalle string `json:"detalle"`
}

type informeDoctor struct {
	Schema int `json:"schema"`
	// Overall es un estado CERRADO: healthy (todo ok), degraded (algo falta y
	// tiene remedio local), failed (algo está roto de verdad: config ilegible
	// o esquema de BD divergente). Un consumidor que reciba un valor fuera de
	// estos tres debe tratarlo como failed, jamás como sano.
	Overall string          `json:"overall"`
	Checks  []chequeoDoctor `json:"checks"`
}

const esquemaDoctor = 1

func doctorCmd() *cobra.Command {
	var enJSON, global bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Verifica las postcondiciones reales: repo, daemon y base de datos (solo observa, no repara)",
		RunE: func(cmd *cobra.Command, args []string) error {
			inf := diagnosticar(global)
			if enJSON {
				data, err := json.MarshalIndent(inf, "", "  ")
				if err != nil {
					return err
				}
				fmt.Println(string(data))
			} else {
				for _, c := range inf.Checks {
					mark := "✓"
					if !c.OK {
						mark = "✗"
					}
					fmt.Printf("   %s %-10s %s\n", mark, c.Nombre, c.Detalle)
				}
				fmt.Println("\nestado:", inf.Overall)
			}
			// El código de salida ES el veredicto para quien no parsea JSON:
			// el instalador y los scripts preguntan con $?.
			if inf.Overall == "failed" {
				os.Exit(2)
			}
			if inf.Overall == "degraded" {
				os.Exit(1)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&enJSON, "json", false, "salida JSON versionada (schema 1)")
	cmd.Flags().BoolVar(&global, "global", false, "solo la máquina (daemon, BD): para el instalador, que no corre dentro de un repo")
	return cmd
}

// chequeosDeCoberturaHistorica lee el historial de salud de capas del repo y
// emite un chequeo por cada capa con racha ≥ 2 (el umbral mínimo, «recurrente»).
// Umbral DOBLE (síntesis Q3): recurrente = 2 corridas seguidas; persistente = 5
// seguidas O ≥2 durante >24 h. Siempre muestra el CONTADOR y la ANTIGÜEDAD, no
// solo un color: un número y una fecha se actúan; un rojo se aprende a ignorar.
// Una racha de 1 es un tropiezo, no un patrón: no se reporta.
func chequeosDeCoberturaHistorica(root string) []chequeoDoctor {
	repoID := store.RepoIDDe(root, gitRemote(root))
	salud, err := store.SaludDeCapasSoloLectura(store.DefaultPath(), repoID)
	if err != nil || len(salud) == 0 {
		return nil // sin historial (o BD ilegible, que el chequeo bd ya denuncia): nada que decir
	}
	var out []chequeoDoctor
	for _, sc := range salud {
		if sc.RachaFallos < 2 {
			continue
		}
		motivo := sc.MotivoCodigo
		if motivo == "" {
			motivo = "sin motivo registrado"
		}
		out = append(out, chequeoDoctor{
			Nombre: "capa:" + sc.Motor,
			OK:     false,
			Detalle: fmt.Sprintf("%s — %d corridas seguidas sin cubrir del todo (%s)%s",
				claseDeRacha(sc), sc.RachaFallos, motivo, antiguedadDeRacha(sc)),
		})
	}
	return out
}

// claseDeRacha aplica el umbral doble.
func claseDeRacha(sc store.SaludCapa) string {
	viejaYRepetida := sc.RachaFallos >= 2 && !sc.PrimerFallo.IsZero() && time.Since(sc.PrimerFallo) > 24*time.Hour
	if sc.RachaFallos >= 5 || viejaYRepetida {
		return "persistente"
	}
	return "recurrente"
}

// antiguedadDeRacha dice desde cuándo dura la racha, en palabras. Vacío si no
// hay fecha de inicio (una racha sin inicio sería un dato incoherente que no se
// inventa).
func antiguedadDeRacha(sc store.SaludCapa) string {
	if sc.PrimerFallo.IsZero() {
		return ""
	}
	d := time.Since(sc.PrimerFallo)
	switch {
	case d < time.Hour:
		return ", desde hace menos de 1 h"
	case d < 24*time.Hour:
		return fmt.Sprintf(", desde hace %d h", int(d.Hours()))
	default:
		return fmt.Sprintf(", desde hace %d día(s)", int(d.Hours())/24)
	}
}

func diagnosticar(global bool) informeDoctor {
	inf := informeDoctor{Schema: esquemaDoctor}
	fallo := false // algo roto de verdad (failed); lo demás degrada

	if !global {
		if root, err := gitdiff.RepoRoot("."); err != nil {
			inf.Checks = append(inf.Checks, chequeoDoctor{"repo", false, "no estás dentro de un repo git (usa --global para la máquina)"})
			fallo = true
		} else {
			orden, checks := chequeosDelRepo(root)
			for _, k := range orden {
				c, existe := checks[k]
				if !existe {
					continue
				}
				inf.Checks = append(inf.Checks, chequeoDoctor{k, c.ok, c.detalle})
				// La config ilegible es rotura, no carencia: el análisis corre
				// con la config por defecto y los motores del repo pueden no
				// correr — «no se miró» de manual.
				if k == "config" && !c.ok && strings.Contains(c.detalle, "ilegible") {
					fallo = true
				}
			}
			// Capas que llevan corridas seguidas sin cubrir (W6 Q3/Q4): el
			// historial de salud convierte «semgrep falló hoy» en «semgrep lleva
			// una semana sin mirar Python», que es lo accionable. Observa, no
			// repara: lee SIN migrar.
			inf.Checks = append(inf.Checks, chequeosDeCoberturaHistorica(root)...)
		}
	}

	// El daemon, por el pipe y con el ping REAL (rama propia desde 581e199):
	// responde su versión, así que aquí se compara contra la del binario.
	switch resp, err := ipc.Call(&ipc.Request{Command: "ping", DeadlineMs: 2000}, 2*time.Second); {
	case err == nil:
		detalle := strings.TrimSpace(resp.Reason)
		if detalle == "" {
			detalle = "responde (daemon anterior al ping versionado)"
		}
		propia := "codeguard-daemon " + version
		if resp.Reason != "" && resp.Reason != propia {
			inf.Checks = append(inf.Checks, chequeoDoctor{"daemon", false,
				detalle + " ≠ binario " + version + " → reinicia el daemon para alinear versiones"})
		} else {
			inf.Checks = append(inf.Checks, chequeoDoctor{"daemon", true, detalle})
		}
	case errors.Is(err, fs.ErrNotExist):
		inf.Checks = append(inf.Checks, chequeoDoctor{"daemon", false,
			"no está corriendo → arráncalo (codeguard-daemon) o cierra y abre sesión; el análisis local funciona igual"})
	default:
		inf.Checks = append(inf.Checks, chequeoDoctor{"daemon", false, "no se pudo confirmar su estado: " + err.Error()})
	}

	// La BD, SIN migrarla: doctor observa. Una divergencia de esquema es
	// rotura (failed) — nada debe escribir encima.
	if detalle, err := store.VerificarEsquema(store.DefaultPath()); err != nil {
		inf.Checks = append(inf.Checks, chequeoDoctor{"bd", false, err.Error()})
		fallo = true
	} else {
		inf.Checks = append(inf.Checks, chequeoDoctor{"bd", true, detalle})
	}

	inf.Overall = "healthy"
	for _, c := range inf.Checks {
		if !c.OK {
			inf.Overall = "degraded"
			break
		}
	}
	if fallo {
		inf.Overall = "failed"
	}
	return inf
}
