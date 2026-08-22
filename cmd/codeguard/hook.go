package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"codeguard/internal/config"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
	"codeguard/internal/pipeline"
)

// hookDeadline es un TOPE, no una espera: un commit cuyos motores terminan en
// 3 segundos tarda 3 segundos, valga el tope 5 o 30. Sólo acota el peor caso.
//
// Eran 5 s, y semgrep —un CLI de Python que paga intérprete + imports + parseo
// de 118 reglas en CADA invocación— tarda 4-8 s incluso caliente y con dos
// archivos (medido). Con 5 s cada commit era un volado: a veces entraba, a
// veces el hook decía "capas no revisadas: semgrep:error" y ese commit pasaba
// sin las reglas de la casa. Eso rompe la promesa central (si pasa aquí, pasa
// allá) de forma intermitente, que es la peor forma: el CI sí corre semgrep.
//
// ¿Por qué 30 y no 15? Con 15 se perdió un commit igual: en una máquina
// corporativa el EDR mete ráfagas y la cola de latencias es PESADA — el mismo
// semgrep midió 3.1 s, 8.0 s y >14.3 s en la misma hora. Se sondeó el sandbox
// (token restringido + job object, por el camino real de proc.Correr) y quedó
// exonerado: 3-8 s, igual que sin él. Contra colas pesadas un tope siempre
// pierde a veces; 30 s cubre las ráfagas observadas y el caso típico no lo
// nota, porque los motores corren en paralelo y el tope no es espera.
const hookDeadline = 30 * time.Second

// plazoSecretos acota la ETAPA 1, que corría sin ninguno.
//
// El agujero: la etapa 2 siempre tuvo tope —el de arriba— y la 1 se llamaba con
// context.Background() pelado. O sea que la única compuerta BLOQUEANTE del
// producto era también la única sin límite: un gitleaks colgado (el EDR
// escaneando su binario, un disco de red, un antivirus a medio actualizar —los
// mismos escenarios que el comentario de arriba documenta MEDIDOS en máquinas
// corporativas) dejaba el `git commit` del usuario esperando para siempre, sin
// mensaje y sin forma de saber qué pasaba. Y no hacía falta ni un fallo raro:
// esta línea la pisa CADA commit.
//
// En el camino de CI no pasaba, y eso es lo que lo escondió: allí la etapa 1
// corre dentro de pipeline.Run, que sí envuelve el contexto con opt.Timeout.
// Sólo el gancho la llamaba a pelo.
//
// ¿Por qué 60 y no los 30 de la etapa 2? Porque aquí agotar el plazo BLOQUEA el
// commit (fail-closed, §14: la promesa no es «busqué», es «nada sale sin
// escanear»), así que equivocarse por corto le cuesta al usuario un commit
// legítimo, mientras que equivocarse por largo sólo le cuesta esperar. Y la
// etapa 1 hace hoy DOS pasadas de gitleaks, no una: la del repo y el reescaneo
// neutral que cierra los cinco modos de apagar la compuerta. El doble de trabajo
// con la mitad de margen habría sido pedir falsos bloqueos.
//
// Sigue siendo un TOPE, no una espera: un commit normal escanea en menos de un
// segundo y sale en menos de un segundo.
const plazoSecretos = 60 * time.Second

func hookCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "hook",
		Short:  "Puntos de entrada de los hooks de git (los invocan los shims de .githooks)",
		Hidden: true,
	}
	cmd.AddCommand(preCommitCmd(), prepareCommitMsgCmd(), postCommitCmd())
	return cmd
}

// lastRunFile guarda el run id entre pre-commit y prepare-commit-msg/post-commit.
func lastRunFile(repoRoot string) string {
	return filepath.Join(repoRoot, ".git", "codeguard-lastrun")
}

// arbolPreparado devuelve el hash del árbol que hay AHORA en el índice.
//
// Es la identidad de lo que se está a punto de commitear: si cambia, lo
// analizado ya no es lo que se commitea.
//
// Devuelve "" si git no puede darlo; quien llama trata eso como "no puedo
// afirmar que sea el mismo contenido", que es la respuesta prudente.
func arbolPreparado(repoRoot string) string {
	out, err := gitCmd("-C", repoRoot, "write-tree").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// guardarRunID deja el run id JUNTO AL ÁRBOL que se analizó.
//
// El árbol va con él porque el run id sobrevive a commits abortados: pre-commit
// lo escribe, y sólo lo borran el bloqueo y post-commit. Si alguien analiza,
// aborta el commit (cerrar el editor del mensaje sin guardar es el caso normal),
// CAMBIA el código y commitea con --no-verify, prepare-commit-msg —que
// --no-verify NO salta— pegaba el trailer del análisis viejo: post-commit veía
// un trailer, daba el commit por revisado y el salto no se registraba.
//
// Medido en TestUnTrailerNoSobreviveAUnCambioDeContenido: con un secreto metido
// después del análisis, el commit entraba al historial marcado como analizado.
//
// Con el árbol dentro, el trailer significa lo que tiene que significar: ESTE
// contenido pasó por CodeGuard. Si el contenido es el mismo, el trailer es
// legítimo aunque el gancho se saltara — porque el análisis de ese contenido
// existe de verdad.
func guardarRunID(repoRoot, runID string) {
	// Best-effort: si no se puede dejar el run id, el trailer del commit no lo
	// llevará, pero el análisis y el veredicto son los mismos.
	_ = os.WriteFile(lastRunFile(repoRoot),
		[]byte(runID+"\t"+arbolPreparado(repoRoot)), 0o644)
}

// leerRunIDVigente devuelve el run id sólo si el árbol guardado con él coincide
// con el que hay ahora en el índice.
func leerRunIDVigente(repoRoot string) string {
	b, err := os.ReadFile(lastRunFile(repoRoot))
	if err != nil {
		return ""
	}
	runID, arbol, hay := strings.Cut(strings.TrimSpace(string(b)), "\t")
	// Sin árbol no se puede afirmar que el análisis sea de este contenido. Pasa
	// con los archivos que dejó una versión anterior del agente, y con los
	// repos donde `git write-tree` falló.
	if !hay || arbol == "" {
		return ""
	}
	if arbol != arbolPreparado(repoRoot) {
		return ""
	}
	return runID
}

func preCommitCmd() *cobra.Command {
	return &cobra.Command{
		Use:  "pre-commit",
		RunE: func(cmd *cobra.Command, args []string) error { return runPreCommit() },
	}
}

// P4: el hook nunca falla por sí mismo — cualquier error interno sale 0, salvo
// lo que deje a la compuerta de secretos sin hacer su trabajo: que no pueda
// correr, o que no se pueda saber QUÉ tiene que revisar. Las dos son
// fail-closed, porque las dos acaban en un commit sin revisar.
func prepareCommitMsgCmd() *cobra.Command {
	return &cobra.Command{
		Use:  "prepare-commit-msg <archivo-mensaje>",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			repoRoot, err := gitdiff.RepoRoot(".")
			if err != nil {
				return nil
			}
			// Vigente = del MISMO contenido que se va a commitear. Un
			// análisis de otro árbol no dice nada sobre este commit.
			runID := leerRunIDVigente(repoRoot)
			if runID == "" {
				return nil // no hubo análisis, o fue de otro contenido
			}
			msgFile := args[0]
			msg, err := os.ReadFile(msgFile)
			if err != nil {
				return nil
			}
			if strings.Contains(string(msg), "Codeguard-Run-Id:") {
				return nil
			}
			trailer := fmt.Sprintf("\nCodeguard-Run-Id: %s\n", strings.TrimSpace(string(runID)))
			return os.WriteFile(msgFile, append(msg, []byte(trailer)...), 0o644)
		},
	}
}

func postCommitCmd() *cobra.Command {
	return &cobra.Command{
		Use: "post-commit",
		RunE: func(cmd *cobra.Command, args []string) error {
			repoRoot, err := gitdiff.RepoRoot(".")
			if err != nil {
				return nil
			}
			defer os.Remove(lastRunFile(repoRoot))
			cfg, err := config.Load(repoRoot)
			if err != nil || cfg == nil {
				return nil
			}
			out, err := gitCmd("-C", repoRoot, "log", "-1", "--format=%B").Output()
			if err != nil {
				return nil
			}
			if strings.Contains(string(out), "Codeguard-Run-Id:") {
				return nil // commit analizado, todo en orden
			}
			// --no-verify se saltó pre-commit y commit-msg, pero no a nosotros:
			// se registra el bypass (§7.1) — señal de producto, no castigo.
			return persistBypass(repoRoot, cfg)
		},
	}
}

func persistBypass(repoRoot string, cfg *config.Config) error {
	res := &pipeline.Result{Verdict: pipeline.Skipped, Degraded: []string{}, Findings: []finding.Finding{}}
	return persistWith(repoRoot, cfg, res, 0, true)
}

