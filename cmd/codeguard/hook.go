package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/spf13/cobra"

	"codeguard/internal/baseline"
	"codeguard/internal/config"
	"codeguard/internal/daemon"
	"codeguard/internal/engines"
	glengine "codeguard/internal/engines/gitleaks"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
	"codeguard/internal/ipc"
	"codeguard/internal/pipeline"
	"codeguard/internal/store"
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
func runPreCommit() error {
	// El recover de abajo aplica P4 tal cual está escrito: la compuerta de
	// secretos es fail-closed y todo lo demás no. Un pánico ANTES de que la
	// etapa 1 emita su veredicto es "la compuerta no pudo correr" —lo mismo
	// que un error de gitdiff.Staged o que glengine.ErrUnavailable, unas
	// líneas más abajo— y se trata igual: se cierra. Un pánico DESPUÉS
	// (etapa 2, telemetría, trailer, avisos) sigue la política de siempre:
	// el hook no falla por sí mismo y el commit pasa. La marca se pone en el
	// punto exacto en que la etapa 1 terminó de decidir.
	compuertaSecretosCumplida := false
	defer func() {
		if r := recover(); r != nil {
			if !compuertaSecretosCumplida {
				// El pánico se imprime: cerrar no es callar. Y se nombra
				// --no-verify porque aquí el usuario se queda atascado,
				// igual que en las otras ramas fail-closed de este archivo.
				fmt.Fprintln(os.Stderr, "CodeGuard  BLOQUEADO: error interno antes de que la compuerta de secretos diera su veredicto (fail-closed):", r)
				fmt.Fprintln(os.Stderr, "CodeGuard  si necesitas commitear ya, `git commit --no-verify` salta la revisión — "+
					"queda constancia de que este commit no se revisó")
				os.Exit(1)
			}
			fmt.Fprintln(os.Stderr, "CodeGuard  error interno (se permite el commit):", r)
			os.Exit(0)
		}
	}()

	repoRoot, err := gitdiff.RepoRoot(".")
	if err != nil {
		return nil // fuera de un repo: nada que hacer
	}
	cfg, err := config.Load(repoRoot)
	if err != nil {
		// Aplanado por lo mismo que el motivo del daemon, y es LITERALMENTE el
		// mismo error: el de koanf al leer este archivo, que llega en tres
		// líneas. Aquí sale antes incluso de que exista progress.
		fmt.Fprintln(os.Stderr, "CodeGuard  config ilegible (se permite el commit):",
			unaSolaLinea(err.Error()))
		return nil
	}
	if cfg == nil {
		return nil // repo no enrolado
	}
	// progress se declara antes de la primera compuerta: un fallo aquí ya tiene
	// que poder hablar, y antes salía mudo.
	progress := func(s string) { fmt.Fprintf(os.Stderr, "CodeGuard  %s\n", s) }

	diff, err := gitdiff.Staged(repoRoot)
	if err != nil {
		// Fail-closed (§14), la misma política que ErrUnavailable unas líneas más
		// abajo y por el mismo motivo: sin la lista de lo preparado, la compuerta
		// de secretos —la única bloqueante— no tiene qué mirar. Es exactamente
		// "la compuerta no pudo correr", sólo que un paso antes.
		//
		// Estaba junto a len(diff.Files) == 0 en el mismo `return nil`, y son
		// cosas distintas: "no hay nada que revisar" (seguir) contra "no pude
		// averiguar qué hay que revisar" (parar). Confundirlas convertía
		// cualquier tropiezo de git en un "adelante" silencioso.
		//
		// Separarlas no bloquea a nadie de más, y esto está medido contra git
		// 2.43: sin nada preparado, en un repo sin ningún commit todavía, con un
		// merge a medio resolver y en `commit --amend`, `git diff --cached` sale
		// con ÉXITO y lista vacía. Un error aquí es git roto de verdad: índice
		// corrupto, binario ausente, permisos.
		// La línea de reparación decía "si el índice quedó dañado, `git reset`
		// suele recomponerlo", y era incorrecta justo en los dos escenarios que
		// de verdad llegan hasta aquí: en ellos el índice está SANO y lo roto es
		// el almacén de objetos. Con el índice corrupto git aborta él solo antes
		// de invocar el hook, así que ese caso no se alcanza desde un commit; lo
		// que sí se alcanza es un blob o un árbol ausente —gc interrumpido,
		// antivirus en cuarentena, clon abortado, disco con errores—, donde
		// `git reset` no recupera nada y manda al usuario a dar vueltas.
		//
		// Y se nombra --no-verify porque aquí el usuario se queda atascado: este
		// archivo ya lo trata como señal de producto y no como castigo.
		progress("BLOQUEADO: no pude leer lo que está preparado para commitear (fail-closed)")
		progress("detalle: " + err.Error())
		progress("suele ser el almacén de objetos, no el índice: `git fsck` lo diagnostica " +
			"(un objeto ausente no lo repone un `git fetch` normal: hace falta " +
			"`git fetch --refetch` o volver a clonar)")
		progress("si necesitas commitear ya, `git commit --no-verify` salta la revisión — " +
			"queda constancia de que este commit no se revisó")
		os.Exit(1)
	}
	if len(diff.Files) == 0 {
		return nil // nada preparado: no hay nada que revisar
	}

	// LO QUE SE VA A ANALIZAR NO SIEMPRE ES LO QUE SE VA A COMMITEAR, Y CALLARLO
	// ES LA MENTIRA QUE ESTE PRODUCTO EXISTE PARA RETIRAR.
	//
	// La lista de archivos sale del ÍNDICE, pero los motores por archivo leen del
	// DISCO. Con `git add -p`, o editando después de un `git add`, las dos cosas
	// se separan y el veredicto habla de un contenido que no va a entrar al
	// historial: el dev ve verde sobre lo que tiene en el editor y el CI analiza
	// lo otro. Justo la promesa central —«si pasa aquí, pasa allá»— rota en
	// silencio, y en un flujo que es rutina, no un caso raro.
	//
	// AVISA Y NO BLOQUEA, a propósito: staging parcial es una forma legítima y
	// muy común de trabajar, y bloquearla convertiría el producto en un estorbo.
	// Lo que no es legítimo es decir "revisado" sin decir "…de otra cosa".
	//
	// El arreglo de fondo (analizar el índice materializándolo en un árbol
	// temporal) es otra conversación: go vet, staticcheck, tsc y dotnet build
	// COMPILAN y no saben leer un índice, así que no es un cambio de ReadFile
	// sino de arquitectura, con coste en cada commit. Ver ConCambiosSinPreparar.
	rutas := make([]string, 0, len(diff.Files))
	for _, f := range diff.Files {
		if f.Status != "D" {
			rutas = append(rutas, f.Path)
		}
	}
	if divergentes, err := gitdiff.ConCambiosSinPreparar(repoRoot, rutas); err == nil && len(divergentes) > 0 {
		// Best-effort: si git no puede decirlo, no se inventa nada y el análisis
		// sigue. Este aviso nunca puede ser el motivo de que un commit se pare.
		progress(fmt.Sprintf("aviso: %d archivo(s) tienen cambios SIN preparar — se revisa lo que hay "+
			"en disco, y no es lo que vas a commitear: %s", len(divergentes),
			unaSolaLinea(strings.Join(divergentes, ", "))))
		progress("     si esto te importa, `git add` esos archivos y vuelve a commitear")
	}

	start := time.Now()

	// ── Etapa 1: secretos, en este proceso, fail-closed ──
	ctxSecretos, cancelSecretos := context.WithTimeout(context.Background(), plazoSecretos)
	secretsEng := &glengine.Engine{Mode: "staged"}
	secretFindings, err := secretsEng.Run(ctxSecretos, engines.Input{RepoRoot: repoRoot, Files: diff.Files})
	cancelSecretos()
	if err != nil {
		// CUALQUIER error de la etapa 1 es fail-closed, no sólo ErrUnavailable
		// (§14: la promesa no es «busqué», es «nada sale sin escanear»). Un
		// error aquí significa "no pude escanear", y un commit que sale sin
		// escanear es exactamente lo que esta compuerta existe para impedir.
		// Antes el resto de errores —el timeout de plazoSecretos incluido,
		// cuyo comentario promete BLOQUEO unas líneas arriba— caía en un
		// "error no fatal" y el commit pasaba con secretFindings vacío: la
		// única compuerta bloqueante del producto se volvía una nota
		// informativa justo cuando no había podido mirar.
		if errors.Is(err, glengine.ErrUnavailable) {
			progress("BLOQUEADO: la compuerta de secretos no pudo correr (fail-closed)")
			progress("repara con: codeguard repair   —   detalle: " + err.Error())
			os.Exit(1)
		}
		if errors.Is(err, context.DeadlineExceeded) {
			// El plazo se agotó: gitleaks no terminó y no se sabe qué había
			// en lo preparado. Los sospechosos son los mismos que documenta
			// MEDIDO el comentario de hookDeadline en máquinas corporativas:
			// el EDR escaneando el binario de gitleaks, un antivirus a medio
			// actualizar, un disco de red. Suele ser transitorio, así que el
			// primer remedio es reintentar — no `codeguard repair`, que aquí
			// no arregla nada.
			progress("BLOQUEADO: la compuerta de secretos no terminó dentro de su plazo (fail-closed)")
			progress("suele ser el EDR/antivirus escaneando el binario de gitleaks o un disco lento: " +
				"reintenta el commit; si se repite, revisa las exclusiones del antivirus")
			progress("si necesitas commitear ya, `git commit --no-verify` salta la revisión — " +
				"queda constancia de que este commit no se revisó")
			os.Exit(1)
		}
		// Cualquier otro fallo de ejecución (salida ilegible, gitleaks roto,
		// disco): el mismo criterio — no se escaneó, no sale. Aplanado: el
		// texto del error arrastra salida del motor, que no es nuestra.
		progress("BLOQUEADO: la compuerta de secretos falló al ejecutarse (fail-closed)")
		progress("detalle: " + unaSolaLinea(err.Error()))
		progress("si necesitas commitear ya, `git commit --no-verify` salta la revisión — " +
			"queda constancia de que este commit no se revisó")
		os.Exit(1)
	}
	if len(secretFindings) > 0 {
		progress(fmt.Sprintf("secretos ✗  BLOQUEADO: %d secreto(s) en el diff — NADA salió a la red", len(secretFindings)))
		for _, f := range secretFindings {
			// Igual que los de la etapa 2: gitleaks admite reglas propias del
			// repo (.gitleaks.toml), así que este texto tampoco es siempre
			// nuestro. Y esta lista es la del bloqueo por secretos, donde una
			// línea falsa hace el máximo daño.
			progress(fmt.Sprintf("  %s:%d  %s", f.File, f.Line, mensajeDeHallazgo(f.Message)))
		}
		progress("rota la credencial PRIMERO; borrarla del historial no la invalida")
		// Haber frenado una credencial es el evento que justifica el producto, y
		// era el ÚNICO que no quedaba anotado en ninguna parte: esta rama salía
		// por os.Exit sin tocar la base, así que después de bloquear una clave de
		// AWS `codeguard stats` seguía diciendo "sin hallazgos registrados
		// todavía". Los commits limpios sí se registraban, o sea que la
		// telemetría contaba los días buenos y se callaba los que importan; y si
		// el dev no estaba mirando la terminal, el bloqueo no existió para nadie.
		//
		// El run id se genera aquí y NO se guarda con guardarRunID: ese archivo
		// existe para el trailer del commit, y este commit no va a existir.
		// Dejarlo escrito es justo lo que el bloqueo de la etapa 2 se cuida de
		// borrar unas líneas más abajo, para que un --no-verify posterior no
		// herede un trailer que diga "revisado".
		res := &pipeline.Result{
			Verdict:          pipeline.Block,
			BlockingFindings: len(secretFindings),
			Degraded:         []string{},
			Findings:         secretFindings,
			ElapsedMs:        time.Since(start).Milliseconds(),
		}
		if err := persistRun(repoRoot, cfg, res, len(diff.Files), false, store.NewULID()); err != nil {
			// Telemetría, no compuerta: el veredicto ya está tomado y no cambia
			// porque la base falle. Se avisa y se bloquea igual.
			fmt.Fprintln(os.Stderr, "CodeGuard  aviso: no se pudo registrar el bloqueo:", err)
		}
		// Y que la INTERFAZ se entere, que era el otro agujero del mismo sitio.
		//
		// Esta rama salía por os.Exit mucho antes de la primera llamada al
		// daemon, así que el orbe se quedaba en verde y el panel mudo justo
		// cuando el producto acababa de frenar una credencial. Medido con una
		// llave privada y una clave de Stripe: commit bloqueado, terminal
		// diciéndolo, y la UI sin enterarse. Si el dev commitea desde un editor
		// que se traga la salida del gancho, el bloqueo no existía para nadie.
		//
		// Va DESPUÉS de persistRun para que el detalle ya esté en la base cuando
		// el panel lo vaya a buscar, y es best-effort: el veredicto ya está
		// tomado y que el agente esté apagado no puede cambiarlo. Por eso no se
		// mira el error — bloquear es lo que importa, avisar es un extra.
		//
		// Viaja el NÚMERO, nunca los hallazgos: son ellos los que llevan la
		// credencial dentro, y abrir un camino nuevo por el que salga sería lo
		// contrario de lo que acabamos de hacer.
		//
		// Del hallazgo se toman SÓLO archivo y línea. Ni el mensaje del motor
		// —que con un .gitleaks.toml propio lo escribe el repo analizado— ni la
		// línea de código, que ES la credencial. Con el sitio, quien lo lee sabe
		// adónde ir; el valor ya lo tiene abierto en su editor.
		donde := make([]string, 0, len(secretFindings))
		for _, f := range secretFindings {
			donde = append(donde, fmt.Sprintf("%s:%d", f.File, f.Line))
		}
		_, _ = ipc.Call(&ipc.Request{
			Command:            "secreto-bloqueado",
			RepoRoot:           repoRoot,
			Branch:             gitBranch(repoRoot),
			SecretosBloqueados: len(secretFindings),
			SecretosEn:         donde,
			DeadlineMs:         2000,
		}, 2*time.Second)
		os.Exit(1)
	}
	progress("secretos ✓")
	// A partir de aquí la compuerta de secretos ya cumplió su trabajo: corrió
	// y emitió su veredicto. La marca NO se pone antes de la rama de bloqueo
	// a propósito: un pánico dentro de ella (persistRun, ipc.Call) caería en
	// el recover con hallazgos de secretos ya detectados, y salir por
	// "se permite el commit" dejaría pasar una credencial frenada. Ahí la
	// salida prudente también es cerrar. La rama de bloqueo normal sale por
	// os.Exit, que no pasa por ningún defer, así que esto no le cambia nada.
	compuertaSecretosCumplida = true

	// ── Run id para el trailer (prepare-commit-msg) ──
	runID := store.NewULID()
	guardarRunID(repoRoot, runID)

	// ── Señal de código generado por IA (RADAR): variables de entorno de la
	// herramienta que invoca el commit. Sube el riesgo (+20) y se etiqueta. ──
	aiGenerated := false
	for _, v := range []string{"CLAUDECODE", "CLAUDE_CODE", "CURSOR_AGENT", "GITHUB_COPILOT_AGENT", "AIDER_MODEL", "GEMINI_CLI"} {
		if os.Getenv(v) != "" {
			aiGenerated = true
			break
		}
	}

	// ── Etapa 2: en el daemon; sin daemon, local degradado ──
	req := &ipc.Request{
		RunID:           runID,
		RepoRoot:        repoRoot,
		RepoID:          store.RepoIDDe(repoRoot, gitRemote(repoRoot)),
		Branch:          gitBranch(repoRoot),
		StagedFiles:     diff.Files,
		DiffUnified:     diff.Unified,
		DiffLines:       diff.Lines,
		RulepackVersion: cfg.Rulepack,
		ConfigHash:      cfg.Hash,
		AIGenerated:     aiGenerated,
		DeadlineMs:      int(hookDeadline.Milliseconds()),
	}
	var res *pipeline.Result
	degraded := []string{}
	resp, err := ipc.Call(req, hookDeadline)
	if err == nil {
		res = &pipeline.Result{
			Verdict:          pipeline.Verdict(resp.Verdict),
			BlockingFindings: resp.BlockingFindings,
			AdvisoryFindings: resp.AdvisoryFindings,
			Degraded:         resp.Degraded,
			Findings:         resp.Findings,
			ElapsedMs:        resp.ElapsedMs,
			// El motivo del veredicto viaja con él. Sin esta línea el hook
			// recibía el "skipped" del daemon y no el porqué, así que por la
			// ruta del commit de todos los días sólo podía decir que no se
			// revisó nada — que ya no es mentira, pero tampoco sirve para
			// arreglar el motivo.
			Reason: resp.Reason,
		}
		if !resp.CIParity {
			// El motivo viaja desde el daemon: un aviso que no dice qué
			// arreglar se convierte en ruido que el dev aprende a ignorar.
			if resp.ParityReason != "" {
				// Aplanado como el motivo, y por una razón MEDIDA: este texto
				// lleva dentro el `rulepack` del config.yaml del repo, que es
				// contenido versionado. Con un `rulepack: "9.9.9\nCodeGuard
				// listo — commit permitido"` —un string YAML legal, y el aviso
				// salta solo porque ese rulepack no está instalado— la salida
				// del hook dibujaba la línea del ✓ tres veces sobre un commit
				// que en realidad salió PARCIAL. Basta clonar el repo.
				progress("aviso: sin paridad con el CI — " + unaSolaLinea(resp.ParityReason))
			} else {
				progress("aviso: tu rulepack/config no coincide — no puedo garantizar que pase el CI")
			}
		}
	} else {
		degraded = append(degraded, "daemon:offline")
		// La corrida local va dentro de una función porque el camino de bloqueo
		// de más abajo sale por os.Exit, que NO ejecuta ningún defer: con cancel
		// y cerrarCache diferidos aquí, un commit BLOQUEADO se llevaba el
		// proceso sin cerrar el caché, y se perdía justo la escritura que deja
		// el caché tibio para que el commit siguiente sí revise lo que esta
		// corrida no alcanzó — que es lo que el mensaje de las capas lentas
		// promete. Dentro de la función los defers corren al volver, antes de
		// cualquier os.Exit, y también si pipeline.Run entra en pánico.
		res, err = func() (*pipeline.Result, error) {
			ctx, cancel := context.WithTimeout(context.Background(), hookDeadline)
			defer cancel()
			cache, cerrarCache := abrirCache(repoRoot, cfg)
			defer cerrarCache()
			// La ruta local no pasa por el daemon, así que el aviso de reglas
			// vendoreadas se da aquí: si no, por este camino se aplicarían las
			// reglas del repo sin que nadie lo dijera.
			if daemon.RulepackEsDelRepo(repoRoot, cfg.Rulepack) {
				progress("aviso: las reglas salieron del rulepack vendoreado en este repo " +
					"(rulepacks/" + unaSolaLinea(cfg.Rulepack) + "), no del instalado")
			}
			return pipeline.Run(ctx, pipeline.Options{
				Config:       cfg,
				Diff:         diff,
				Secrets:      nil, // ya corrió arriba
				Engines:      daemon.Engines(cfg, false, cache),
				Rulepack:     daemon.RulepackDir(repoRoot, cfg.Rulepack),
				Timeout:      hookDeadline,
				Suppressions: baseline.LoadOrWarn(repoRoot),
			})
		}()
		if err != nil {
			progress("análisis local falló (se permite el commit): " + err.Error())
			return nil
		}
		res.Degraded = append(res.Degraded, degraded...)
	}

	// ── Veredicto en la terminal (§12.1.1) ──
	gates := "formato/lint/tipos/reglas/migraciones"
	// El veredicto lo decide el pipeline y viaja en res.Verdict: un Block por
	// AVERÍA de la compuerta de secretos (timeout, ErrUnavailable, ...) llega
	// con BlockingFindings == 0, porque no hay hallazgos que contar — hay una
	// compuerta que no llegó a mirar. Decidir sólo por el contador dejaba ese
	// Block caer en el `else` final: "✓ listo — commit permitido" y salida 0
	// sobre un Result que decía Block. El fail-closed se construía en
	// pipeline.Run y se perdía al cruzar el pipe. La fuente de verdad es el
	// Verdict; el contador sólo cubre el caso con hallazgos.
	//
	// Va ANTES de Skipped/Degraded/✓ a propósito: un Block con capas
	// degradadas tiene que bloquear, no anunciarse como PARCIAL.
	bloquea := res.BlockingFindings > 0 || res.Verdict == pipeline.Block
	if bloquea {
		progress(gates + " ✗")
		for _, f := range res.Findings {
			if f.Blocking {
				// El mensaje sale del YAML de una regla, y ese YAML puede venir
				// del rulepack vendoreado en ESTE repo (RulepackDir lo prioriza).
				// Sin aplanar, un `message` con saltos escribe líneas propias
				// justo aquí: debajo del hallazgo que bloquea el commit.
				progress(fmt.Sprintf("  [%s] %s:%d  %s",
					f.RuleKey, f.File, f.Line, mensajeDeHallazgo(f.Message)))
			}
		}
		if res.BlockingFindings > 0 {
			progress(fmt.Sprintf("BLOQUEADO: %d problema(s) que el CI también rechazaría  (%.1f s)",
				res.BlockingFindings, time.Since(start).Seconds()))
		} else {
			// Block sin hallazgos: es la avería de la compuerta, y quien la
			// explica es res.Reason ("la compuerta de secretos no terminó
			// dentro de su plazo (fail-closed): ..."), no "0 problema(s)".
			// Aplanado: el Reason arrastra el error del motor, que no es
			// texto nuestro. Y se nombra --no-verify como en toda rama
			// fail-closed de este archivo: aquí el usuario se queda atascado.
			progress("BLOQUEADO: " + unaSolaLinea(res.Reason) +
				fmt.Sprintf("  (%.1f s)", time.Since(start).Seconds()))
			progress("si necesitas commitear ya, `git commit --no-verify` salta la revisión — " +
				"queda constancia de que este commit no se revisó")
		}
	} else if res.Verdict == pipeline.Skipped {
		// Un análisis OMITIDO no es una revisión, ni completa ni parcial: el
		// embudo se paró en la etapa 0 y ninguna compuerta llegó a mirar nada.
		//
		// Esta rama existe porque el hook decidía el mensaje sólo con
		// BlockingFindings y len(Degraded), sin leer NUNCA res.Verdict — que es
		// el campo que el pipeline rellena precisamente para esto. Un Skipped
		// sin capas degradadas caía en el `else` de abajo y firmaba
		// "formato/... ✓  listo — commit permitido" sobre cinco compuertas que
		// no corrieron; con el daemon caído caía en la rama PARCIAL y prometía
		// "lo que SÍ se revisó", que tampoco existía. Es el mismo fallo que ya
		// se corrigió para el caso degradado, en el caso de al lado.
		//
		// Va ANTES de la rama de Degraded a propósito: por el camino local
		// siempre hay al menos "daemon:offline", así que si fuera después no se
		// alcanzaría nunca.
		//
		// No se bloquea. Que un merge o una configuración que excluye estos
		// archivos no dejen nada que revisar es normal y es decisión del propio
		// equipo; sólo los secretos son fail-closed (§14). Pero se dice.
		progress(fmt.Sprintf("%s — SIN REVISAR   (%.1f s)", gates, time.Since(start).Seconds()))
		switch {
		case pipeline.EsDecisionDelEquipo(res.Reason):
			// Tono neutro a propósito. Un repo que excluye vendor/** o docs/**
			// ve esto en CADA commit que sólo toque esas rutas, y "esto NO es
			// una revisión limpia" repetido cien veces deja de leerse — y se
			// lleva por delante el aviso serio, que es el mismo mensaje. Aquí no
			// hay nada roto ni nada que arreglar: el equipo decidió qué mirar y
			// el hook lo respeta. El encabezado de arriba ya impide confundirlo
			// con un análisis que sí corrió, que era el fallo original.
			progress("sin archivos que revisar: todos excluidos por la configuración")
		case res.Reason != "":
			// Lo que SÍ es avería: la config que no se pudo leer. Aquí la línea
			// fuerte se gana su sitio, porque hay algo que arreglar y el commit
			// se está yendo sin revisar.
			progress("no se analizó nada: " + unaSolaLinea(res.Reason))
			progress("el commit sigue permitido, pero esto NO es una revisión limpia")
		default:
			// Sin motivo no se puede saber si fue decisión o avería, así que se
			// asume lo segundo: pasa con un daemon anterior al campo `reason`.
			progress("no se analizó nada (el motivo no llegó hasta aquí)")
			progress("el commit sigue permitido, pero esto NO es una revisión limpia")
		}
	} else if len(res.Degraded) > 0 {
		// Revisión PARCIAL: no se puede poner un ✓ ni decir "listo" cuando una
		// compuerta no llegó a mirar nada.
		//
		// Casi todas las compuertas de §7 están configuradas para BLOQUEAR
		// (formato, compilación, lint, reglas, migraciones). Una capa que no
		// corre es una compuerta que no revisa nada mientras aparenta que sí, y
		// el ✓ de esta línea era justo esa apariencia: el aviso de las capas
		// caídas se imprimía DESPUÉS, como nota al pie de un veredicto que ya
		// había dicho que todo estaba bien.
		//
		// No se bloquea —sólo los secretos son fail-closed (§14), y volver
		// obstáculo al agente cada vez que un motor tropieza es la forma más
		// rápida de que lo desinstalen— pero el veredicto dice la verdad: aquí
		// no se miró todo.
		progress(fmt.Sprintf("%s — PARCIAL   (%.1f s)", gates, time.Since(start).Seconds()))
		if res.AdvisoryFindings > 0 {
			progress(fmt.Sprintf("commit permitido sobre lo que SÍ se revisó; %d sugerencia(s) en el panel", res.AdvisoryFindings))
		} else {
			progress("commit permitido sobre lo que SÍ se revisó")
		}
	} else {
		progress(fmt.Sprintf("%s ✓   (%.1f s)", gates, time.Since(start).Seconds()))
		if res.AdvisoryFindings > 0 {
			progress(fmt.Sprintf("listo — commit permitido; %d sugerencia(s) en el panel", res.AdvisoryFindings))
		} else {
			progress("listo — commit permitido")
		}
	}
	// El detalle de capas caídas se calla cuando el análisis ni siquiera
	// empezó: enumerar "capas no revisadas" y explicar que "esta revisión fue
	// en frío" habla de una revisión que no existió, y encima suena a avería
	// donde sólo hubo un merge o unos archivos excluidos.
	if len(res.Degraded) > 0 && res.Verdict != pipeline.Skipped {
		// Aplanado: las etiquetas no son todas nuestras — "rulepack-ausente:<v>"
		// lleva pegado el `rulepack` del config.yaml del repo, y por ahí entra
		// texto de fuera a una línea de la terminal.
		progress("capas no revisadas: " + unaSolaLinea(strings.Join(res.Degraded, ", ")))
		// El daemon caído no es una capa más: sin él, la etapa 2 corre en el
		// proceso del hook, en frío y contra el mismo plazo, así que suele
		// arrastrar a otras capas con ella. Se dice qué hacer.
		for _, d := range res.Degraded {
			if d == "daemon:offline" {
				fmt.Fprintln(os.Stderr,
					"CodeGuard  el agente no estaba corriendo, así que esta revisión fue en frío y sin\n"+
						"           caché. Arráncalo (cierra y abre sesión, o lanza codeguard-daemon) y el\n"+
						"           siguiente commit se revisa completo y en segundos.")
			}
		}
		// Un motor que no cupo en el plazo se explica solo, porque su remedio
		// es "no hagas nada": la primera corrida en frío compila o arranca node,
		// y la siguiente va con caché. Sin esta línea el dev lee una etiqueta
		// cruda y no sabe si le acaban de romper algo.
		var lentos []string
		for _, d := range res.Degraded {
			if m, ok := strings.CutSuffix(d, ":plazo"); ok {
				lentos = append(lentos, m)
			}
		}
		if len(lentos) > 0 {
			fmt.Fprintf(os.Stderr,
				"CodeGuard  %s no cabía(n) en el plazo de esta corrida (la primera es la cara:\n"+
					"           compilar o arrancar node). El caché ya quedó tibio; el próximo commit\n"+
					"           sí los revisa. El CI los aplica igual, así que nada se cuela.\n",
				strings.Join(lentos, " y "))
		}
		// Un rulepack ausente no es una capa más: significa que este commit NO
		// se revisó con las reglas del CI y puede fallar allá aunque aquí pase.
		for _, d := range res.Degraded {
			if v, ok := strings.CutPrefix(d, "rulepack-ausente:"); ok {
				fmt.Fprintf(os.Stderr,
					"CodeGuard  ATENCIÓN: este repo apunta al rulepack %s y no está instalado.\n"+
						"           Las reglas de la casa NO se aplicaron: el CI puede rechazar este commit.\n"+
						"           Arréglalo con `codeguard repair` o vendorea el rulepack en el repo.\n",
					unaSolaLinea(v))
			}
		}
	}

	if err := persistRun(repoRoot, cfg, res, len(diff.Files), false, runID); err != nil {
		fmt.Fprintln(os.Stderr, "CodeGuard  aviso: no se pudo registrar el run:", err)
	}
	// La MISMA condición que el mensaje de arriba: si el veredicto es Block
	// —con hallazgos o por avería de la compuerta— el commit no sale. Con
	// dos condiciones escritas a los dos lados, la primera que se editara
	// distinta dejaría la terminal diciendo BLOQUEADO mientras el hook
	// devolvía 0 (o al revés), y el dev sin forma de saber cuál miente.
	if bloquea {
		// Sin run id pendiente: si el dev reintenta con --no-verify,
		// prepare-commit-msg (que --no-verify NO salta) no debe pegar un
		// trailer viejo que camufle el bypass.
		os.Remove(lastRunFile(repoRoot))
		os.Exit(1)
	}
	return nil
}

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

// aplanado deja un texto de otro origen en UNA línea y sin nada que pueda
// reescribir lo ya impreso, antes de que salga junto al prefijo "CodeGuard ".
//
// Aquí llega texto que no redactamos nosotros: el motivo del análisis omitido
// lo escribe el daemon —y uno de los suyos arrastra el error de koanf, que es
// MULTILÍNEA—, el aviso de paridad lleva dentro el `rulepack` del config.yaml
// del repo, y el mensaje de un hallazgo sale del YAML de una regla, que puede
// venir del rulepack VENDOREADO en el repo analizado. Los tres son contenido
// que viaja versionado: basta clonar un repo para controlarlos.
//
// Sin aplanar, un salto en el sitio justo dibuja una línea que aparenta ser
// nuestra. Está medido: con una regla vendoreada cuyo `message` lleva dos
// saltos, la lista de hallazgos bloqueantes enseñaba
// "CodeGuard  listo — commit permitido" DEBAJO del hallazgo que estaba
// bloqueando el commit.
//
// strings.Fields se lleva por delante todo lo que unicode considera espacio, y
// eso ya cubre los separadores que parten una línea: \n, \r, \t, \v, \f, el NEL
// U+0085 y los U+2028/U+2029 de Unicode. Lo que NO cubre son los controles que
// mueven el cursor sin ser espacio —ESC y sus secuencias ANSI, el retroceso,
// NUL, BEL, DEL—: con un ESC[1A se sube una línea y se reescribe la de arriba,
// y con retrocesos se borra el prefijo "CodeGuard " y se pone otro texto. Se
// llega a la misma falsificación sin usar un solo salto de línea, así que se
// quitan por rango en vez de enumerar secuencias, que es una lista que siempre
// se queda corta.
//
// El tope va por RUNAS: cortar el slice de bytes parte el último carácter
// multibyte y deja un rombo de reemplazo.
func aplanado(s string, topeRunas int) string {
	sinControles := strings.Map(func(r rune) rune {
		// Se conservan los espacios: los aplana Fields justo debajo, y quitarlos
		// aquí pegaría dos palabras.
		if unicode.IsSpace(r) {
			return r
		}
		// IsControl cubre las dos bandas Cc de una vez: la baja (NUL..US, con
		// ESC y el retroceso dentro) y la alta (DEL..U+009F).
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	limpio := strings.Join(strings.Fields(sinControles), " ")
	if runas := []rune(limpio); len(runas) > topeRunas {
		return string(runas[:topeRunas]) + "…"
	}
	return limpio
}

// Dos topes porque son dos clases de texto, no por gusto.
const (
	// topeServicio corta los textos que ORIENTAN: el motivo de un análisis
	// omitido, el aviso de paridad. Un error de esquema puede traer el volcado
	// entero de la estructura y aquí sólo hace falta lo que sitúa el problema.
	topeServicio = 300
	// topeMensaje corta el texto de un hallazgo, que es OTRA cosa: es lo que el
	// desarrollador necesita para arreglar el código, y recortarlo a 300 le
	// quitaría justo la parte que explica qué hacer. El tope existe sólo para
	// que un YAML absurdo no vuelque un megabyte en la terminal; ninguna regla
	// real de las 119 del rulepack se acerca (la más larga anda por 180).
	topeMensaje = 2000
)

// unaSolaLinea es el aplanado de los textos de servicio.
func unaSolaLinea(s string) string { return aplanado(s, topeServicio) }

// mensajeDeHallazgo aplana el texto de un hallazgo conservándolo entero.
//
// Se aplica al MENSAJE y no a la línea ya formateada a propósito: la sangría de
// dos espacios con la que se listan los hallazgos es del formato, no del texto
// ajeno, y aplanar después se la comería. Primero se sanea lo que viene de
// fuera, después se coloca en su sitio.
func mensajeDeHallazgo(s string) string { return aplanado(s, topeMensaje) }
