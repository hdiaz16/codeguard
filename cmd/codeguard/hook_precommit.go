package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"codeguard/internal/baseline"
	"codeguard/internal/config"
	"codeguard/internal/daemon"
	"codeguard/internal/engines"
	glengine "codeguard/internal/engines/gitleaks"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
	"codeguard/internal/ipc"
	"codeguard/internal/pipeline"
	"codeguard/internal/rulepack"
	"codeguard/internal/store"
)

func runPreCommit() error {
	var inst *gitdiff.InstantaneaIndice
	limpiarInstantanea := func() {
		if inst == nil {
			return
		}
		if err := inst.Cerrar(); err != nil {
			fmt.Fprintln(os.Stderr, "CodeGuard  aviso: no se pudo retirar la instantánea temporal:", err)
		}
		inst = nil
	}
	defer limpiarInstantanea()
	salir := func(codigo int) {
		// os.Exit no ejecuta defers. Toda salida del hook pasa por este dueño para
		// que un commit bloqueado no acumule copias del repositorio en TEMP.
		limpiarInstantanea()
		os.Exit(codigo)
	}

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
				salir(1)
			}
			fmt.Fprintln(os.Stderr, "CodeGuard  error interno (se permite el commit):", r)
			salir(0)
		}
	}()

	repoRoot, err := gitdiff.RepoRoot(".")
	if err != nil {
		return nil // fuera de un repo: nada que hacer
	}
	// progress se declara antes de la primera compuerta: un fallo aquí ya tiene
	// que poder hablar, y antes salía mudo.
	progress := func(s string) { fmt.Fprintf(os.Stderr, "CodeGuard  %s\n", s) }

	arbolDelDiff, err := gitdiff.ArbolIndice(repoRoot)
	if err != nil {
		progress("BLOQUEADO: no pude identificar el índice que se va a commitear (fail-closed)")
		progress("detalle: " + unaSolaLinea(err.Error()))
		progress("si necesitas commitear ya, `git commit --no-verify` salta la revisión — queda constancia de que este commit no se revisó")
		salir(1)
	}
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
		salir(1)
	}
	if len(diff.Files) == 0 {
		return nil // nada preparado: no hay nada que revisar
	}

	// El árbol que consumen los analizadores se construye con los blobs del
	// índice, no con el disco. Así `git add -p`, `git commit -a` y una edición
	// posterior al add revisan exactamente los bytes que van al commit.
	inst, errInstantanea := gitdiff.MaterializarIndice(repoRoot)
	if errInstantanea == nil && inst.Tree != arbolDelDiff {
		errInstantanea = fmt.Errorf("el índice cambió entre el diff y la instantánea (%s → %s)", arbolDelDiff, inst.Tree)
		_ = inst.Cerrar()
		inst = nil
	}
	analysisRoot := repoRoot
	if errInstantanea == nil {
		analysisRoot = inst.Root
		for i := range diff.Files {
			if diff.Files[i].Status == "D" {
				diff.Files[i].SHA256 = ""
				continue
			}
			diff.Files[i].SHA256 = gitdiff.SHA256De(analysisRoot, diff.Files[i].Path)
		}
	} else {
		// La compuerta de secretos aún corre sobre el diff de Git. Lo que no se
		// hará es declarar limpia la calidad mirando el worktree equivocado.
		progress("aviso: no se pudo congelar el índice: " + unaSolaLinea(errInstantanea.Error()))
	}

	cfg, errConfig := config.Load(analysisRoot)
	if errConfig == nil && cfg != nil {
		// El lock, la baseline y un rulepack vendoreado también se leen de la
		// foto que entra al commit. Después se restaura la identidad del repo
		// real para confianza, caché y persistencia local.
		declararSkewDeLock(analysisRoot, cfg)
		cfg.RepoRoot = repoRoot
	}
	var degradacionesInstantanea []string
	if inst != nil && len(inst.Submodulos) > 0 {
		degradacionesInstantanea = append(degradacionesInstantanea,
			fmt.Sprintf("index:submodules-opaque:%d", len(inst.Submodulos)))
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
			salir(1)
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
			salir(1)
		}
		// Cualquier otro fallo de ejecución (salida ilegible, gitleaks roto,
		// disco): el mismo criterio — no se escaneó, no sale. Aplanado: el
		// texto del error arrastra salida del motor, que no es nuestra.
		progress("BLOQUEADO: la compuerta de secretos falló al ejecutarse (fail-closed)")
		progress("detalle: " + unaSolaLinea(err.Error()))
		progress("si necesitas commitear ya, `git commit --no-verify` salta la revisión — " +
			"queda constancia de que este commit no se revisó")
		salir(1)
	}
	// La etapa 1 corre FUERA de pipeline.Run (fail-closed, no depende de nadie),
	// así que sus hallazgos no pasan por la asignación colectiva del pipeline:
	// la identidad se asigna aquí, con la MISMA función y la MISMA fuente que
	// usan el pipeline y la sombra — el mismo secreto debe producir la misma
	// huella venga por el camino que venga. El ancla solo entra al hash, así
	// que nada del contenido viaja a ninguna parte.
	finding.AsignarHuellas(secretFindings, finding.FuenteDeArchivos(analysisRoot))
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
		if cfg != nil {
			if err := persistRun(repoRoot, cfg, res, pipeline.Finalizar(res, "", nil), len(diff.Files), false, store.NewULID()); err != nil {
				// Telemetría, no compuerta: el veredicto ya está tomado y no cambia
				// porque la base falle. Se avisa y se bloquea igual.
				fmt.Fprintln(os.Stderr, "CodeGuard  aviso: no se pudo registrar el bloqueo:", err)
			}
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
		salir(1)
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
	if errConfig != nil {
		progress("config ilegible: " + unaSolaLinea(errConfig.Error()))
		progress("la compuerta de secretos sí corrió; el análisis de calidad se omite y se permite el commit")
		return nil
	}
	if cfg == nil {
		return nil // hook residual en un repo que no está enrolado en este índice
	}
	if errInstantanea != nil {
		progress("análisis de calidad omitido: no se pudo demostrar que los motores leerían el índice")
		progress("se permite el commit, pero CodeGuard no afirma que esté limpio")
		return nil
	}

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
		RunID:            runID,
		RepoRoot:         repoRoot,
		AnalysisRoot:     analysisRoot,
		AnalysisDegraded: degradacionesInstantanea,
		RepoID:           store.RepoIDDe(repoRoot, gitRemote(repoRoot)),
		Branch:           gitBranch(repoRoot),
		StagedFiles:      diff.Files,
		DiffUnified:      diff.Unified,
		DiffLines:        diff.Lines,
		RulepackVersion:  cfg.Rulepack,
		ConfigHash:       cfg.Hash,
		AIGenerated:      aiGenerated,
		DeadlineMs:       int(hookDeadline.Milliseconds()),
	}
	var res *pipeline.Result
	var outcome pipeline.AnalysisOutcome
	degraded := []string{}
	resp, err := ipc.Call(req, hookDeadline)
	// Un rechazo ESTRUCTURADO del daemon (protocolo incompatible, [13]) no es
	// una respuesta de análisis: se dice y se cae a la ruta local — el mismo
	// camino honesto de daemon:offline, con su propia etiqueta porque el
	// remedio es otro (actualizar el binario que quedó atrás, no arrancar el
	// agente). Exenta en garantia.go: es despliegue mixto, no cobertura rota.
	if err == nil && resp.Verdict == "error" {
		progress("el agente rechazó la conexión: " + unaSolaLinea(resp.Reason))
		err = errors.New("daemon incompatible")
		degraded = append(degraded, "daemon:incompatible")
	}
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
			// Capas y Suppressed viajaban por el cable y ESTA reconstrucción
			// los tiraba: por la ruta del daemon —la de todos los días— la BD
			// nunca los veía. Ensamblar completo cuesta dos líneas.
			Suppressed: resp.Suppressed,
			Capas:      resp.Capas,
		}
		// La identidad del rulepack también viajaba ya por el cable (daemon
		// nuevo); un daemon viejo la deja nil y el Result queda sin identidad —
		// legacy explícito, jamás se re-infiere aquí.
		if resp.Rulepack != nil {
			res.Rulepack = *resp.Rulepack
		}
		if resp.Outcome != nil {
			// El veredicto llega YA derivado del daemon; aquí solo se ensambla
			// con los datos del Response (ipc.AOutcome). El hook no re-deriva.
			outcome = resp.Outcome.AOutcome(resp)
		} else {
			// Daemon de una versión anterior: el cable no trae outcome. Se
			// deriva con LA MISMA función canónica sobre lo reconstruido —no
			// con un criterio propio— y se dice que la precisión es la del
			// formato antiguo: un "skipped" de un daemon viejo puede ser un
			// fallo disfrazado (daemon.go lo hacía) y este hook no puede
			// distinguirlo (condición de Kimi, turno 64).
			outcome = pipeline.Finalizar(res, "", nil)
			progress("aviso: el agente responde en el formato antiguo del veredicto — reinícialo para el veredicto tipado")
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
		if len(degraded) == 0 {
			// Solo si no hay ya una etiqueta más precisa (daemon:incompatible).
			degraded = append(degraded, "daemon:offline")
		}
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
			cache, cerrarCache := abrirCache(repoRoot, analysisRoot, cfg)
			defer cerrarCache()
			// La ruta local no pasa por el daemon, así que el aviso de reglas
			// vendoreadas se da aquí: si no, por este camino se aplicarían las
			// reglas del repo sin que nadie lo dijera.
			rulepackID, rulepackErr := rulepack.Resolver(analysisRoot, cfg.Rulepack)
			if rulepackID.Source == rulepack.SourceVendored && rulepackErr == nil {
				progress("aviso: las reglas salieron del rulepack vendoreado en este repo " +
					"(rulepacks/" + unaSolaLinea(cfg.Rulepack) + "), no del instalado")
			}
			if rulepackErr != nil && !errors.Is(rulepackErr, rulepack.ErrNoEncontrado) {
				// Presente pero sin identidad verificable: se dice (la tanda c
				// de W3 lo volverá rechazo cuando la firma exista).
				progress("aviso: " + unaSolaLinea(rulepackErr.Error()))
			}
			return pipeline.Run(ctx, pipeline.Options{
				Config:          cfg,
				Diff:            diff,
				AnalysisRoot:    analysisRoot,
				InitialDegraded: degradacionesInstantanea,
				Secrets:         nil, // ya corrió arriba
				Engines:         daemon.Engines(cfg, false, cache),
				Rulepack:        rulepackID.Path,
				RulepackID:      rulepackID,
				Timeout:         hookDeadline,
				Suppressions:    baseline.LoadOrWarn(analysisRoot),
			})
		}()
		if err != nil {
			progress("análisis local falló (se permite el commit): " + err.Error())
			return nil
		}
		res.Degraded = append(res.Degraded, degraded...)
		outcome = pipeline.Finalizar(res, "", nil)
	}

	// ── Veredicto en la terminal (§12.1.1) ──
	bloquea := imprimirVeredictoTerminal(outcome, res.Findings, start)
	if err := persistRun(repoRoot, cfg, res, outcome, len(diff.Files), false, runID); err != nil {
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
		salir(1)
	}
	return nil
}
