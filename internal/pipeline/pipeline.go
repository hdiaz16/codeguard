// Package pipeline orquesta las etapas del embudo (sección 5).
// Fase 1: etapas 0 (elegibilidad), 1 (secretos), 2 (deterministas) y 7 (consolidación).
package pipeline

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"codeguard/internal/engines"
	"codeguard/internal/engines/gitleaks"
	"codeguard/internal/engines/semgrep"
	"codeguard/internal/finding"
)

// Run ejecuta el embudo determinista y devuelve el resultado consolidado.
func Run(ctx context.Context, opt Options) (*Result, error) {
	start := time.Now()
	res := &Result{Verdict: Pass, Degraded: []string{}}
	defer func() { res.ElapsedMs = time.Since(start).Milliseconds() }()

	// ── Etapa 0: elegibilidad ────────────────────────────────────────────
	if opt.Config == nil {
		res.Verdict, res.Reason = Skipped, MotivoNoEnrolado
		return res, nil
	}
	// Sin diff no hay nada que mirar, y eso es un análisis que se salta, no un
	// pánico. La comprobación va junto a la de Config porque el contrato de
	// Options era asimétrico: toleraba un Config ausente con un veredicto
	// controlado y daba por hecho el diff, aunque el tipo permite que falte.
	// El estado inválido seguía siendo representable y esta es la etapa donde
	// se decide la elegibilidad; dejarlo a la suerte de que los cinco
	// llamadores de hoy nunca manden nil es un invariante que nadie impone.
	if opt.Diff == nil {
		res.Verdict, res.Reason = Skipped, MotivoSinDiff
		return res, nil
	}
	if opt.IsMerge || opt.IsRevert {
		res.Verdict, res.Reason = Skipped, MotivoMergeORevert
		return res, nil
	}
	files, patronesInvalidos := filterExcluded(opt.Config, opt.Diff.Files)
	// Un patrón que no compila NO se descarta en silencio: el equipo cree que
	// esa ruta está excluida y no lo está. Se nombra en Degraded para que el
	// typo en config.yaml sea visible en el veredicto, no un agujero mudo.
	for _, p := range patronesInvalidos {
		res.Degraded = append(res.Degraded, "patron-invalido:"+p)
	}
	// Sin archivos que pasarles, la etapa 2 no tiene trabajo. La etapa 1 SÍ, y
	// ahí estaba N005: esta lista es el diff de ÁRBOLES entre base y head
	// filtrado por paths.exclude, y la compuerta de secretos no la lee nunca —
	// escanea el HISTORIAL del rango con --log-opts, o el índice entero con
	// --staged. Dos conjuntos distintos, y el pequeño decidía por el grande.
	//
	// Lo que dejaba pasar, medido contra gitleaks 8.30.0:
	//
	//	c1 → c2 añade creds.go con un PAT → c3 lo borra
	//	git diff c1..c3            → vacío (los árboles coinciden)
	//	gitleaks --log-opts c1..c3 → leaks found: 1
	//	codeguard ci               → "análisis omitido", EXIT 0
	//
	// Y no hace falta un atacante: es el flujo de quien commitea una credencial,
	// se da cuenta y la quita en el commit siguiente creyendo que ya está. El
	// secreto se queda en el historial, que es contra lo que existe un escáner
	// por historial.
	//
	// El otro camino era el mismo agujero con otra llave: el secreto en una ruta
	// que paths.exclude tapa. Esa lista sirve para no pasarle vendor/ ni los .log
	// al analizador de estilo; la compuerta de secretos ya la ignora cuando corre
	// —el motor no mira in.Files—, así que el sistema era incoherente consigo
	// mismo: el MISMO secreto en el MISMO bin/config.txt bloqueaba si venía
	// acompañado de un archivo no excluido y pasaba si venía solo.
	//
	// Con Secrets nil la compuerta ya corrió fuera (el hook, fase 1) y esta
	// salida sigue siendo la de siempre: allí el conjunto del diff SÍ es el que
	// mira la compuerta, y ese camino corre en cada commit.
	sinArchivosQueAnalizar := len(files) == 0
	if sinArchivosQueAnalizar && opt.Secrets == nil {
		res.Verdict, res.Reason = Skipped, MotivoTodoExcluido
		return res, nil
	}
	degradeToSecretsOnly := opt.Diff.Lines > opt.Config.MaxDiffLines

	if opt.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opt.Timeout)
		defer cancel()
	}

	in := engines.Input{
		RepoRoot:    opt.Config.RepoRoot,
		Files:       files,
		RulepackDir: opt.Rulepack,
	}

	// ── Etapa 1: secretos (BLOQUEANTE, fail-closed) ──────────────────────
	// Secrets es nil cuando la etapa ya corrió en el proceso del hook (§5).
	if opt.Secrets != nil {
		secretFindings, err := opt.Secrets.Run(ctx, in)
		if err != nil {
			// CUALQUIER error de la etapa 1 bloquea, y se resuelve AQUÍ, en la
			// compuerta — no se delega al llamador con `return nil, err`
			// (sección 14: la promesa no es «busqué», es «nada sale sin
			// escanear»). Antes sólo ErrUnavailable cerraba y el resto salía
			// como error pelado: un timeout del ctx —este camino corre con
			// opt.Timeout— dejaba el veredicto en manos de cada llamador, y
			// basta que uno lo degrade para que la única compuerta bloqueante
			// del producto se vuelva optativa. Con el Block dentro, el cierre
			// viaja en el Result y ningún consumidor tiene que acordarse.
			res.Verdict = Block
			switch {
			case errors.Is(err, gitleaks.ErrUnavailable):
				res.Reason = fmt.Sprintf("la compuerta de secretos no pudo correr (fail-closed): %v", err)
			case errors.Is(err, context.DeadlineExceeded):
				res.Reason = fmt.Sprintf("la compuerta de secretos no terminó dentro de su plazo (fail-closed): %v", err)
			default:
				res.Reason = fmt.Sprintf("la compuerta de secretos falló al ejecutarse (fail-closed): %v", err)
			}
			return res, nil
		}
		res.Findings = append(res.Findings, secretFindings...)
	}

	// ── Etapa 2: compuertas deterministas en paralelo ────────────────────
	//
	// El estado por motor se lleva FUERA del switch porque las tres ramas
	// dejan capas sin correr y las tres tienen que poder decirlo: el panel
	// enumera esta lista para afirmar "esto te vigila", y una capa que no
	// aparezca en ella es una capa que el dev cree que no existe.
	aplica := make([]bool, len(opt.Engines))
	duracion := make([]int64, len(opt.Engines))
	failures := make([]error, len(opt.Engines))
	hallazgos := make([]int, len(opt.Engines))
	// motivoSinCorrer: por qué NINGÚN motor corrió, cuando es el caso.
	motivoSinCorrer := ""

	// Quién va a mirar se decide ANTES de lanzar a nadie, porque el denominador
	// del progreso ("3 de 9") tiene que existir desde el primer instante. Se
	// calcula sólo en el camino donde los motores de verdad corren: en los otros
	// dos, `aplica` tiene que quedarse en falso entero o la clasificación final
	// llamaría "corrio" a capas que nadie ejecutó.
	corren := 0
	if !sinArchivosQueAnalizar && !degradeToSecretsOnly {
		for i, eng := range opt.Engines {
			if aplica[i] = eng.Applies(in); aplica[i] {
				corren++
			}
		}
	}
	// El aviso de apertura sale también con cero: "ninguna capa aplica a este
	// cambio" es información, y callarla dejaría al orbe contando hacia un total
	// que nunca llega.
	avisos := &avisador{fn: opt.Progreso}
	avisos.abrir(corren)

	switch {
	case sinArchivosQueAnalizar:
		// Nada que degradar: no es que las deterministas se saltaran su trabajo,
		// es que no había ninguno. Marcarlo como degradación pintaría de naranja
		// cada run de un repo que excluya vendor/** y arruinaría la señal justo
		// donde importa —"degradado" tiene que significar que algo NO se miró
		// pudiendo mirarse—. El veredicto queda en el que dejó la etapa 1, que es
		// la única que sí tenía qué mirar.
		motivoSinCorrer = "no había archivos que analizar en este cambio"
	case degradeToSecretsOnly:
		res.Degraded = append(res.Degraded, "deterministic:diff_too_large")
		motivoSinCorrer = "el diff es demasiado grande: sólo se revisaron secretos"
	default:
		g, gctx := errgroup.WithContext(ctx)
		results := make([][]finding.Finding, len(opt.Engines))
		for i, eng := range opt.Engines {
			if !aplica[i] {
				continue
			}
			g.Go(func() error {
				t0 := time.Now()
				fs, err := eng.Run(gctx, in)
				duracion[i] = time.Since(t0).Milliseconds()
				// El desglose por motor es la única forma de saber quién se
				// come el presupuesto: el total ya lo dice ElapsedMs, pero un
				// total gordo sin desglose obliga a adivinar.
				log.Printf("%s: %d hallazgo(s) en %dms", eng.Name(), len(fs), duracion[i])
				if err != nil {
					failures[i] = err // no bloquea: se degrada (sección 14)
				} else {
					hallazgos[i] = len(fs)
					results[i] = fs
				}
				// El aviso sale DENTRO de la goroutine, no en un repaso al final:
				// un progreso que se publica cuando ya terminó todo no es
				// progreso. Y sale de capaDe, la misma función que construye la
				// lista definitiva unas líneas más abajo, para que el orbe no
				// pueda decir en vivo algo que el panel desmienta al terminar.
				avisos.capa(capaDe(eng.Name(), opt.Config.Rulepack,
					true, failures[i], hallazgos[i], duracion[i], ""))
				return nil
			})
		}
		if err := g.Wait(); err != nil {
			return nil, err
		}
		for i, fs := range results {
			res.Findings = append(res.Findings, fs...)
			if failures[i] == nil {
				continue
			}
			// Un motor NO INSTALADO es un asunto de configuración, no una
			// degradación del análisis: se informa distinto para que un trivy
			// ausente no pinte de naranja cada commit del día.
			if errors.Is(failures[i], semgrep.ErrSinRulepack) {
				// Sin rulepack no hay paridad con el CI, que es la promesa
				// central: se nombra aparte para poder decirlo con claridad.
				res.Degraded = append(res.Degraded, "rulepack-ausente:"+opt.Config.Rulepack)
			} else if isMissingBinary(failures[i]) {
				res.Degraded = append(res.Degraded, "falta:"+opt.Engines[i].Name())
			} else if errors.Is(failures[i], context.DeadlineExceeded) {
				// "No terminó a tiempo" no es "falló". Un motor que se pasa del
				// presupuesto en su primera corrida en frío —staticcheck compila
				// el módulo, eslint arranca node— vuelve a entrar en cuanto el
				// caché está caliente, y decirle "error" al desarrollador lo
				// manda a buscar una avería que no existe. Pasó tras una
				// instalación limpia: staticcheck y eslint aparecieron como
				// error y en la corrida siguiente tardaron 502 ms y 610 ms.
				log.Printf("%s no cupo en el plazo: %v", opt.Engines[i].Name(), failures[i])
				res.Degraded = append(res.Degraded, opt.Engines[i].Name()+":plazo")
			} else {
				// La etiqueta corta viaja al veredicto; el PORQUÉ va al log.
				// Antes el mensaje del motor se tiraba aquí mismo y diagnosticar
				// un "semgrep:error" exigía reproducirlo a mano con suerte.
				log.Printf("%s degradado: %v", opt.Engines[i].Name(), failures[i])
				res.Degraded = append(res.Degraded, opt.Engines[i].Name()+":error")
			}
		}

		// Un motor que "no aplica" se salta en silencio, y casi siempre está
		// bien: sin archivos Go no hay nada que formatear. Pero squawk no
		// aplica por dos motivos que se ven idénticos desde fuera —no hay
		// migraciones en el commit, o las hay y `paths.migrations` no las
		// cubre— y el segundo es un agujero en la compuerta que se anuncia
		// exactamente igual que la normalidad: no diciendo nada.
		//
		// Va aquí y no en `init` porque `init` sólo arregla los repos que
		// nazcan de ahora en adelante. Los ya enrolados —y los que añadan una
		// carpeta de migraciones después— sólo se enteran si el análisis lo
		// dice el día que ocurre.
		if etiqueta := migracionSinVigilar(opt.Config, files); etiqueta != "" {
			res.Degraded = append(res.Degraded, etiqueta)
		}
	}

	// El estado de TODAS las capas, incluidas las que no corrieron. Lo consume
	// la cabecera del panel ("qué motores te vigilan") y por eso se construye
	// aquí y no en la UI: si cada superficie lo dedujera de Degraded, cada una
	// llegaría a una conclusión distinta sobre lo mismo.
	for i, eng := range opt.Engines {
		res.Capas = append(res.Capas, capaDe(eng.Name(), opt.Config.Rulepack,
			aplica[i], failures[i], hallazgos[i], duracion[i], motivoSinCorrer))
	}

	// ── Etapa 2b: reglas del playbook sobre el repo y el cambio ──────────
	// No dependen de ningún motor externo ni de la red, así que corren
	// siempre, incluso con el diff degradado a solo-secretos.
	res.Findings = append(res.Findings, revisarLockfiles(opt.Config, files)...)
	res.Findings = append(res.Findings, revisarTamano(opt.Diff, files)...)
	res.Findings = append(res.Findings, revisarComplejidad(opt.Config, files)...)

	// ── Auto-calibración: reglas con exceso de falsos positivos (según el
	// feedback del equipo en ESTE repo) bajan a aviso. gitleaks jamás. ────
	if len(opt.DemotedRules) > 0 {
		for i := range res.Findings {
			f := &res.Findings[i]
			if f.Engine != "gitleaks" && f.Blocking && opt.DemotedRules[f.Engine+"/"+f.RuleKey] {
				f.Blocking = false
				f.Severity = finding.Warning
				f.Why = strings.TrimSpace("Regla degradada a aviso por el feedback del equipo (exceso de falsos positivos aquí). " + f.Why)
			}
		}
	}

	// ── Supresiones de baseline: solo lo nuevo bloquea ──────────────────
	if len(opt.Suppressions) > 0 {
		kept := res.Findings[:0]
		for _, f := range res.Findings {
			// La compuerta de secretos no admite baseline: un secreto viejo
			// sigue siendo un secreto vivo.
			if f.Engine != "gitleaks" && opt.Suppressions[f.Fingerprint] {
				res.Suppressed++
				continue
			}
			kept = append(kept, f)
		}
		res.Findings = kept
	}

	// ── Etapa 7: consolidación ───────────────────────────────────────────
	res.Findings = consolidate(res.Findings)
	for _, f := range res.Findings {
		if f.Blocking {
			res.BlockingFindings++
		} else {
			res.AdvisoryFindings++
		}
	}
	if res.BlockingFindings > 0 {
		res.Verdict = Block
	}
	return res, nil
}

// capaDe clasifica UNA capa: qué le pasó al motor y cómo se le cuenta al dev.
//
// Es el ÚNICO sitio donde se decide, y tiene que serlo porque el mismo veredicto
// se publica DOS VECES: en vivo, en cuanto el motor termina (para el orbe), y en
// Result.Capas cuando terminan todos (para el panel y el historial). Con la
// clasificación escrita a los dos lados, la primera versión que se escribiera
// distinta pondría al orbe diciendo «gofmt revisó» de una capa que el panel
// lista como caída medio segundo después — y el dev no tendría forma de saber
// cuál de las dos superficies le está mintiendo.
//
// motivoSinCorrer sólo aplica al caso NoAplica y por eso el camino en vivo lo
// manda vacío: ahí sólo se anuncian capas que SÍ arrancaron.