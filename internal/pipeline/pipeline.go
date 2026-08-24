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

	"codeguard/internal/confianza"
	"codeguard/internal/engines"
	"codeguard/internal/engines/gitleaks"
	"codeguard/internal/engines/proc"
	"codeguard/internal/engines/semgrep"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
	"codeguard/internal/rulepack"
)

// Run ejecuta el embudo determinista y devuelve el resultado consolidado.
func Run(ctx context.Context, opt Options) (*Result, error) {
	start := time.Now()
	res := &Result{Verdict: Pass, Degraded: []string{}, Rulepack: opt.RulepackID}
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
	// cobertura[i] es el cruce plan-vs-recibos de los motores que la declaran
	// (ConCobertura); nil para los todo-o-nada. Una capa con hueco de cobertura
	// se degrada aunque haya devuelto hallazgos (W6 Q2).
	cobertura := make([]*coberturaResumen, len(opt.Engines))
	// motivoSinCorrer: por qué NINGÚN motor corrió, cuando es el caso.
	motivoSinCorrer := ""

	// Quién va a mirar se decide ANTES de lanzar a nadie, porque el denominador
	// del progreso ("3 de 9") tiene que existir desde el primer instante. Se
	// calcula sólo en el camino donde los motores de verdad corren: en los otros
	// dos, `aplica` tiene que quedarse en falso entero o la clasificación final
	// llamaría "corrio" a capas que nadie ejecutó.
	corren := 0
	if !sinArchivosQueAnalizar && !degradeToSecretsOnly {
		// Guardián de confianza (W4, Q3): si el repo trae config-ejecutable
		// (eslint.config.js, target MSBuild, plugin de mypy, binario del repo)
		// y el usuario no la ha CONFIADO, los motores que la ejecutan NO
		// corren — default seguro. El código del repo hostil tiene acceso
		// fuera del árbol (probado en proc), así que ejecutarlo sin permiso es
		// el hueco; degradarlo con aviso es el cierre. Se confía una vez con
		// `codeguard confiar` (TOFU fuera del repo, atado a repo+digest).
		var nombres []string
		for _, eng := range opt.Engines {
			nombres = append(nombres, eng.Name())
		}
		_, sinConfiar := confianza.MotoresDegradados(opt.Config.RepoRoot, nombres)
		noConfiado := map[string]bool{}
		for _, m := range sinConfiar {
			noConfiado[m] = true
		}
		for i, eng := range opt.Engines {
			if noConfiado[eng.Name()] {
				// No corre, y se DICE: es garantía de cobertura rota (a
				// diferencia del aislamiento degradado, aquí la capa NO miró).
				res.Degraded = append(res.Degraded, "config-ejecutable-no-confiada:"+eng.Name())
				continue
			}
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
		// El colector de contención por motor (W4, t.116): proc.Correr reporta
		// solo qué capas del sandbox se activaron; ningún adaptador tiene que
		// acordarse de propagar nada. Es un canal SEPARADO de failures: el
		// motor corrió y sus hallazgos valen — lo degradado es el AISLAMIENTO,
		// no la cobertura, y mezclarlos enseñaría a ignorar el naranja.
		contenciones := make([]*proc.Recolector, len(opt.Engines))
		for i, eng := range opt.Engines {
			if !aplica[i] {
				continue
			}
			g.Go(func() error {
				ectx, rec := proc.ConRecolector(gctx)
				contenciones[i] = rec
				t0 := time.Now()
				var fs []finding.Finding
				var err error
				// Un motor que declara cobertura (semgrep) corre por el camino que
				// devuelve recibos; el orquestador cruza su plan contra ellos. El
				// resto —todo-o-nada— corre por Run y no carga con recibos.
				if cc, ok := eng.(engines.ConCobertura); ok {
					plan := cc.Plan(in)
					var r engines.Resultado
					r, err = cc.RunConCobertura(ectx, in)
					fs = r.Findings
					if err == nil {
						cobertura[i] = resumirCobertura(plan, r.Recibos)
					}
				} else {
					fs, err = eng.Run(ectx, in)
				}
				duracion[i] = time.Since(t0).Milliseconds()
				// El desglose por motor es la única forma de saber quién se
				// come el presupuesto: el total ya lo dice ElapsedMs, pero un
				// total gordo sin desglose obliga a adivinar.
				//
				// El log mira el err ANTES de contar nada: la versión anterior
				// imprimía una línea antes de esta bifurcación y con
				// ErrSinRulepack salía «semgrep: 0 hallazgo(s) en 0ms» mientras
				// esta misma corrida clasificaba la capa como Degradada — el
				// contador honesto y el mentiroso, medidos en el mismo log
				// (bitácora 2026-08-22). Un motor que falló no tiene conteo que
				// reportar: tiene un fallo que nombrar.
				if err != nil {
					log.Printf("%s: FALLÓ en %dms: %v", eng.Name(), duracion[i], err)
					failures[i] = err // no bloquea: se degrada (sección 14)
				} else {
					log.Printf("%s: %d hallazgo(s) en %dms", eng.Name(), len(fs), duracion[i])
					hallazgos[i] = len(fs)
					results[i] = fs
				}
				// El aviso sale DENTRO de la goroutine, no en un repaso al final:
				// un progreso que se publica cuando ya terminó todo no es
				// progreso. Y sale de capaDe, la misma función que construye la
				// lista definitiva unas líneas más abajo, para que el orbe no
				// pueda decir en vivo algo que el panel desmienta al terminar.
				avisos.capa(capaDe(eng.Name(), opt.Config.Rulepack,
					true, failures[i], hallazgos[i], duracion[i], "", cobertura[i]))
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

		// Cobertura incompleta (W6 Q2): un motor que declaró un plan y no cubrió
		// todo lo prometido dejó un hueco. Va a Degraded —donde SinGarantia lo
		// trata como garantía rota, porque no está exento— aunque haya devuelto
		// hallazgos: el «sin más hallazgos» de lo no mirado no cubre nada. Es un
		// canal SEPARADO de <motor>:error (el motor corrió; lo que falló es la
		// completitud) para que el remedio —excluir el objetivo a propósito o
		// arreglar lo que no se pudo parsear— se lea distinto de «se averió».
		for i := range opt.Engines {
			if cobertura[i].hayHueco() {
				res.Degraded = append(res.Degraded, opt.Engines[i].Name()+":cobertura-parcial")
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

		// El peor caso de contención entre TODOS los motores, deduplicado por
		// faceta. El detalle por motor ya quedó en el log de proc; el veredicto
		// dice QUÉ capa faltó, no la letanía por motor (condición de Kimi,
		// t.110: el ruido por commit enseña a ignorar la degradación).
		vistas := map[string]bool{}
		for _, rec := range contenciones {
			if rec == nil {
				continue
			}
			c, hubo := rec.Resultado()
			if !hubo {
				continue
			}
			for _, faceta := range c.Degradadas() {
				if !vistas[faceta] {
					vistas[faceta] = true
					res.AislamientoDegradado = append(res.AislamientoDegradado, faceta)
				}
			}
		}
	}

	// El estado de TODAS las capas, incluidas las que no corrieron. Lo consume
	// la cabecera del panel ("qué motores te vigilan") y por eso se construye
	// aquí y no en la UI: si cada superficie lo dedujera de Degraded, cada una
	// llegaría a una conclusión distinta sobre lo mismo.
	for i, eng := range opt.Engines {
		res.Capas = append(res.Capas, capaDe(eng.Name(), opt.Config.Rulepack,
			aplica[i], failures[i], hallazgos[i], duracion[i], motivoSinCorrer, cobertura[i]))
	}

	// ── Etapa 2b: reglas del playbook sobre el repo y el cambio ──────────
	// No dependen de ningún motor externo ni de la red, así que corren
	// siempre, incluso con el diff degradado a solo-secretos.
	res.Findings = append(res.Findings, revisarLockfiles(opt.Config, files)...)
	res.Findings = append(res.Findings, revisarTamano(opt.Diff, files)...)
	res.Findings = append(res.Findings, revisarComplejidad(opt.Config, files)...)

	// ── La IDENTIDAD se asigna aquí, UNA vez y para el conjunto entero ────
	// (huellas v2, consejo turnos 71-84). Antes cada parser llamaba a
	// ComputeFingerprint por su cuenta —36 sitios— y la regla de ambigüedad
	// (dos hallazgos indistinguibles ⇒ ninguno se suprime) es imposible de
	// aplicar sin ver el conjunto. Va DESPUÉS de que exista todo hallazgo
	// determinista y ANTES de la supresión, que es la primera consumidora.
	// La fuente lee el mismo disco que leyeron los motores; si el worktree
	// cambió durante el análisis, el aviso del bug #8 (etapa final) lo dice.
	finding.AsignarHuellas(res.Findings, finding.FuenteDeArchivos(opt.Config.RepoRoot))

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
			// sigue siendo un secreto vivo. Y un hallazgo AMBIGUO (otro de
			// esta corrida produjo la misma huella) tampoco se suprime:
			// baselinear uno enterraría al otro en silencio — la falla va
			// hacia bloquear (regla de ambigüedad, turno 83).
			if f.Engine != "gitleaks" && !f.HuellaAmbigua && !f.NoSuprimible && estaSuprimido(opt.Suppressions, &f) {
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

	// ── El worktree pudo cambiar DURANTE el análisis (bug #8, la otra mitad):
	// la huella de cada archivo se leyó en el instante del diff y los motores
	// leyeron el disco después, en el suyo. El caché ya se defiende solo
	// (engines.Cacheable.Vigente descarta la entrada que mentiría); esto cubre
	// el REPORTE de esta corrida, que no se puede corregir re-analizando sin
	// reabrir la misma carrera — pero sí DECIRSE: los hallazgos de esos
	// archivos describen el disco de hace unos segundos, no necesariamente lo
	// que se va a commitear. Un autosave del editor en medio del análisis
	// basta para llegar aquí.
	var cambiados []string
	for _, f := range opt.Diff.Files {
		if f.Status == "D" || f.SHA256 == "" {
			continue
		}
		if gitdiff.SHA256De(opt.Config.RepoRoot, f.Path) != f.SHA256 {
			cambiados = append(cambiados, f.Path)
		}
	}
	if len(cambiados) > 0 {
		res.Degraded = append(res.Degraded, fmt.Sprintf(
			"worktree: %s cambió durante el análisis — los hallazgos de esos archivos describen el contenido de hace unos segundos",
			strings.Join(cambiados, ", ")))
	}

	// ── La MISMA clase de carrera, para las REGLAS (W3, GPT t.103): el digest
	// del rulepack se calculó al resolver y semgrep leyó el directorio después.
	// Si el árbol cambió en medio, este veredicto describe reglas que ya no
	// son las del disco — no se puede corregir sin reabrir la carrera, pero sí
	// DECIRSE, y la identidad estampada deja de prometer un digest que ya no
	// es verdad.
	if opt.RulepackID.Digest != "" {
		if ahora, err := rulepack.DigestArbol(opt.RulepackID.Path); err != nil || ahora != opt.RulepackID.Digest {
			res.Degraded = append(res.Degraded, "rulepack:changed-during-analysis")
			res.Rulepack.Digest = ""
			res.Rulepack.Verified = false
		}
	}
	return res, nil
}

// estaSuprimido consulta el mapa de supresiones con la PAREJA de huellas del
// hallazgo (v2 + legacy v1): la ventana dual de la migración de huellas vive
// en HuellasDeBusqueda y aquí solo se pregunta — cuando la ventana expire,
// apagar v1 es un cambio en el paquete finding, no una cacería por sitios.
func estaSuprimido(supresiones map[string]bool, f *finding.Finding) bool {
	for _, h := range f.HuellasDeBusqueda() {
		if supresiones[h] {
			return true
		}
	}
	return false
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
