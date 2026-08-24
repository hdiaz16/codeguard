package shadow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"codeguard/internal/config"
	"codeguard/internal/finding"
	"codeguard/internal/ipc"
	"codeguard/internal/llm"
	"codeguard/internal/store"
	"codeguard/internal/textutil"
)

type Runner struct {
	Store *store.Store
	// OnThinking recibe fragmentos del razonamiento del modelo en vivo para
	// mostrarlos en la UI. pillar=="" y text=="" señala que la sombra terminó.
	// Las llamadas se serializan con muThinking: quien lo reciba NO necesita
	// ser seguro para uso concurrente.
	OnThinking func(pillar, text string)
	// muThinking serializa OnThinking: los pilares corren en paralelo y sin él
	// la UI recibiría llamadas simultáneas de las tres goroutines. Va en el
	// struct y no dentro de Run para cubrir también Runs concurrentes.
	muThinking sync.Mutex
}

// Run ejecuta la sombra completa para una petición ya respondida al hook.
// anotarRiesgo escribe risk_score y llm_used en el run, y si no se pudo, LO
// DICE.
//
// Los cinco sitios que llaman aquí hacían `_ = r.Store.UpdateRunLLM(...)`,
// tirando incluso el nil. Y debajo de ese descarte había un fallo real: el run
// lo persiste el proceso del hook, y si la sombra llegaba antes, el UPDATE no
// tocaba ninguna fila —que en database/sql no es error— y el riesgo se perdía
// sin dejar rastro. Ahora el store distingue ese caso con ErrRunNoExiste y aquí
// se registra con el runID por delante: risk_score no se lee en ninguna
// pantalla, su único consumidor es la telemetría central, así que un log es
// literalmente la única forma de enterarse de que faltó.
func (r *Runner) anotarRiesgo(runID string, risk int, llmUsed bool) {
	if err := r.Store.UpdateRunLLM(runID, risk, llmUsed); err != nil {
		log.Printf("sombra: no se pudo anotar el riesgo del run %s (risk=%d llm=%v): %v",
			runID, risk, llmUsed, err)
	}
}

func (r *Runner) Run(ctx context.Context, cfg *config.Config, req *ipc.Request, deterministic []finding.Finding) {
	client := llm.New(cfg.LLM)
	risk := RiskScore(cfg, req)

	// ── Etapa 4: decisión de presupuesto ──
	switch {
	case client == nil:
		log.Println("sombra: sin endpoint/API key — capa LLM apagada")
		r.anotarRiesgo(req.RunID, risk, false)
		return
	case risk < cfg.Risk.Threshold:
		log.Printf("sombra: riesgo %d < umbral %d — sin LLM", risk, cfg.Risk.Threshold)
		r.anotarRiesgo(req.RunID, risk, false)
		return
	}

	// ── Tope de presupuesto mensual ──
	// Apagar la capa LLM no afecta al veredicto (P2: el modelo nunca bloquea),
	// así que quedarse sin presupuesto degrada el análisis, no lo detiene.
	if cfg.LLM.MonthlyBudgetUSD > 0 {
		gastado, err := r.Store.GastoDelMesUSD()
		switch {
		case err != nil:
			log.Printf("sombra: no se pudo leer el gasto del mes (%v) — se continúa", err)
		case gastado >= cfg.LLM.MonthlyBudgetUSD:
			log.Printf("sombra: presupuesto del mes agotado (%.2f de %.2f USD) — capa LLM apagada hasta el día 1",
				gastado, cfg.LLM.MonthlyBudgetUSD)
			_ = r.Store.SaveLLMCall(store.LLMCall{RunID: req.RunID, Pillar: "todos", Status: "skipped"})
			r.anotarRiesgo(req.RunID, risk, false)
			return
		}
		if _, hayTarifas := cfg.LLM.CostoMicros(config.ConsumoTokens{PromptTokens: 1, CompletionTokens: 1}); !hayTarifas {
			log.Println("sombra: monthly_budget_usd configurado pero sin price_in_per_mtok/price_out_per_mtok: " +
				"el gasto no se puede calcular y el tope no se aplicará")
		}
	}
	diffSHA := sha256hex(req.DiffUnified)
	// La clave del caché lleva los modelos que REALMENTE analizan el diff, no
	// cfg.LLM.Model: con modelos por pilar, dos repartos distintos colisionaban
	// en la misma clave y cambiar el modelo de un pilar no invalidaba la
	// entrada — se servían hallazgos del modelo viejo como si fueran del nuevo.
	// Y lleva la VERSIÓN del verificador (claveDelCache): un verify() que
	// aprende a rechazar más no puede seguir sirviendo lo que aprobó su versión
	// anterior con cara de acierto.
	modeloCache := claveDelCache(cfg)
	if cacheado, hit := r.Store.DiffCacheGet(req.RepoID, diffSHA, req.RulepackVersion, req.ConfigHash, modeloCache); hit {
		var entrada sombraCacheada
		if err := json.Unmarshal([]byte(cacheado), &entrada); err != nil ||
			entrada.Version != versionVerificador || len(entrada.Crudas) == 0 {
			// Entrada corrupta o de otra versión del formato: NO se sirve un
			// vacío con cara de acierto. Se cae al análisis real.
			log.Printf("sombra: entrada de caché ilegible o de otro formato — se repite el análisis")
		} else {
			// EL ACIERTO TAMBIÉN SE VERIFICA, con EL MISMO verify() de la
			// etapa 6 — jamás un juego de chequeos reducido, que sería el
			// segundo criterio del que este refactor viene huyendo. Por eso el
			// caché guarda las respuestas CRUDAS del modelo y no los hallazgos
			// ya verificados: la confianza, la línea citada y el archivo se
			// re-juzgan contra el MUNDO DE HOY (el worktree pudo cambiar desde
			// que se cacheó: una línea que existía puede ya no existir) y
			// contra el verificador de hoy. Una entrada envenenada que cite un
			// archivo fuera del diff muere aquí, no en el informe.
			//
			// llm_used va en true porque los hallazgos SON de una llamada al
			// modelo —hecha antes, pero hecha—; el gasto no se falsea (vive en
			// llm_calls.cost_micros y ahí no se añade ninguna fila), y por lo
			// mismo tampoco se añaden filas de llamadas: verificar es local.
			var verificados []finding.Finding
			rechazados := 0
			for _, pillar := range pilaresEnOrden() {
				crudo, ok := entrada.Crudas[string(pillar)]
				if !ok {
					continue
				}
				fs, rej := verify(req, pillar, crudo, deterministic)
				verificados = append(verificados, fs...)
				rechazados += rej
			}
			// La identidad se asigna al conjunto (los tres pilares juntos):
			// la regla de ambigüedad no funciona por partes.
			finding.AsignarHuellas(verificados, finding.FuenteDeArchivos(req.RepoRoot))
			log.Printf("sombra: diff en caché — %d hallazgo(s) re-verificados y registrados sin llamadas (%d rechazado(s) por el verificador de hoy)",
				len(verificados), rechazados)
			if err := r.Store.SaveLLMFindings(req.RunID, verificados); err != nil {
				log.Println("sombra: no se pudieron guardar los hallazgos cacheados:", err)
			}
			r.anotarRiesgo(req.RunID, risk, true)
			return
		}
	}
	r.anotarRiesgo(req.RunID, risk, true)

	// Contexto común: diff REDACTADO (P5 — nada que parezca credencial sale
	// a la red) y truncado por presupuesto, + lo ya encontrado.
	diff := Redact(req.DiffUnified)
	if maxChars := cfg.LLM.MaxDiffTokens * 4; len(diff) > maxChars {
		diff = textutil.TruncarRunas(diff, maxChars) + "\n[diff truncado por presupuesto]"
	}
	var detList strings.Builder
	for _, f := range deterministic {
		fmt.Fprintf(&detList, "- %s %s:%d %s\n", f.RuleKey, f.File, f.Line, f.Message)
	}

	// ── Etapa 5: fan-out concurrente, un prompt por pilar ──
	timeout := plazoSombra(cfg)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var verified []finding.Finding
	// Lo que se cachea son las respuestas CRUDAS por pilar, no los hallazgos
	// verificados: el acierto futuro re-verifica con el verify() de su día.
	crudas := map[string]string{}
	// completo se pone en falso si CUALQUIER pilar no llegó a responder. De él
	// depende que el resultado se pueda cachear (ver el final de esta función).
	completo := true

	for pillar, scope := range pillarScope {
		wg.Add(1)
		go func(pillar finding.Pillar, scope string) {
			defer wg.Done()
			model := cfg.LLM.ModelFor(string(pillar))
			user := fmt.Sprintf("%s\n\nHallazgos deterministas ya reportados (NO repetir):\n%s\nDiff a analizar:\n```\n%s\n```", scope, detList.String(), diff)

			call := store.LLMCall{RunID: req.RunID, Pillar: string(pillar), Model: model}
			var onDelta func(kind, text string)
			if r.OnThinking != nil {
				onDelta = func(kind, text string) {
					if kind == "reasoning" {
						r.muThinking.Lock()
						r.OnThinking(string(pillar), text)
						r.muThinking.Unlock()
					}
				}
			}
			res, err := client.CompleteStream(ctx, model, systemPrompt, user, timeout, techoSombra, onDelta)
			if err != nil {
				call.Status = "error"
				if ctx.Err() != nil || strings.Contains(err.Error(), "deadline") {
					call.Status = "timeout"
				}
				log.Printf("sombra %s: %v", pillar, err)
				_ = r.Store.SaveLLMCall(call)
				mu.Lock()
				completo = false
				mu.Unlock()
				return
			}
			call.Status = "ok"
			call.PromptTokens = res.Usage.PromptTokens
			call.CompletionTokens = res.Usage.CompletionTokens
			call.LatencyMs = res.LatencyMs
			call.CostMicros, _ = cfg.LLM.CostoMicros(config.ConsumoTokens{
				PromptTokens:        res.Usage.PromptTokens,
				CompletionTokens:    res.Usage.CompletionTokens,
				CacheReadTokens:     res.Usage.CacheReadTokens,
				CacheCreationTokens: res.Usage.CacheCreationTokens,
			})

			// ── Etapa 6: verificación determinista de cada hallazgo ──
			ok, rejected := verify(req, pillar, res.Content, deterministic)
			call.FindingsReturned = len(ok) + rejected
			call.FindingsRejected = rejected
			_ = r.Store.SaveLLMCall(call)

			mu.Lock()
			verified = append(verified, ok...)
			crudas[string(pillar)] = res.Content
			mu.Unlock()
		}(pillar, scope)
	}
	wg.Wait()
	if r.OnThinking != nil {
		// Bajo el mismo candado, por si hay Runs concurrentes en este Runner.
		r.muThinking.Lock()
		r.OnThinking("", "") // señal de fin: la UI apaga el hilo de pensamiento
		r.muThinking.Unlock()
	}

	// La identidad se asigna UNA vez sobre el conjunto de los tres pilares
	// (finding.AsignarHuellas): un parser no puede aplicar la regla de
	// ambigüedad porque no ve a los demás.
	finding.AsignarHuellas(verified, finding.FuenteDeArchivos(req.RepoRoot))
	// Los hallazgos que SÍ se obtuvieron se guardan siempre: son reales aunque
	// otro pilar se haya caído.
	if err := r.Store.SaveLLMFindings(req.RunID, verified); err != nil {
		log.Println("sombra: no se pudieron guardar hallazgos:", err)
	}
	// El caché, en cambio, sólo se escribe si los tres pilares respondieron.
	//
	// Antes se escribía siempre, y eso convertía un fallo pasajero en permanente:
	// un pilar que se cae por plazo dejaba un resultado PARCIAL cacheado por el
	// sha del diff, y la siguiente vez que apareciera ese mismo diff el caché
	// acertaría y ya nunca se volvería a preguntar. Es la misma trampa que el
	// caché de semgrep evita al no guardar cuando hay reglas rotas: un resultado
	// incompleto con cara de acierto es peor que no tener caché.
	if completo {
		if payload, err := json.Marshal(sombraCacheada{Version: versionVerificador, Crudas: crudas}); err == nil {
			_ = r.Store.DiffCachePut(req.RepoID, diffSHA, req.RulepackVersion, req.ConfigHash, modeloCache, string(payload))
		}
		log.Printf("sombra: %d hallazgos verificados registrados (shown=0)", len(verified))
	} else {
		log.Printf("sombra: %d hallazgos verificados registrados (shown=0); sin cachear porque no todos los pilares respondieron",
			len(verified))
	}
}

// plazoSombra devuelve el plazo de una llamada de la sombra, con un piso de un
// minuto.
//
// timeout_ms lo pensó alguien para una espera INTERACTIVA (la pantalla de
// configuración prueba la conexión y ahí 20 s es una eternidad razonable). La
// sombra es lo contrario: corre DESPUÉS de responder al hook, desligada del
// commit, y nadie la está esperando. Cortarla a los 20 s tira una llamada que
// ya se pagó en tokens por ahorrar una espera que nadie sufre.
//
// El número sale de medir: seis pruebas contra el Azure real dieron 2.5-3.0 s
// en cinco y 23.4 s en una —el atípico cayó justo mientras el instalador, el
// arranque del daemon y el precalentado de semgrep competían por la máquina—.
// O sea que la cola de latencia llega a diez veces la mediana, y un plazo de
// 20 s la corta. Un minuto la cubre con margen sin dejar una llamada colgada
// para siempre.
// El piso subió de 1 a 3 minutos el día que se le dio techo de salida real a
// los modelos razonadores (ver techoSombra): FW-Kimi-K3 emite ~75 tokens/s
// (medido: 2 383 tokens en 31,7 s), así que un pilar que aproveche el techo
// tarda 2-3 minutos. Con el piso de un minuto, subir el techo sólo habría
// movido el fallo de "truncada" a "timeout". Nadie espera a la sombra: el
// commit ya se respondió.
func plazoSombra(cfg *config.Config) time.Duration {
	plazo := time.Duration(cfg.LLM.TimeoutMs) * time.Millisecond
	if minimo := 3 * time.Minute; plazo < minimo {
		return minimo
	}
	return plazo
}

// techoSombra es el máximo de tokens de SALIDA por pilar.
//
// Con el default del cliente (4000) el pilar de calidad fallaba SIEMPRE con
// modelos razonadores: el razonamiento consume del mismo presupuesto que la
// respuesta, y el JSON llegaba cortado. Medido con FW-Kimi-K3 el día que se
// verificó la integración: data cupo con 1 942 tokens, security con 2 383, y
// quality reventó el techo — "respuesta truncada por max_tokens (4000)".
//
// La consecuencia no era sólo perder un pilar: sin los TRES pilares el
// resultado no se cachea (a propósito — un parcial cacheado se vuelve
// permanente), así que cada commit del mismo diff volvía a pagar las tres
// llamadas. Un pilar truncado convertía el caché en decorado.
//
// 16000 da holgura de sobra para el razonamiento más el JSON; el costo por
// token de salida sólo se paga por lo que el modelo emite de verdad.
const techoSombra = 16000

// versionVerificador es la versión del CONTRATO de verificación de la sombra
// y entra en la clave del caché de diffs (claveDelCache). Sube cuando cambie
// lo que verify() acepta o rechaza, o el formato de lo cacheado.
//
// v1 (implícita, sin número): el caché guardaba los hallazgos YA verificados y
// el acierto los re-registraba sin mirarlos — un verify() que aprendiera a
// rechazar más seguía sirviendo lo que aprobó su versión anterior, y una
// entrada envenenada en la BD llegaba al informe sin pasar por ninguna
// aduana (plan W1, aceptación: «hallazgo fuera-de-diff inyectado en caché LLM
// no se registra»).
//
// v2: se cachean las respuestas CRUDAS por pilar (sombraCacheada) y el acierto
// re-verifica SIEMPRE con el mismo verify() de la etapa 6. Las entradas v1
// quedan huérfanas por la clave nueva y expiran solas.
const versionVerificador = 2

// sombraCacheada es lo que vive en el diff_cache: las respuestas íntegras del
// modelo, pilar por pilar. Los hallazgos NO se cachean a propósito — se
// derivan en cada acierto, contra el worktree y el verificador de ese día.
type sombraCacheada struct {
	Version int               `json:"version"`
	Crudas  map[string]string `json:"crudas"`
}

// claveDelCache compone el componente de modelo de la clave del caché:
// verificador + reparto real de modelos. Es LA función de ambos lados (Get,
// Put y las pruebas): compuesta a mano en dos sitios, el día que uno cambiara
// el otro serviría entradas de otro contrato.
func claveDelCache(cfg *config.Config) string {
	return fmt.Sprintf("verificador:v%d|%s", versionVerificador, modelosPorPilar(cfg))
}

// pilaresEnOrden devuelve los pilares en orden fijo: el mapa no garantiza
// orden de iteración y los logs y pruebas agradecen el determinismo.
func pilaresEnOrden() []finding.Pillar {
	claves := make([]string, 0, len(pillarScope))
	for p := range pillarScope {
		claves = append(claves, string(p))
	}
	sort.Strings(claves)
	out := make([]finding.Pillar, 0, len(claves))
	for _, c := range claves {
		out = append(out, finding.Pillar(c))
	}
	return out
}

// modelosPorPilar resuelve el modelo efectivo de cada pilar y los concatena en
// orden fijo (el mapa de pilares no garantiza orden de iteración), para que la
// clave del caché de diffs refleje el reparto real de modelos.
func modelosPorPilar(cfg *config.Config) string {
	pilares := make([]string, 0, len(pillarScope))
	for p := range pillarScope {
		pilares = append(pilares, string(p))
	}
	sort.Strings(pilares)
	var sb strings.Builder
	for _, p := range pilares {
		fmt.Fprintf(&sb, "%s=%s;", p, cfg.LLM.ModelFor(p))
	}
	return sb.String()
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(strings.ReplaceAll(s, "\r\n", "\n")))
	return hex.EncodeToString(sum[:])
}
