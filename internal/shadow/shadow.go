// Package shadow implementa las etapas 3-6 del embudo en modo sombra (fase 3):
// clasificación de riesgo, decisión de presupuesto, fan-out al modelo y
// verificación determinista. Los hallazgos se registran con shown=0 — nunca
// se muestran ni bloquean (P2). Corre en el daemon DESPUÉS de responder al
// hook: la latencia del modelo jamás toca el commit.
package shadow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gobwas/glob"

	"codeguard/internal/config"
	"codeguard/internal/finding"
	"codeguard/internal/ipc"
	"codeguard/internal/llm"
	"codeguard/internal/store"
	"codeguard/internal/textutil"
)

// ── Etapa 3: clasificación de riesgo (heurística, sin ML en v1) ──────────

func matchAny(patterns []string, p string) bool {
	for _, pat := range patterns {
		if g, err := glob.Compile(pat, '/'); err == nil && g.Match(p) {
			return true
		}
	}
	return false
}

var manifests = map[string]bool{
	"package.json": true, "package-lock.json": true, "go.mod": true, "go.sum": true,
	"requirements.txt": true, "pom.xml": true, "pubspec.yaml": true, "pubspec.lock": true,
}

var securityConfigs = map[string]bool{
	"androidmanifest.xml": true, "web.config": true, "appsettings.json": true,
	"dockerfile": true, "docker-compose.yml": true,
}

func RiskScore(cfg *config.Config, req *ipc.Request) int {
	w := cfg.Risk.Weights
	score := 0
	var anyMigration, anySensitive, anyDep, anyQuery, anySecCfg bool
	allTests, allDocs := true, true

	for _, f := range req.StagedFiles {
		p := strings.ToLower(f.Path)
		base := path.Base(p)
		if matchAny(cfg.Paths.Migrations, f.Path) {
			anyMigration = true
		}
		if matchAny(cfg.Paths.Sensitive, f.Path) {
			anySensitive = true
		}
		if manifests[base] || strings.HasSuffix(base, ".csproj") || strings.HasSuffix(base, ".lock") {
			anyDep = true
		}
		if strings.HasSuffix(p, ".sql") {
			anyQuery = true
		}
		if securityConfigs[base] || strings.HasSuffix(p, ".tf") {
			anySecCfg = true
		}
		isTest := strings.Contains(p, "test") || strings.Contains(p, "spec")
		isDoc := strings.HasSuffix(p, ".md") || strings.HasSuffix(p, ".txt")
		if !isTest {
			allTests = false
		}
		if !isDoc {
			allDocs = false
		}
	}
	add := func(key string, cond bool) {
		if cond {
			score += w[key]
		}
	}
	add("touches_migration", anyMigration)
	add("touches_sensitive", anySensitive)
	add("ai_generated", req.AIGenerated)
	add("touches_security_config", anySecCfg)
	add("adds_dependency", anyDep)
	add("touches_query", anyQuery)
	add("many_files", len(req.StagedFiles) > 10)
	add("tests_only", allTests && len(req.StagedFiles) > 0)
	add("docs_only", allDocs && len(req.StagedFiles) > 0)
	if score < 0 {
		return 0
	}
	return score
}

// ── Etapas 4-6 ───────────────────────────────────────────────────────────

const systemPrompt = `Eres un revisor de código senior. Analizas un diff y devuelves SOLO JSON válido con este esquema exacto:
{"findings":[{"file":"ruta relativa exacta tal como aparece en el diff","line":1,"rule_key":"ad-hoc","severity":"info|warning","confidence":0.0,"message":"una frase en español","why":"por qué importa, máximo dos frases, en español","fix_hint":"qué hacer, concreto, en español"}]}
Reglas estrictas:
- Devolver {"findings":[]} es un resultado VÁLIDO y FRECUENTE. No inventes problemas para parecer útil.
- Cita archivo y línea exactos del diff. Todo lo no verificable se descarta.
- NO repitas los hallazgos deterministas que se te entregan: ya fueron reportados.
- confidence entre 0 y 1: tu certeza real de que es un problema.
- Todo el texto para el desarrollador va en español.`

var pillarScope = map[finding.Pillar]string{
	finding.Quality:  "PILAR CALIDAD: nombres que mienten, responsabilidades mezcladas, abstracción incorrecta (¿enum/clase/record?), tests que no verifican nada, comentarios que ya no son ciertos.",
	finding.Security: "PILAR SEGURIDAD: fallas de autorización a nivel de objeto y función (BOLA/BFLA), validación de entrada faltante, manejo de errores que filtra información, configuración insegura.",
	finding.Data:     "PILAR DATOS: N+1, consultas en bucle, transacciones mal delimitadas, PII hacia logs, compatibilidad hacia atrás de esquema en despliegues por fases.",
}

type llmFinding struct {
	File       string  `json:"file"`
	Line       int     `json:"line"`
	RuleKey    string  `json:"rule_key"`
	Severity   string  `json:"severity"`
	Confidence float64 `json:"confidence"`
	Message    string  `json:"message"`
	Why        string  `json:"why"`
	FixHint    string  `json:"fix_hint"`
}

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
	modeloCache := modelosPorPilar(cfg)
	if cacheado, hit := r.Store.DiffCacheGet(req.RepoID, diffSHA, req.RulepackVersion, req.ConfigHash, modeloCache); hit {
		var cacheados []finding.Finding
		if err := json.Unmarshal([]byte(cacheado), &cacheados); err != nil {
			// Entrada corrupta: NO se sirve un vacío con cara de acierto. Se
			// cae al análisis real, como si no hubiera caché.
			log.Printf("sombra: entrada de caché ilegible (%v) — se repite el análisis", err)
		} else {
			// El acierto re-registra los hallazgos en ESTE run: son el
			// resultado del análisis, y la telemetría no debe ver un run vacío.
			// llm_used va en true porque los hallazgos SON de una llamada al
			// modelo —hecha antes, pero hecha—; el gasto no se falsea, porque
			// vive en llm_calls.cost_micros y ahí no se añade ninguna fila.
			log.Printf("sombra: diff en caché — %d hallazgos re-registrados sin llamadas", len(cacheados))
			if err := r.Store.SaveLLMFindings(req.RunID, cacheados); err != nil {
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
		if payload, err := json.Marshal(verified); err == nil {
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

// verify implementa la etapa 6 (anti-alucinación, directo de RADAR).
func verify(req *ipc.Request, pillar finding.Pillar, content string, deterministic []finding.Finding) ([]finding.Finding, int) {
	// Tolerar fences de markdown alrededor del JSON.
	content = strings.TrimSpace(content)
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSuffix(content, "```")

	var parsed struct {
		Findings []llmFinding `json:"findings"`
	}
	if err := json.Unmarshal([]byte(content), &parsed); err != nil {
		log.Printf("sombra %s: JSON ilegible (todo rechazado): %v", pillar, err)
		return nil, 1 // se cuenta como rechazo: señal de calidad del prompt
	}

	inDiff := map[string]bool{}
	for _, f := range req.StagedFiles {
		inDiff[strings.ToLower(f.Path)] = true
	}
	seen := map[string]bool{}
	for _, d := range deterministic {
		seen[fmt.Sprintf("%s|%d", strings.ToLower(d.File), d.Line)] = true
	}

	var ok []finding.Finding
	rejected := 0
	for _, lf := range parsed.Findings {
		file := filepath.ToSlash(strings.TrimSpace(lf.File))
		key := fmt.Sprintf("%s|%d", strings.ToLower(file), lf.Line)
		switch {
		case !inDiff[strings.ToLower(file)]: // ¿el archivo citado está en el diff?
			rejected++
			continue
		case lf.Line < 1 || lf.Line > fileLines(req.RepoRoot, file): // ¿la línea existe?
			rejected++
			continue
		case lf.Confidence < 0.5: // umbral de confianza (§13)
			rejected++
			continue
		case seen[key]: // ¿duplica uno determinista?
			rejected++
			continue
		case lf.Severity != "info" && lf.Severity != "warning": // el modelo no emite errores
			rejected++
			continue
		}
		f := finding.Finding{
			Engine:      "llm",
			RuleKey:     nonEmpty(lf.RuleKey, "ad-hoc"),
			Pillar:      pillar,
			Severity:    finding.Severity(lf.Severity),
			Blocking:    false, // P2: no negociable
			File:        file,
			Line:        lf.Line,
			Message:     lf.Message,
			Why:         lf.Why,
			FixHint:     lf.FixHint,
			Verified:    true,
			Source:      finding.LLM,
			LineContent: lf.Message,
		}
		f.ComputeFingerprint()
		ok = append(ok, f)
	}
	return ok, rejected
}

func fileLines(repoRoot, rel string) int {
	// Confinado al repo (gosec G304): rutas citadas por el modelo no salen de él.
	full := filepath.Clean(filepath.Join(repoRoot, filepath.FromSlash(rel)))
	if !strings.HasPrefix(full, filepath.Clean(repoRoot)+string(filepath.Separator)) {
		return 0
	}
	raw, err := os.ReadFile(full)
	if err != nil {
		return 0
	}
	return strings.Count(string(raw), "\n") + 1
}

func nonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
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
