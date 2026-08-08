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
	"strings"
	"sync"
	"time"

	"github.com/gobwas/glob"

	"codeguard/internal/config"
	"codeguard/internal/finding"
	"codeguard/internal/foundry"
	"codeguard/internal/ipc"
	"codeguard/internal/store"
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
	OnThinking func(pillar, text string)
}

// Run ejecuta la sombra completa para una petición ya respondida al hook.
func (r *Runner) Run(ctx context.Context, cfg *config.Config, req *ipc.Request, deterministic []finding.Finding) {
	client := foundry.New(cfg.LLM)
	risk := RiskScore(cfg, req)

	// ── Etapa 4: decisión de presupuesto ──
	switch {
	case client == nil:
		log.Println("sombra: sin endpoint/API key — capa LLM apagada")
		r.Store.UpdateRunLLM(req.RunID, risk, false)
		return
	case risk < cfg.Risk.Threshold:
		log.Printf("sombra: riesgo %d < umbral %d — sin LLM", risk, cfg.Risk.Threshold)
		r.Store.UpdateRunLLM(req.RunID, risk, false)
		return
	}
	diffSHA := sha256hex(req.DiffUnified)
	if _, hit := r.Store.DiffCacheGet(req.RepoID, diffSHA, req.RulepackVersion, req.ConfigHash, cfg.LLM.Model); hit {
		log.Println("sombra: diff en caché — sin llamadas")
		r.Store.UpdateRunLLM(req.RunID, risk, false)
		return
	}
	r.Store.UpdateRunLLM(req.RunID, risk, true)

	// Contexto común: diff REDACTADO (P5 — nada que parezca credencial sale
	// a la red) y truncado por presupuesto, + lo ya encontrado.
	diff := Redact(req.DiffUnified)
	if maxChars := cfg.LLM.MaxDiffTokens * 4; len(diff) > maxChars {
		diff = diff[:maxChars] + "\n[diff truncado por presupuesto]"
	}
	var detList strings.Builder
	for _, f := range deterministic {
		fmt.Fprintf(&detList, "- %s %s:%d %s\n", f.RuleKey, f.File, f.Line, f.Message)
	}

	// ── Etapa 5: fan-out concurrente, un prompt por pilar ──
	timeout := time.Duration(cfg.LLM.TimeoutMs) * time.Millisecond
	var wg sync.WaitGroup
	var mu sync.Mutex
	var verified []finding.Finding

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
						r.OnThinking(string(pillar), text)
					}
				}
			}
			res, err := client.CompleteStream(ctx, model, systemPrompt, user, timeout, 0, onDelta)
			if err != nil {
				call.Status = "error"
				if ctx.Err() != nil || strings.Contains(err.Error(), "deadline") {
					call.Status = "timeout"
				}
				log.Printf("sombra %s: %v", pillar, err)
				r.Store.SaveLLMCall(call)
				return
			}
			call.Status = "ok"
			call.PromptTokens = res.Usage.PromptTokens
			call.CompletionTokens = res.Usage.CompletionTokens
			call.LatencyMs = res.LatencyMs

			// ── Etapa 6: verificación determinista de cada hallazgo ──
			ok, rejected := verify(req, pillar, res.Content, deterministic)
			call.FindingsReturned = len(ok) + rejected
			call.FindingsRejected = rejected
			r.Store.SaveLLMCall(call)

			mu.Lock()
			verified = append(verified, ok...)
			mu.Unlock()
		}(pillar, scope)
	}
	wg.Wait()
	if r.OnThinking != nil {
		r.OnThinking("", "") // señal de fin: la UI apaga el hilo de pensamiento
	}

	if err := r.Store.SaveLLMFindings(req.RunID, verified); err != nil {
		log.Println("sombra: no se pudieron guardar hallazgos:", err)
	}
	if payload, err := json.Marshal(verified); err == nil {
		r.Store.DiffCachePut(req.RepoID, diffSHA, req.RulepackVersion, req.ConfigHash, cfg.LLM.Model, string(payload))
	}
	log.Printf("sombra: %d hallazgos verificados registrados (shown=0)", len(verified))
}

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

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(strings.ReplaceAll(s, "\r\n", "\n")))
	return hex.EncodeToString(sum[:])
}
