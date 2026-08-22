package shadow

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"codeguard/internal/finding"
	"codeguard/internal/ipc"
)

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

