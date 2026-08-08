package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"

	"codeguard/internal/config"
	"codeguard/internal/foundry"
	"codeguard/internal/ipc"
)

// D1 — el agente que habla tu idioma, literal: los mensajes crípticos de las
// herramientas se traducen a una explicación en español sobre el código real
// del dev. La investigación muestra que la causa #1 de ignorar advertencias
// es no entenderlas. Nunca toca el veredicto; solo enriquece el panel.

const explainSystem = `Eres un mentor de programación senior que explica en español claro y cercano.
Te doy hallazgos BLOQUEANTES de herramientas de análisis con el código señalado.
Para cada uno devuelve una explicación breve dirigida al autor del código.
Responde SOLO JSON: {"explanations":[{"id":"<id del hallazgo>","text":"..."}]}
Reglas:
- Máximo 3 frases por hallazgo: qué está mal EN ESTE código concreto, por qué el CI lo rechazará, y el arreglo exacto.
- Tono de compañero, no de juez. Sin tecnicismos innecesarios, sin regaños.
- Si el mensaje original ya es claro, mejora igual la parte del "cómo arreglarlo" con el código real.`

var explainCache sync.Map // fingerprint -> string

type explanation struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

func explainBlockers(app *application.App, cfg *config.Config, req *ipc.Request, resp *ipc.Response) {
	client := foundry.New(cfg.LLM)
	if client == nil {
		return
	}

	// máximo 3 bloqueantes por llamada; caché por fingerprint
	var pending []string
	count := 0
	var sb strings.Builder
	for _, f := range resp.Findings {
		if !f.Blocking || count >= 3 {
			continue
		}
		if cached, ok := explainCache.Load(f.Fingerprint); ok {
			emitExplain(app, f.ID, cached.(string))
			continue
		}
		count++
		pending = append(pending, f.ID)
		fmt.Fprintf(&sb, "— id: %s\n  regla: %s (%s)\n  mensaje: %s\n  archivo: %s línea %d\n  código:\n%s\n\n",
			f.ID, f.RuleKey, f.Engine, f.Message, f.File, f.Line, snippetText(req.RepoRoot, f.File, f.Line))
	}
	if count == 0 {
		return
	}

	res, err := client.Complete(context.Background(), cfg.LLM.Fast(), explainSystem,
		sb.String(), time.Duration(cfg.LLM.TimeoutMs)*time.Millisecond, 0)
	if err != nil {
		log.Println("explicaciones: el modelo no respondió:", err)
		return
	}
	content := strings.TrimSpace(res.Content)
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSuffix(content, "```")
	var parsed struct {
		Explanations []explanation `json:"explanations"`
	}
	if err := json.Unmarshal([]byte(content), &parsed); err != nil {
		log.Println("explicaciones ilegibles:", err)
		return
	}
	byID := map[string]string{}
	for _, f := range resp.Findings {
		byID[f.ID] = f.Fingerprint
	}
	for _, e := range parsed.Explanations {
		if e.Text == "" {
			continue
		}
		if fp, ok := byID[e.ID]; ok {
			explainCache.Store(fp, e.Text)
		}
		emitExplain(app, e.ID, e.Text)
	}
	_ = pending
}

func emitExplain(app *application.App, findingID, text string) {
	app.Event.Emit("explain", map[string]string{"finding_id": findingID, "text": text})
}

func snippetText(repoRoot, rel string, line int) string {
	sn := snippet(repoRoot, rel, line)
	var sb strings.Builder
	for _, l := range sn {
		marker := "  "
		if l.Culprit {
			marker = "> "
		}
		fmt.Fprintf(&sb, "  %s%d| %s\n", marker, l.No, l.Text)
	}
	return sb.String()
}
