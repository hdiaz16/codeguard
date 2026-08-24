package main

import (
	"container/list"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"

	"codeguard/internal/config"
	"codeguard/internal/ipc"
	"codeguard/internal/llm"
	"codeguard/internal/shadow"
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

// maxExplicacionesCache topa las explicaciones en memoria. Un sync.Map a
// secas crece sin límite: cada fingerprint único explicado se quedaba para
// siempre, y un daemon que vive semanas sobre muchos repos acumulaba miles de
// entradas. Evictar es seguro porque las explicaciones se REGENERAN pidiéndolas
// al modelo de nuevo — perder una entrada cuesta una re-explicación, nunca
// corrección.
const maxExplicacionesCache = 1024

// cacheExplicaciones es un LRU mínimo (fingerprint -> texto) con tope duro de
// entradas. Mantiene la interfaz Load/Store del sync.Map que reemplaza.
type cacheExplicaciones struct {
	mu     sync.Mutex
	orden  *list.List // frente = usado más recientemente; fondo = próximo a evictar
	indice map[string]*list.Element
}

type entradaExplicacion struct {
	fingerprint string
	texto       string
}

func nuevoCacheExplicaciones() *cacheExplicaciones {
	return &cacheExplicaciones{
		orden:  list.New(),
		indice: make(map[string]*list.Element),
	}
}

func (c *cacheExplicaciones) Load(fingerprint string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.indice[fingerprint]
	if !ok {
		return "", false
	}
	c.orden.MoveToFront(el)
	return el.Value.(entradaExplicacion).texto, true
}

func (c *cacheExplicaciones) Store(fingerprint, texto string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.indice[fingerprint]; ok {
		el.Value = entradaExplicacion{fingerprint, texto}
		c.orden.MoveToFront(el)
		return
	}
	el := c.orden.PushFront(entradaExplicacion{fingerprint, texto})
	c.indice[fingerprint] = el
	if c.orden.Len() > maxExplicacionesCache {
		viejo := c.orden.Back()
		c.orden.Remove(viejo)
		delete(c.indice, viejo.Value.(entradaExplicacion).fingerprint)
	}
}

var explainCache = nuevoCacheExplicaciones()

type explanation struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

func explainBlockers(app *application.App, cfg *config.Config, req *ipc.Request, resp *ipc.Response) {
	client := llm.New(cfg.LLM)
	if client == nil {
		return
	}

	// máximo 3 bloqueantes por llamada; caché por fingerprint
	count := 0
	var sb strings.Builder
	for _, f := range resp.Findings {
		if !f.Blocking {
			continue
		}
		// La caché se consulta ANTES del tope: una explicación ya cacheada no
		// cuesta llamada al modelo, así que se emite aunque el tope esté lleno.
		// Antes el «count >= 3» iba primero y se comía explicaciones gratis.
		if cached, ok := explainCache.Load(f.Fingerprint); ok {
			emitExplain(app, f.ID, cached)
			continue
		}
		// El tope solo frena las llamadas NUEVAS. Se sigue recorriendo —y no se
		// corta el bucle— porque un hallazgo posterior puede estar cacheado y
		// emitirlo no cuesta nada.
		if count >= 3 {
			continue
		}
		count++
		// P5: el código que viaja al modelo va redactado.
		fmt.Fprintf(&sb, "— id: %s\n  regla: %s (%s)\n  mensaje: %s\n  archivo: %s línea %d\n  código:\n%s\n\n",
			f.ID, f.RuleKey, f.Engine, f.Message, f.File, f.Line,
			shadow.Redact(snippetText(req.RepoRoot, f.File, f.Line)))
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
