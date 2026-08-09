// Package llm es el cliente de la capa de consejo. Habla dos dialectos —el de
// OpenAI, que copiaron casi todos, y el de Anthropic— y con eso alcanza para
// los servicios que un equipo usa de verdad, incluido un modelo local.
// Sin SDK: net/http.
package llm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"codeguard/internal/config"
)

type Client struct {
	endpoint string
	apiKey   string
	dialecto Dialecto
	http     *http.Client
}

// New devuelve nil (sin error) cuando la capa no se puede usar: sin endpoint,
// o con un proveedor que exige key y no la encuentra. Nunca es un requisito
// para commitear (P2), así que su ausencia degrada y no rompe.
//
// Un modelo local (Ollama, LM Studio) no lleva key: exigirla dejaría fuera
// justo la opción en la que el código no sale de la máquina.
func New(cfg config.LLM) *Client {
	if cfg.Endpoint == "" {
		return nil
	}
	prov, _ := BuscarProveedor(cfg.Provider)
	key := ""
	if cfg.APIKeyEnv != "" {
		key = os.Getenv(cfg.APIKeyEnv)
	}
	if key == "" && requiereKey(cfg, prov) {
		return nil
	}

	dial := dialectoDe(cfg.Provider, cfg.Endpoint)
	endpoint := normalizarEndpoint(cfg.Endpoint)
	if dial == DialectoOpenAI && !strings.Contains(endpoint, "/chat/completions") {
		endpoint += "/chat/completions"
	}
	return &Client{
		endpoint: endpoint,
		apiKey:   key,
		dialecto: dial,
		// El límite real lo pone el context de cada llamada; este es el techo.
		http: &http.Client{Timeout: 3 * time.Minute},
	}
}

// requiereKey: los preajustes lo declaran; para un endpoint escrito a mano se
// deduce de si apunta a la propia máquina.
func requiereKey(cfg config.LLM, prov Proveedor) bool {
	if cfg.Provider != "" {
		return prov.NecesitaKey
	}
	e := strings.ToLower(cfg.Endpoint)
	return !strings.Contains(e, "localhost") && !strings.Contains(e, "127.0.0.1")
}

// Dialecto dice con qué API se está hablando. Sirve para mostrarlo en la
// pantalla de configuración.
func (c *Client) Dialecto() Dialecto { return c.dialecto }

// normalizarEndpoint completa las URLs de Azure a las que les falta la ruta.
//
// Azure expone dos superficies sobre el mismo host: la moderna, bajo
// /openai/v1, que habla el dialecto de OpenAI tal cual; y la clásica, que
// exige ?api-version= en cada llamada. Quien pega la URL del portal se lleva
// el host pelado, y la respuesta —"Missing required query parameter:
// api-version"— no da ninguna pista de que falta un trozo de ruta.
func normalizarEndpoint(bruto string) string {
	e := strings.TrimRight(strings.TrimSpace(bruto), "/")
	if e == "" {
		return e
	}
	bajo := strings.ToLower(e)
	esAzure := strings.Contains(bajo, ".services.ai.azure.com") ||
		strings.Contains(bajo, ".openai.azure.com") ||
		strings.Contains(bajo, ".cognitiveservices.azure.com")
	if !esAzure {
		return e
	}
	// Ya trae ruta propia: no tocarla, puede ser un despliegue clásico
	// deliberado con su api-version.
	if strings.Contains(bajo, "/openai/") || strings.Contains(bajo, "?") {
		return e
	}
	return e + "/openai/v1"
}

// pistaDeError traduce las respuestas del proveedor que, tal cual, no dicen
// qué hacer. Un HTTP 400 crudo manda al desarrollador a adivinar.
func pistaDeError(cuerpo string) string {
	switch {
	case strings.Contains(cuerpo, "api-version"):
		return "\n\nEste endpoint de Azure es de la API clásica. Usa la moderna añadiendo " +
			"/openai/v1 al final del host (por ejemplo https://TU-RECURSO.services.ai.azure.com/openai/v1), " +
			"que es la que habla el dialecto de OpenAI sin api-version."
	case strings.Contains(cuerpo, "DeploymentNotFound"):
		return "\n\nEl modelo no existe en ese recurso: en Azure el nombre es el del DESPLIEGUE, " +
			"no el del modelo base."
	case strings.Contains(cuerpo, "401") || strings.Contains(cuerpo, "Unauthorized") ||
		strings.Contains(cuerpo, "invalid_api_key"):
		return "\n\nLa clave no es válida para este endpoint. Revisa que la variable de entorno " +
			"tenga la clave de ESTE recurso."
	}
	return ""
}

type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
}

type Result struct {
	Content   string
	Usage     Usage
	LatencyMs int64
}

// Complete hace una llamada de chat y devuelve el contenido del primer choice.
// maxTokens: 0 = default (4000). Los razonadores (Kimi K3) gastan presupuesto
// en pensar ANTES de responder — tareas grandes necesitan techos grandes.
func (c *Client) Complete(ctx context.Context, model, system, user string, timeout time.Duration, maxTokens int) (*Result, error) {
	if c.dialecto == DialectoAnthropic {
		return c.completarAnthropic(ctx, model, system, user, timeout, maxTokens)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if maxTokens <= 0 {
		maxTokens = 4000
	}
	payload := map[string]any{
		"model": model,
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
		// Fuerza JSON válido en endpoints que lo soportan; inofensivo si no.
		"response_format": map[string]string{"type": "json_object"},
	}
	// Dialectos por familia: los GPT-5.x exigen max_completion_tokens y no
	// aceptan temperature=0; el resto (Kimi, DeepSeek...) usa max_tokens.
	do := func(useNewParams bool) (*http.Response, []byte, error) {
		p := map[string]any{}
		for k, v := range payload {
			p[k] = v
		}
		if useNewParams {
			p["max_completion_tokens"] = maxTokens
		} else {
			p["max_tokens"] = maxTokens
			p["temperature"] = 0
		}
		body, _ := json.Marshal(p)
		req, err := http.NewRequestWithContext(ctx, "POST", c.endpoint, bytes.NewReader(body))
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
		req.Header.Set("api-key", c.apiKey) // estilo Azure
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, nil, err
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		return resp, raw, err
	}

	start := time.Now()
	resp, raw, err := do(false)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == 400 && strings.Contains(string(raw), "max_completion_tokens") {
		resp, raw, err = do(true)
		if err != nil {
			return nil, err
		}
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d: %s%s", resp.StatusCode, truncate(string(raw), 300), pistaDeError(string(raw)))
	}
	var parsed struct {
		Choices []struct {
			FinishReason string `json:"finish_reason"`
			Message      struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage Usage `json:"usage"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("respuesta ilegible: %v", err)
	}
	if len(parsed.Choices) == 0 {
		return nil, fmt.Errorf("respuesta sin choices")
	}
	if parsed.Choices[0].FinishReason == "length" {
		return nil, fmt.Errorf("respuesta truncada por max_tokens (%d): el razonamiento consumió el presupuesto — sube el techo", maxTokens)
	}
	return &Result{
		Content:   parsed.Choices[0].Message.Content,
		Usage:     parsed.Usage,
		LatencyMs: time.Since(start).Milliseconds(),
	}, nil
}

// CompleteStream: igual que Complete pero en streaming SSE, entregando los
// deltas de razonamiento y contenido vía onDelta (kind: "reasoning"|"content").
// Permite mostrar en la UI lo que el modelo va pensando mientras analiza.
func (c *Client) CompleteStream(ctx context.Context, model, system, user string, timeout time.Duration, maxTokens int, onDelta func(kind, text string)) (*Result, error) {
	if c.dialecto == DialectoAnthropic {
		return c.streamAnthropic(ctx, model, system, user, timeout, maxTokens, onDelta)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if maxTokens <= 0 {
		maxTokens = 4000
	}

	do := func(useNewParams bool) (*http.Response, error) {
		p := map[string]any{
			"model": model,
			"messages": []map[string]string{
				{"role": "system", "content": system},
				{"role": "user", "content": user},
			},
			"response_format": map[string]string{"type": "json_object"},
			"stream":          true,
			"stream_options":  map[string]bool{"include_usage": true},
		}
		if useNewParams {
			p["max_completion_tokens"] = maxTokens
		} else {
			p["max_tokens"] = maxTokens
			p["temperature"] = 0
		}
		body, _ := json.Marshal(p)
		req, err := http.NewRequestWithContext(ctx, "POST", c.endpoint, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
		req.Header.Set("api-key", c.apiKey)
		return c.http.Do(req)
	}

	start := time.Now()
	resp, err := do(false)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == 400 {
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close() // se reintenta con otro cuerpo; este ya se leyó entero
		if !strings.Contains(string(raw), "max_completion_tokens") {
			return nil, fmt.Errorf("HTTP 400: %s%s", truncate(string(raw), 300), pistaDeError(string(raw)))
		}
		if resp, err = do(true); err != nil {
			return nil, err
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s%s", resp.StatusCode, truncate(string(raw), 300), pistaDeError(string(raw)))
	}

	var content strings.Builder
	var usage Usage
	finish := ""
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			break
		}
		var chunk struct {
			Choices []struct {
				FinishReason string `json:"finish_reason"`
				Delta        struct {
					Content          string `json:"content"`
					ReasoningContent string `json:"reasoning_content"`
				} `json:"delta"`
			} `json:"choices"`
			Usage *Usage `json:"usage"`
		}
		if json.Unmarshal([]byte(data), &chunk) != nil {
			continue
		}
		if chunk.Usage != nil {
			usage = *chunk.Usage
		}
		if len(chunk.Choices) == 0 {
			continue
		}
		ch := chunk.Choices[0]
		if ch.FinishReason != "" {
			finish = ch.FinishReason
		}
		if ch.Delta.ReasoningContent != "" && onDelta != nil {
			onDelta("reasoning", ch.Delta.ReasoningContent)
		}
		if ch.Delta.Content != "" {
			content.WriteString(ch.Delta.Content)
			if onDelta != nil {
				onDelta("content", ch.Delta.Content)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if finish == "length" {
		return nil, fmt.Errorf("respuesta truncada por max_tokens (%d)", maxTokens)
	}
	return &Result{Content: content.String(), Usage: usage, LatencyMs: time.Since(start).Milliseconds()}, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
