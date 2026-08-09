package llm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// La API de Anthropic no es la de OpenAI con otro nombre: el system va fuera
// de los mensajes, la autenticación usa x-api-key en vez de Bearer, max_tokens
// es obligatorio y la respuesta viene en bloques de contenido. Traducir aquí
// deja al resto de CodeGuard sin enterarse de con quién habla.

const versionAnthropic = "2023-06-01"

type peticionAnthropic struct {
	Model     string             `json:"model"`
	System    string             `json:"system,omitempty"`
	MaxTokens int                `json:"max_tokens"`
	Stream    bool               `json:"stream,omitempty"`
	Messages  []mensajeAnthropic `json:"messages"`
}

type mensajeAnthropic struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

func (c *Client) endpointAnthropic() string {
	e := strings.TrimRight(c.endpoint, "/")
	if strings.HasSuffix(e, "/messages") {
		return e
	}
	return e + "/messages"
}

func (c *Client) peticion(ctx context.Context, cuerpo any) (*http.Request, error) {
	body, err := json.Marshal(cuerpo)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.endpointAnthropic(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", versionAnthropic)
	return req, nil
}

func (c *Client) completarAnthropic(ctx context.Context, model, system, user string, timeout time.Duration, maxTokens int) (*Result, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if maxTokens <= 0 {
		maxTokens = 4000
	}

	req, err := c.peticion(ctx, peticionAnthropic{
		Model: model, System: system, MaxTokens: maxTokens,
		Messages: []mensajeAnthropic{{Role: "user", Content: user}},
	})
	if err != nil {
		return nil, err
	}

	inicio := time.Now()
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(raw), 300))
	}

	var parsed struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		StopReason string `json:"stop_reason"`
		Usage      struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("respuesta ilegible: %v", err)
	}
	if parsed.StopReason == "max_tokens" {
		return nil, fmt.Errorf("respuesta truncada por max_tokens (%d): sube el techo", maxTokens)
	}

	var texto strings.Builder
	for _, b := range parsed.Content {
		if b.Type == "text" {
			texto.WriteString(b.Text)
		}
	}
	return &Result{
		Content:   texto.String(),
		Usage:     Usage{PromptTokens: parsed.Usage.InputTokens, CompletionTokens: parsed.Usage.OutputTokens},
		LatencyMs: time.Since(inicio).Milliseconds(),
	}, nil
}

func (c *Client) streamAnthropic(ctx context.Context, model, system, user string, timeout time.Duration, maxTokens int, onDelta func(kind, text string)) (*Result, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if maxTokens <= 0 {
		maxTokens = 4000
	}

	req, err := c.peticion(ctx, peticionAnthropic{
		Model: model, System: system, MaxTokens: maxTokens, Stream: true,
		Messages: []mensajeAnthropic{{Role: "user", Content: user}},
	})
	if err != nil {
		return nil, err
	}

	inicio := time.Now()
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(raw), 300))
	}

	var texto strings.Builder
	var uso Usage
	parada := ""
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		linea := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(linea, "data: ") {
			continue // las líneas "event:" no hacen falta: el JSON trae su tipo
		}
		var ev struct {
			Type  string `json:"type"`
			Delta struct {
				Type       string `json:"type"`
				Text       string `json:"text"`
				Thinking   string `json:"thinking"`
				StopReason string `json:"stop_reason"`
			} `json:"delta"`
			Message struct {
				Usage struct {
					InputTokens int `json:"input_tokens"`
				} `json:"usage"`
			} `json:"message"`
			Usage struct {
				OutputTokens int `json:"output_tokens"`
			} `json:"usage"`
		}
		if json.Unmarshal([]byte(strings.TrimPrefix(linea, "data: ")), &ev) != nil {
			continue
		}
		switch ev.Type {
		case "message_start":
			uso.PromptTokens = ev.Message.Usage.InputTokens
		case "content_block_delta":
			if ev.Delta.Thinking != "" && onDelta != nil {
				onDelta("reasoning", ev.Delta.Thinking)
			}
			if ev.Delta.Text != "" {
				texto.WriteString(ev.Delta.Text)
				if onDelta != nil {
					onDelta("content", ev.Delta.Text)
				}
			}
		case "message_delta":
			if ev.Delta.StopReason != "" {
				parada = ev.Delta.StopReason
			}
			if ev.Usage.OutputTokens > 0 {
				uso.CompletionTokens = ev.Usage.OutputTokens
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("stream interrumpido: %w", err)
	}
	if parada == "max_tokens" {
		return nil, fmt.Errorf("respuesta truncada por max_tokens (%d): sube el techo", maxTokens)
	}
	return &Result{
		Content:   texto.String(),
		Usage:     uso,
		LatencyMs: time.Since(inicio).Milliseconds(),
	}, nil
}
