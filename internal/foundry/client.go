// Package foundry es el cliente del modelo advisory: endpoint compatible con
// la API de OpenAI (Azure AI Foundry, Moonshot, vLLM...). Sin SDK: net/http.
package foundry

import (
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
	http     *http.Client
}

// New devuelve nil (sin error) si no hay endpoint o API key: la capa LLM
// simplemente no corre — nunca es requisito (P2).
func New(cfg config.LLM) *Client {
	if cfg.Endpoint == "" || cfg.APIKeyEnv == "" {
		return nil
	}
	key := os.Getenv(cfg.APIKeyEnv)
	if key == "" {
		return nil
	}
	endpoint := strings.TrimRight(cfg.Endpoint, "/")
	if !strings.Contains(endpoint, "/chat/completions") {
		endpoint += "/chat/completions"
	}
	return &Client{
		endpoint: endpoint,
		apiKey:   key,
		http:     &http.Client{Timeout: 60 * time.Second},
	}
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
func (c *Client) Complete(ctx context.Context, model, system, user string, timeout time.Duration) (*Result, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	body, _ := json.Marshal(map[string]any{
		"model": model,
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
		"temperature": 0,
		"max_tokens":  1500,
		// Fuerza JSON válido en endpoints que lo soportan; inofensivo si no.
		"response_format": map[string]string{"type": "json_object"},
	})
	req, err := http.NewRequestWithContext(ctx, "POST", c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("api-key", c.apiKey) // estilo Azure

	start := time.Now()
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
		Choices []struct {
			Message struct {
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
	return &Result{
		Content:   parsed.Choices[0].Message.Content,
		Usage:     parsed.Usage,
		LatencyMs: time.Since(start).Milliseconds(),
	}, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
