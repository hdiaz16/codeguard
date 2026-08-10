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

// Techos de salida, por camino. max_tokens topa el pensamiento MÁS la
// respuesta, y en los modelos actuales el pensamiento viene encendido de
// fábrica: con el techo viejo de 4000 la sombra —que razona y además devuelve
// un JSON de hallazgos de tres pilares— se cortaba a media respuesta. Un techo
// alto no cuesta nada: sólo se paga lo que el modelo genera de verdad.
const (
	techoAnthropic       = 16000 // llamadas sueltas: explicar, sugerir reglas
	techoAnthropicStream = 64000 // sombra: razonamiento + JSON completo
)

// pensamientoAnthropic pide razonamiento con resumen legible.
//
// El campo display es el que importa: su default es "omitted", así que sin
// pedirlo los bloques de pensamiento llegan VACÍOS. El hilo de pensamiento del
// panel se quedaba en blanco y no había forma de notarlo —no hay error, no hay
// aviso, simplemente nunca llega texto.
type pensamientoAnthropic struct {
	Type    string `json:"type"`
	Display string `json:"display,omitempty"`
}

type peticionAnthropic struct {
	Model     string                `json:"model"`
	System    string                `json:"system,omitempty"`
	MaxTokens int                   `json:"max_tokens"`
	Stream    bool                  `json:"stream,omitempty"`
	Thinking  *pensamientoAnthropic `json:"thinking,omitempty"`
	Messages  []mensajeAnthropic    `json:"messages"`
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

// errNegativa arma el error de un stop_reason "refusal": los clasificadores
// del proveedor declinaron la petición.
//
// Llega como HTTP 200 con el contenido vacío (o a medias, si ya había
// empezado a responder), así que sin este chequeo se lee como una respuesta
// legítima sin nada que decir — y la sombra registraba cero hallazgos sin
// explicar por qué. Importa especialmente aquí: CodeGuard analiza código de
// seguridad, que es justo lo que esos clasificadores rozan.
func errNegativa(categoria, explicacion string) error {
	detalle := explicacion
	if categoria != "" {
		detalle = strings.TrimSpace(categoria + ": " + explicacion)
	}
	if detalle == "" {
		detalle = "el proveedor no dio motivo"
	}
	return fmt.Errorf("el proveedor declinó la petición (%s). No es un fallo de red ni "+
		"un error de configuración: sus clasificadores rechazaron el contenido del diff", detalle)
}

// detalleParada acompaña a stop_reason; sólo viene poblado en las negativas,
// así que se trata como opcional en todos los caminos.
type detalleParada struct {
	Category    string `json:"category"`
	Explanation string `json:"explanation"`
}

func (c *Client) completarAnthropic(ctx context.Context, model, system, user string, timeout time.Duration, maxTokens int) (*Result, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if maxTokens <= 0 {
		maxTokens = techoAnthropic
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
		return nil, fmt.Errorf("HTTP %d: %s%s", resp.StatusCode, truncate(string(raw), 300), pistaDeError(string(raw)))
	}

	var parsed struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		StopReason  string         `json:"stop_reason"`
		StopDetails *detalleParada `json:"stop_details"`
		Usage       struct {
			InputTokens              int `json:"input_tokens"`
			OutputTokens             int `json:"output_tokens"`
			CacheReadInputTokens     int `json:"cache_read_input_tokens"`
			CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("respuesta ilegible: %v", err)
	}
	// La negativa se comprueba ANTES del truncamiento: llega con HTTP 200 y
	// contenido vacío, que de otro modo pasaría por respuesta buena.
	if parsed.StopReason == "refusal" {
		var categoria, explicacion string
		if parsed.StopDetails != nil {
			categoria, explicacion = parsed.StopDetails.Category, parsed.StopDetails.Explanation
		}
		return nil, errNegativa(categoria, explicacion)
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
		Content: texto.String(),
		Usage: Usage{
			PromptTokens:        parsed.Usage.InputTokens,
			CompletionTokens:    parsed.Usage.OutputTokens,
			CacheReadTokens:     parsed.Usage.CacheReadInputTokens,
			CacheCreationTokens: parsed.Usage.CacheCreationInputTokens,
		},
		LatencyMs: time.Since(inicio).Milliseconds(),
	}, nil
}

func (c *Client) streamAnthropic(ctx context.Context, model, system, user string, timeout time.Duration, maxTokens int, onDelta func(kind, text string)) (*Result, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if maxTokens <= 0 {
		maxTokens = techoAnthropicStream
	}

	// Este es el único camino que consume onDelta("reasoning"), así que es el
	// único que pide pensamiento. Las llamadas mecánicas no lo piden: no se
	// muestra en ninguna parte y el modelo no tiene por qué gastarlo.
	pedir := func(conPensamiento bool) (*http.Response, error) {
		cuerpo := peticionAnthropic{
			Model: model, System: system, MaxTokens: maxTokens, Stream: true,
			Messages: []mensajeAnthropic{{Role: "user", Content: user}},
		}
		if conPensamiento {
			cuerpo.Thinking = &pensamientoAnthropic{Type: "adaptive", Display: "summarized"}
		}
		req, err := c.peticion(ctx, cuerpo)
		if err != nil {
			return nil, err
		}
		return c.http.Do(req)
	}

	inicio := time.Now()
	resp, err := pedir(true)
	if err != nil {
		return nil, err
	}
	// El pensamiento adaptativo no existe en los modelos anteriores a la
	// generación 4.6, que lo rechazan con un 400. Se reintenta sin él en vez de
	// dejar sin capa de consejo a quien apunte a un modelo viejo — mismo patrón
	// que el reintento de max_completion_tokens en el dialecto de OpenAI.
	if resp.StatusCode == 400 {
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close() // ya se leyó entero; se reintenta con otro cuerpo
		if !strings.Contains(strings.ToLower(string(raw)), "thinking") {
			return nil, fmt.Errorf("HTTP 400: %s%s", truncate(string(raw), 300), pistaDeError(string(raw)))
		}
		if resp, err = pedir(false); err != nil {
			return nil, err
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s%s", resp.StatusCode, truncate(string(raw), 300), pistaDeError(string(raw)))
	}

	var texto strings.Builder
	var uso Usage
	parada := ""
	categoriaNegativa, explicacionNegativa := "", ""
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
				Type        string         `json:"type"`
				Text        string         `json:"text"`
				Thinking    string         `json:"thinking"`
				StopReason  string         `json:"stop_reason"`
				StopDetails *detalleParada `json:"stop_details"`
			} `json:"delta"`
			Message struct {
				Usage struct {
					InputTokens              int `json:"input_tokens"`
					CacheReadInputTokens     int `json:"cache_read_input_tokens"`
					CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
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
			// Los tokens de entrada (y su desglose de caché) sólo viajan aquí;
			// los de salida llegan al final, en message_delta.
			uso.PromptTokens = ev.Message.Usage.InputTokens
			uso.CacheReadTokens = ev.Message.Usage.CacheReadInputTokens
			uso.CacheCreationTokens = ev.Message.Usage.CacheCreationInputTokens
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
				if ev.Delta.StopDetails != nil {
					categoriaNegativa = ev.Delta.StopDetails.Category
					explicacionNegativa = ev.Delta.StopDetails.Explanation
				}
			}
			if ev.Usage.OutputTokens > 0 {
				uso.CompletionTokens = ev.Usage.OutputTokens
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("stream interrumpido: %w", err)
	}
	// La negativa puede llegar a mitad del stream, ya con texto entregado a la
	// UI. Se descarta lo parcial: media respuesta de un análisis es peor que
	// ninguna, porque parece completa.
	if parada == "refusal" {
		return nil, errNegativa(categoriaNegativa, explicacionNegativa)
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
