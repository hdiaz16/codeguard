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
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"codeguard/internal/config"
	"codeguard/internal/secreto"
	"codeguard/internal/textutil"
)

type Client struct {
	endpoint string
	apiKey   string
	dialecto Dialecto
	http     *http.Client
}

// maxRespuestaLLM topa los cuerpos que se leen enteros a memoria (respuestas
// de Complete y cuerpos de error). El endpoint lo configura el usuario y puede
// ser cualquiera: sin tope, un endpoint roto o hostil que devuelva un cuerpo
// gigante tumba el daemon por memoria.
//
// 32 MB es ~100x lo que una respuesta legítima puede ocupar (el techo de
// salida más alto del paquete es 64000 tokens ≈ unos cientos de KB de JSON) y
// la mitad del proc.MaxSalida (64 MB) que el repo ya usa como referencia de
// "tope de salida". Si el corte llega a morder, el JSON truncado falla el
// Unmarshal con "respuesta ilegible: unexpected end of JSON input", que ya
// dice lo que pasó — no hace falta detectar el truncamiento aparte.
//
// El streaming NO pasa por aquí: usa bufio.Scanner línea a línea, y limitarlo
// rompería respuestas largas legítimas.
const maxRespuestaLLM = 32 << 20

// leerSecreto es el punto de sustitución de las pruebas.
//
// La bóveda real no se puede ROMPER a propósito desde un test —haría falta
// corromper el Administrador de credenciales del usuario, o pararle el
// servicio— y el fallo de bóveda es justamente la rama que este código existe
// para distinguir. Mismo patrón, y por la misma razón, que las sustituciones de
// cmd/daemon/configllm.go.
var leerSecreto = secreto.Leer

// ClaveDe resuelve la clave del modelo, primero de la bóveda del sistema y
// luego del entorno.
//
// El orden importa y la caída al entorno NO es un descuido: es lo que permite
// que quien exporta la clave a mano para una prueba, o la inyecta en el CI por
// variable, siga funcionando sin migrar nada. Lo que se deja de hacer es
// ESCRIBIRLA ahí (ver cmd/daemon/configllm.go).
//
// La bóveda se consulta en cada llamada en vez de cachearse al arrancar, y eso
// también es a propósito: la versión anterior leía la clave del entorno del
// proceso, así que el daemon arrancaba sin ella cada vez que se reiniciaba
// —varias veces por semana, una por actualización— y la capa semántica se
// apagaba sola. El log decía "sin API key" mientras la clave llevaba días
// guardada. Leer en el momento de usarla no tiene ese modo de fallo.
func ClaveDe(cfg config.LLM) string {
	if cfg.APIKeyEnv == "" {
		return ""
	}
	guardada, err := leerSecreto(cfg.APIKeyEnv)
	clave, aviso := decidirClave(cfg.APIKeyEnv, guardada, err, os.Getenv(cfg.APIKeyEnv))
	avisarDeLaBoveda(aviso)
	return clave
}

// decidirClave dice de dónde sale la clave y qué hay que contar en voz alta.
//
// Es pura y vive separada de la bóveda para poder probar la distinción que
// importa —"aquí no hay nada guardado" contra "la bóveda falló"— sin tocar el
// Administrador de credenciales de nadie.
//
// Aquí estaba el defecto: `if v, err := secreto.Leer(...); err == nil && v !=
// ""` metía las dos cosas en el mismo saco. Una bóveda corrupta, sin permisos o
// con el servicio parado caía EXACTAMENTE igual que "todavía no se ha migrado",
// y río abajo el síntoma era el de siempre —"sin endpoint/API key, capa
// apagada"—, así que el dev leía "no configuraste la clave" cuando lo que
// pasaba es que su bóveda estaba rota. La avería se disfrazaba de descuido, que
// es el peor diagnóstico posible: manda a arreglar lo que ya estaba bien.
//
// La caída al entorno se CONSERVA aun con la bóveda averiada, y no es
// resignación: la capa de consejo nunca es requisito para commitear (P2), así
// que negarse a mirar el entorno convertiría un fallo de la bóveda en una capa
// apagada incluso cuando la variable tiene una clave perfectamente buena. Lo
// que NO se conserva es el silencio — el fallo se registra, y el aviso dice si
// el entorno salvó la llamada o si además se quedó sin clave.
func decidirClave(nombreVar, guardada string, errBoveda error, delEntorno string) (clave, aviso string) {
	switch {
	case errBoveda == nil && guardada != "":
		return guardada, ""
	case errBoveda == nil || secreto.NoEncontrado(errBoveda):
		// El camino de siempre: no hay nada guardado —no se ha migrado, o esta
		// máquina no tiene bóveda—. Se cae al entorno sin decir nada, porque no
		// ha fallado nada.
		return delEntorno, ""
	}
	if delEntorno != "" {
		return delEntorno, fmt.Sprintf("la bóveda no pudo leer %s (%v). Se usó el valor de la "+
			"variable de entorno, así que la capa sigue en pie, pero la clave GUARDADA no se está "+
			"leyendo: revisa el Administrador de credenciales", nombreVar, errBoveda)
	}
	return "", fmt.Sprintf("la bóveda no pudo leer %s (%v) y la variable de entorno tampoco tiene "+
		"valor: la capa de consejo queda apagada por un FALLO de la bóveda, no porque falte "+
		"configurar la clave", nombreVar, errBoveda)
}

var (
	muAviso     sync.Mutex
	ultimoAviso string
)

// avisarDeLaBoveda registra el fallo, pero no una vez por llamada.
//
// ClaveDe se consulta en CADA uso —a propósito, ver arriba— y la pantalla de
// configuración la llama en cada refresco: sin filtro, una bóveda averiada
// escribe la misma línea decenas de veces y entierra todo lo demás en el log,
// que es otra forma de no decir nada.
//
// Se recuerda el último aviso y no un "ya avisé" a secas, y el camino bueno
// pasa por aquí con la cadena vacía para BORRAR esa memoria. Así, un fallo que
// se arregla y vuelve se cuenta las dos veces; con un sync.Once, la segunda
// avería habría sido tan muda como el bug que este código viene a quitar.
func avisarDeLaBoveda(aviso string) {
	muAviso.Lock()
	repetido := aviso == ultimoAviso
	ultimoAviso = aviso
	muAviso.Unlock()
	if aviso != "" && !repetido {
		log.Printf("clave del modelo: %s", aviso)
	}
}

// New devuelve nil (sin error) cuando la capa no se puede usar: sin endpoint,
// o con un proveedor que exige key y no la encuentra. Nunca es un requisito
// para commitear (P2), así que su ausencia degrada y no rompe.
//
// Un modelo local (Ollama, LM Studio) no lleva key: exigirla dejaría fuera
// justo la opción en la que el código no sale de la máquina.
func New(cfg config.LLM) *Client { return NewConClave(cfg, ClaveDe(cfg)) }

// NewConClave construye el cliente con una clave EXPLÍCITA, sin consultar la
// bóveda ni el entorno.
//
// Existe para probar una clave recién pegada en el formulario, que todavía no
// está guardada en ningún sitio. Antes eso se hacía metiéndola un momento en
// el entorno del proceso y quitándola después; con la bóveda por delante, ese
// truco dejó de funcionar en silencio: `New` habría leído la clave GUARDADA e
// ignorado la que el usuario acaba de escribir. Habría respondido "OK" con la
// clave vieja, que es la peor respuesta posible — la que hace pensar que ya
// está arreglado.
func NewConClave(cfg config.LLM, key string) *Client {
	if cfg.Endpoint == "" {
		return nil
	}
	prov, conocido := BuscarProveedor(cfg.Provider)
	// Un nombre de proveedor desconocido NO se traga: con el Proveedor en su
	// valor cero, NecesitaKey queda en false, requiereKey dice que no hace falta
	// clave y se construye un cliente SIN ella contra un servicio que la exige —
	// todas las llamadas fallarían con 401 y sin una pista de que el nombre
	// estaba mal escrito. Se cierra con aviso, igual que el endpoint inseguro de
	// abajo: la capa degrada (P2, nunca rompe el commit) pero el log dice qué
	// está mal. El endpoint escrito a mano (Provider vacío) no pasa por aquí: no
	// hay nombre que buscar y requiereKey lo deduce del loopback, como siempre.
	if cfg.Provider != "" && !conocido {
		log.Printf("capa de consejo apagada: proveedor %q desconocido. Revisa el nombre en la "+
			"configuración, o deja el proveedor vacío si el endpoint va escrito a mano",
			cfg.Provider)
		return nil
	}
	if key == "" && requiereKey(cfg, prov) {
		return nil
	}
	// Un cliente con clave es un cliente que la VA A ENVIAR: si el endpoint no
	// puede recibirla sin exponerla, no se construye. Validar aquí —y no en
	// cada request— cubre Complete y CompleteStream por construcción: si el
	// Client existe, su endpoint ya es seguro para llevar la clave.
	//
	// Se registra y no se calla: devolver nil degrada la capa (P2, nunca
	// rompe el commit), pero un nil mudo aquí sería el mismo síntoma de
	// siempre —"capa apagada" sin motivo— para una decisión de seguridad
	// deliberada. El log dice QUÉ se cerró y CÓMO se arregla.
	if key != "" && !endpointSeguroParaClave(cfg.Endpoint) {
		log.Printf("capa de consejo apagada: el endpoint %q no es HTTPS ni apunta a esta "+
			"máquina, y enviar la clave por HTTP en claro la expondría. Usa https:// o un "+
			"modelo local (Ollama, LM Studio)", cfg.Endpoint)
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
		// SIN plazo en el Client: el que manda es el context de cada llamada.
		//
		// Aquí había un `Timeout: 3 * time.Minute` con un comentario que lo
		// llamaba "el techo", y era un techo ESCONDIDO. http.Client.Timeout cubre
		// la petición entera, incluida la lectura del cuerpo —o sea, todo el
		// stream—, así que cortaba a los tres minutos por mucho más plazo que
		// hubiera pedido el llamador. Y corta como un error de red cualquiera: la
		// sombra lo clasifica como "timeout", de modo que el síntoma es idéntico
		// al de un plazo agotado y no hay nada que delate el tope de tres minutos
		// que nadie configuró.
		//
		// Importa porque timeout_ms no tiene tope en la config y el techo de
		// salida del dialecto de Anthropic en streaming es de 64000 tokens: un
		// razonador los gasta de sobra en más de tres minutos. Quien subiera
		// timeout_ms a diez minutos seguía cortado a los tres.
		//
		// Quitarlo no deja llamadas colgadas: los CUATRO caminos que usan este
		// Client —Complete y CompleteStream, en los dos dialectos— empiezan por
		// context.WithTimeout(ctx, timeout) y son los únicos que lo tocan. El
		// plazo sigue existiendo; ahora es el que se pidió.
		http: &http.Client{},
	}
}

// requiereKey: los preajustes lo declaran; para un endpoint escrito a mano se
// deduce de si apunta a la propia máquina.
func requiereKey(cfg config.LLM, prov Proveedor) bool {
	if cfg.Provider != "" {
		return prov.NecesitaKey
	}
	return !esLoopback(cfg.Endpoint)
}

// esLoopback dice si el endpoint apunta a la propia máquina, caso en el que
// el tráfico no sale de ella y HTTP en claro es aceptable (Ollama, LM Studio).
//
// Se parsea el host de verdad —net/url + net.ParseIP— y no con
// strings.Contains como antes: un host como "localhost.evil.com" CONTIENE
// "localhost" y colaba como local. IsLoopback cubre todo 127.0.0.0/8 y ::1,
// no sólo 127.0.0.1.
func esLoopback(endpoint string) bool {
	u, err := url.Parse(endpoint)
	if err != nil {
		return false
	}
	if u.Scheme == "unix" {
		return true
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// endpointSeguroParaClave es la ÚNICA fuente de la política "¿puede este
// endpoint llevar la API key?": sí si es HTTPS (la clave viaja cifrada a
// cualquier host), o si apunta a loopback (la clave no sale de la máquina).
// Un http:// a un host remoto con clave es el caso que se cierra.
func endpointSeguroParaClave(endpoint string) bool {
	u, err := url.Parse(endpoint)
	if err != nil {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	return esLoopback(endpoint)
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
	// Desglose de caché del dialecto de Anthropic. Los rellena ese adaptador;
	// el de OpenAI los deja en cero.
	//
	// Hacen falta porque PromptTokens (input_tokens) cuenta SÓLO el resto no
	// cacheado: sin estos dos, lo servido desde caché no se cobra en absoluto
	// y el costo sale corto, así que el tope mensual se alcanzaría tarde.
	CacheReadTokens     int `json:"-"`
	CacheCreationTokens int `json:"-"`
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
		raw, err := io.ReadAll(io.LimitReader(resp.Body, maxRespuestaLLM))
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
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespuestaLLM))
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
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespuestaLLM))
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
	return textutil.TruncarRunas(s, n) + "…"
}
