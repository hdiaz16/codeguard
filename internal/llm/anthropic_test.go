package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Los tests de este archivo levantan un servidor local y hablan el protocolo de
// verdad. Los cuatro defectos que arreglan eran invisibles desde dentro: el
// pensamiento vacío, el techo corto, la negativa disfrazada de respuesta buena
// y la caché sin cobrar no producen ningún error — sólo resultados falsos.

// clienteDePrueba devuelve un cliente del dialecto Anthropic apuntado al
// servidor dado, más el cuerpo de cada petición que reciba.
func clienteDePrueba(t *testing.T, manejar func(peticion map[string]any, w http.ResponseWriter)) (*Client, *[]map[string]any) {
	t.Helper()
	var recibidas []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var cuerpo map[string]any
		if err := json.NewDecoder(r.Body).Decode(&cuerpo); err != nil {
			t.Errorf("petición ilegible: %v", err)
			w.WriteHeader(500)
			return
		}
		if got := r.Header.Get("anthropic-version"); got != versionAnthropic {
			t.Errorf("anthropic-version = %q, se esperaba %q", got, versionAnthropic)
		}
		if r.Header.Get("x-api-key") == "" {
			t.Error("falta la cabecera x-api-key (Anthropic no usa Bearer)")
		}
		recibidas = append(recibidas, cuerpo)
		manejar(cuerpo, w)
	}))
	t.Cleanup(srv.Close)
	return &Client{
		endpoint: srv.URL,
		apiKey:   "clave-de-prueba",
		dialecto: DialectoAnthropic,
		http:     srv.Client(),
	}, &recibidas
}

const sseConPensamiento = `data: {"type":"message_start","message":{"usage":{"input_tokens":1200,"cache_read_input_tokens":800,"cache_creation_input_tokens":100}}}

data: {"type":"content_block_delta","delta":{"type":"thinking_delta","thinking":"El diff toca una consulta cruda."}}

data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"{\"findings\":[]}"}}

data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":42}}

data: [DONE]
`

// El hilo de pensamiento del panel dependía de un campo que nunca se pedía.
// Sin "display": "summarized" los bloques llegan VACÍOS —su default es
// "omitted"— así que la UI se quedaba en blanco sin un solo error que lo
// delatara. Este test falla si alguien vuelve a quitar el parámetro.
func TestStreamPidePensamientoConResumen(t *testing.T) {
	c, peticiones := clienteDePrueba(t, func(_ map[string]any, w http.ResponseWriter) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(sseConPensamiento))
	})

	var razonamiento, contenido strings.Builder
	res, err := c.CompleteStream(context.Background(), "claude-opus-5", "sys", "user", 30*time.Second, 0,
		func(kind, text string) {
			switch kind {
			case "reasoning":
				razonamiento.WriteString(text)
			case "content":
				contenido.WriteString(text)
			}
		})
	if err != nil {
		t.Fatalf("stream falló: %v", err)
	}

	pensamiento, ok := (*peticiones)[0]["thinking"].(map[string]any)
	if !ok {
		t.Fatal("la petición no llevaba el bloque thinking: el panel no recibirá razonamiento")
	}
	if pensamiento["type"] != "adaptive" {
		t.Errorf("thinking.type = %v, se esperaba adaptive", pensamiento["type"])
	}
	if pensamiento["display"] != "summarized" {
		t.Errorf("thinking.display = %v — sin summarized los bloques llegan vacíos", pensamiento["display"])
	}
	if razonamiento.Len() == 0 {
		t.Error("no llegó nada por onDelta(\"reasoning\")")
	}
	if res.Content != `{"findings":[]}` {
		t.Errorf("contenido = %q", res.Content)
	}
}

// El techo topa pensamiento MÁS respuesta, y el pensamiento viene encendido de
// fábrica. Con 4000 la sombra se cortaba a media respuesta.
func TestTechosPorCamino(t *testing.T) {
	c, peticiones := clienteDePrueba(t, func(cuerpo map[string]any, w http.ResponseWriter) {
		if cuerpo["stream"] == true {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte(sseConPensamiento))
			return
		}
		_, _ = w.Write([]byte(`{"content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`))
	})

	if _, err := c.Complete(context.Background(), "claude-opus-5", "sys", "user", 30*time.Second, 0); err != nil {
		t.Fatalf("Complete falló: %v", err)
	}
	if _, err := c.CompleteStream(context.Background(), "claude-opus-5", "sys", "user", 30*time.Second, 0, nil); err != nil {
		t.Fatalf("CompleteStream falló: %v", err)
	}

	if got := (*peticiones)[0]["max_tokens"]; got != float64(techoAnthropic) {
		t.Errorf("techo de la llamada suelta = %v, se esperaba %d", got, techoAnthropic)
	}
	if got := (*peticiones)[1]["max_tokens"]; got != float64(techoAnthropicStream) {
		t.Errorf("techo del stream = %v, se esperaba %d", got, techoAnthropicStream)
	}
	// La llamada mecánica no muestra razonamiento en ninguna parte: pedirlo
	// sería gastar presupuesto del techo para tirarlo.
	if _, pidio := (*peticiones)[0]["thinking"]; pidio {
		t.Error("la llamada no-streaming no debe pedir pensamiento")
	}
	// Y un techo explícito del llamador manda sobre el default.
	if _, err := c.Complete(context.Background(), "claude-opus-5", "sys", "user", 30*time.Second, 500); err != nil {
		t.Fatal(err)
	}
	if got := (*peticiones)[2]["max_tokens"]; got != float64(500) {
		t.Errorf("techo explícito ignorado: %v", got)
	}
}

// El pensamiento adaptativo no existe antes de la generación 4.6: esos modelos
// devuelven 400. Se reintenta sin él en vez de dejar sin capa de consejo a
// quien apunte a un modelo viejo.
func TestStreamReintentaSinPensamientoEn400(t *testing.T) {
	intento := 0
	c, peticiones := clienteDePrueba(t, func(_ map[string]any, w http.ResponseWriter) {
		intento++
		if intento == 1 {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":{"message":"thinking: unsupported parameter for this model"}}`))
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(sseConPensamiento))
	})

	res, err := c.CompleteStream(context.Background(), "modelo-viejo", "sys", "user", 30*time.Second, 0, nil)
	if err != nil {
		t.Fatalf("el reintento sin pensamiento debía funcionar: %v", err)
	}
	if res.Content == "" {
		t.Error("sin contenido tras el reintento")
	}
	if len(*peticiones) != 2 {
		t.Fatalf("se esperaban 2 peticiones, hubo %d", len(*peticiones))
	}
	if _, pidio := (*peticiones)[1]["thinking"]; pidio {
		t.Error("el reintento volvió a pedir pensamiento: bucle garantizado")
	}
}

// Un 400 que NO habla de thinking no se debe reintentar: sería esconder el
// error real detrás de una segunda llamada idéntica.
func TestStreamNoReintentaOtros400(t *testing.T) {
	c, peticiones := clienteDePrueba(t, func(_ map[string]any, w http.ResponseWriter) {
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"error":{"code":"invalid_api_key"}}`))
	})
	_, err := c.CompleteStream(context.Background(), "claude-opus-5", "sys", "user", 30*time.Second, 0, nil)
	if err == nil {
		t.Fatal("un 400 de credenciales debe fallar, no reintentarse")
	}
	if len(*peticiones) != 1 {
		t.Errorf("se reintentó un error que no era de thinking (%d peticiones)", len(*peticiones))
	}
	if !strings.Contains(err.Error(), "clave") {
		t.Errorf("el error debería conservar la pista de la clave: %v", err)
	}
}

// Una negativa de los clasificadores llega con HTTP 200 y contenido vacío. Sin
// chequear stop_reason se lee como "el modelo no encontró nada", y la sombra
// registraba cero hallazgos sin explicar por qué. CodeGuard analiza código de
// seguridad: es justo lo que esos clasificadores rozan.
func TestNegativaNoPasaPorRespuestaBuena(t *testing.T) {
	c, _ := clienteDePrueba(t, func(_ map[string]any, w http.ResponseWriter) {
		_, _ = w.Write([]byte(`{"content":[],"stop_reason":"refusal",
			"stop_details":{"type":"refusal","category":"cyber","explanation":"contenido rechazado"},
			"usage":{"input_tokens":900,"output_tokens":0}}`))
	})

	res, err := c.Complete(context.Background(), "claude-opus-5", "sys", "user", 30*time.Second, 0)
	if err == nil {
		t.Fatalf("una negativa debe ser error, no una respuesta vacía: %+v", res)
	}
	for _, esperado := range []string{"declinó", "cyber", "clasificadores"} {
		if !strings.Contains(err.Error(), esperado) {
			t.Errorf("el error no menciona %q:\n%v", esperado, err)
		}
	}
}

// La negativa también puede llegar a mitad del stream, con texto ya entregado.
// Se descarta lo parcial: media respuesta de un análisis es peor que ninguna,
// porque parece completa.
func TestNegativaAMitadDelStreamDescartaLoParcial(t *testing.T) {
	c, _ := clienteDePrueba(t, func(_ map[string]any, w http.ResponseWriter) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(`data: {"type":"message_start","message":{"usage":{"input_tokens":900}}}

data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"{\"findings\":[{\"file\":"}}

data: {"type":"message_delta","delta":{"stop_reason":"refusal","stop_details":{"category":"cyber","explanation":"cortado"}},"usage":{"output_tokens":9}}
`))
	})

	res, err := c.CompleteStream(context.Background(), "claude-opus-5", "sys", "user", 30*time.Second, 0, nil)
	if err == nil {
		t.Fatalf("la negativa a mitad de stream debe ser error, se devolvió: %+v", res)
	}
	if res != nil {
		t.Error("no se debe devolver el JSON a medias: parsearlo daría hallazgos inventados")
	}
}

// PromptTokens (input_tokens) cuenta sólo el resto NO cacheado. Sin leer el
// desglose, lo servido desde caché no se cobraba en absoluto y el costo salía
// corto — el tope mensual se alcanzaba tarde, gastando más de lo autorizado.
func TestUsageLeeElDesgloseDeCache(t *testing.T) {
	c, _ := clienteDePrueba(t, func(cuerpo map[string]any, w http.ResponseWriter) {
		if cuerpo["stream"] == true {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte(sseConPensamiento))
			return
		}
		_, _ = w.Write([]byte(`{"content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn",
			"usage":{"input_tokens":1200,"output_tokens":42,
			"cache_read_input_tokens":800,"cache_creation_input_tokens":100}}`))
	})

	for _, caso := range []struct {
		nombre string
		correr func() (*Result, error)
	}{
		{"no-streaming", func() (*Result, error) {
			return c.Complete(context.Background(), "claude-opus-5", "s", "u", 30*time.Second, 0)
		}},
		{"streaming", func() (*Result, error) {
			return c.CompleteStream(context.Background(), "claude-opus-5", "s", "u", 30*time.Second, 0, nil)
		}},
	} {
		res, err := caso.correr()
		if err != nil {
			t.Fatalf("%s: %v", caso.nombre, err)
		}
		if res.Usage.PromptTokens != 1200 || res.Usage.CompletionTokens != 42 {
			t.Errorf("%s: tokens base = %d/%d", caso.nombre, res.Usage.PromptTokens, res.Usage.CompletionTokens)
		}
		if res.Usage.CacheReadTokens != 800 {
			t.Errorf("%s: lectura de caché = %d, se esperaban 800", caso.nombre, res.Usage.CacheReadTokens)
		}
		if res.Usage.CacheCreationTokens != 100 {
			t.Errorf("%s: escritura de caché = %d, se esperaban 100", caso.nombre, res.Usage.CacheCreationTokens)
		}
	}
}
