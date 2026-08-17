package llm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"codeguard/internal/config"
)

// El cliente no puede llevar un plazo de red propio.
//
// Llevaba `Timeout: 3 * time.Minute`, y http.Client.Timeout cubre la petición
// ENTERA —incluida la lectura del cuerpo, o sea todo el stream—, así que
// cortaba a los tres minutos por mucho más plazo que hubiera pedido el
// llamador. timeout_ms no tiene tope en la config y el techo de salida del
// dialecto de Anthropic en streaming es de 64000 tokens: un razonador tarda más
// de tres minutos sin despeinarse. El corte llegaba encima disfrazado de error
// de red, indistinguible de un plazo agotado de verdad.
func TestElClienteNoLlevaPlazoDeRedFijo(t *testing.T) {
	c := NewConClave(config.LLM{Provider: "openai", Endpoint: "https://api.openai.com/v1"}, "clave")
	if c == nil {
		t.Fatal("con endpoint y clave el cliente debía construirse")
	}
	if c.http.Timeout != 0 {
		t.Errorf("el cliente lleva un plazo de red fijo de %v: corta por debajo del plazo "+
			"configurado y el error no se distingue de un timeout normal", c.http.Timeout)
	}
}

// Y sin ese plazo, el que corta es el context de cada llamada.
//
// Es la otra mitad del cambio anterior: quitar el techo del Client sólo es
// correcto porque los cuatro caminos que lo usan abren con
// context.WithTimeout(ctx, timeout). Si alguno dejara de hacerlo, la llamada se
// quedaría colgada para siempre contra un servidor que no contesta — que es
// exactamente lo que este servidor hace.
func TestElPlazoQueCortaEsElDelLlamador(t *testing.T) {
	fin := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done(): // el cliente colgó: es lo que se espera
		case <-fin:
		}
	}))
	// Orden a propósito: close(fin) corre ANTES de srv.Close(), que espera a que
	// terminen las peticiones en vuelo. Si la prueba falla, soltar al manejador
	// es lo que evita que el binario se quede colgado en vez de reportar.
	defer srv.Close()
	defer close(fin)

	const plazo = 150 * time.Millisecond
	casos := []struct {
		nombre   string
		provider string
		correr   func(*Client) error
	}{
		{"openai · Complete", "openai", func(c *Client) error {
			_, err := c.Complete(context.Background(), "m", "s", "u", plazo, 64)
			return err
		}},
		{"openai · CompleteStream", "openai", func(c *Client) error {
			_, err := c.CompleteStream(context.Background(), "m", "s", "u", plazo, 64, nil)
			return err
		}},
		{"anthropic · Complete", "anthropic", func(c *Client) error {
			_, err := c.Complete(context.Background(), "m", "s", "u", plazo, 64)
			return err
		}},
		{"anthropic · CompleteStream", "anthropic", func(c *Client) error {
			_, err := c.CompleteStream(context.Background(), "m", "s", "u", plazo, 64, nil)
			return err
		}},
	}

	for _, caso := range casos {
		t.Run(caso.nombre, func(t *testing.T) {
			c := NewConClave(config.LLM{Provider: caso.provider, Endpoint: srv.URL}, "clave-de-prueba")
			if c == nil {
				t.Fatal("el cliente debía construirse")
			}
			hecho := make(chan error, 1)
			inicio := time.Now()
			go func() { hecho <- caso.correr(c) }()
			select {
			case err := <-hecho:
				if err == nil {
					t.Fatal("un servidor que no responde nunca no puede dar una respuesta buena")
				}
				if transcurrido := time.Since(inicio); transcurrido < plazo {
					t.Errorf("cortó en %v, antes del plazo pedido (%v)", transcurrido, plazo)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("la llamada no cortó por su cuenta: sin plazo en el Client, el context " +
					"de la llamada es lo ÚNICO que la para, y aquí no la paró nada")
			}
		})
	}
}
