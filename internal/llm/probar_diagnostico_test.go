package llm

import (
	"strings"
	"testing"

	"codeguard/internal/config"
)

// Un proveedor mal escrito tiene que decirse por su nombre.
//
// NewConClave se niega a armar el cliente cuando el nombre no está en la tabla
// (llm.go:181), pero el diagnóstico de Probar descartaba el bool de
// BuscarProveedor: el typo caía en el Proveedor de relleno —NecesitaKey en
// false— y el usuario recibía «configuración incompleta: revisa el endpoint»,
// que lo manda a auditar un endpoint que está perfecto. Es el mismo defecto que
// se cerró en el constructor, sobreviviendo en la pantalla que el usuario mira
// mientras configura.
func TestUnProveedorMalEscritoSeDicePorSuNombre(t *testing.T) {
	cfg := config.LLM{
		Provider:  "opeenai", // el typo
		Endpoint:  "https://api.openai.com/v1",
		Model:     "gpt-4o-mini",
		APIKeyEnv: "CODEGUARD_CLAVE_QUE_NO_EXISTE",
	}
	_, err := Probar(cfg, "")
	if err == nil {
		t.Fatal("un proveedor desconocido no puede dar por buena la configuración")
	}
	if !strings.Contains(err.Error(), "proveedor desconocido") ||
		!strings.Contains(err.Error(), "opeenai") {
		t.Errorf("el error no nombra el proveedor mal escrito: %v", err)
	}
	if strings.Contains(err.Error(), "revisa el endpoint") {
		t.Errorf("el error manda a revisar el endpoint, que no es el fallo: %v", err)
	}
}

// La reordenación no puede tapar el diagnóstico de la clave que falta: un
// proveedor CONOCIDO que exige clave y no la tiene sigue diciendo eso mismo.
func TestUnProveedorConocidoSinClaveSigueDiciendoQueFaltaLaClave(t *testing.T) {
	cfg := config.LLM{
		Provider:  "anthropic",
		Endpoint:  "https://api.anthropic.com",
		Model:     "claude-sonnet-4-5",
		APIKeyEnv: "CODEGUARD_CLAVE_QUE_NO_EXISTE",
	}
	_, err := Probar(cfg, "")
	if err == nil {
		t.Fatal("sin clave, un proveedor que la exige no puede dar por buena la configuración")
	}
	if !strings.Contains(err.Error(), "falta la clave") {
		t.Errorf("se perdió el diagnóstico de la clave ausente: %v", err)
	}
}

// Y el cierre de seguridad tampoco se pierde: con clave y endpoint HTTP remoto,
// el mensaje sigue siendo el de no enviar la credencial en claro.
func TestElCierreDeSeguridadDelEndpointSigueDiciendoLoSuyo(t *testing.T) {
	cfg := config.LLM{
		Provider: "openai",
		Endpoint: "http://modelo.remoto.example/v1",
		Model:    "gpt-4o-mini",
	}
	_, err := Probar(cfg, "clave-pegada-a-mano")
	if err == nil {
		t.Fatal("no se puede dar por buena una config que mandaría la clave por HTTP en claro")
	}
	if !strings.Contains(err.Error(), "no es HTTPS") {
		t.Errorf("se perdió el cierre de seguridad del endpoint: %v", err)
	}
}
