package llm

import "testing"

// Un endpoint de Azure pegado del portal viene sin ruta, y la API clásica
// responde "Missing required query parameter: api-version" — un error que no
// dice en ninguna parte que falta un trozo de URL. Pasó de verdad al
// configurar el agente por primera vez.
func TestNormalizarEndpointAzure(t *testing.T) {
	casos := []struct{ entrada, esperado, porque string }{
		{
			"https://mi-recurso.services.ai.azure.com",
			"https://mi-recurso.services.ai.azure.com/openai/v1",
			"host pelado de Foundry: se completa a la API moderna",
		},
		{
			"https://mi-recurso.services.ai.azure.com/",
			"https://mi-recurso.services.ai.azure.com/openai/v1",
			"la barra final no cambia nada",
		},
		{
			"https://mi-recurso.openai.azure.com",
			"https://mi-recurso.openai.azure.com/openai/v1",
			"el host clásico de Azure OpenAI también",
		},
		{
			"https://mi-recurso.services.ai.azure.com/openai/v1",
			"https://mi-recurso.services.ai.azure.com/openai/v1",
			"ya normalizado: no se toca",
		},
		{
			"https://mi-recurso.openai.azure.com/openai/deployments/x?api-version=2024-02-01",
			"https://mi-recurso.openai.azure.com/openai/deployments/x?api-version=2024-02-01",
			"despliegue clásico deliberado: respetarlo",
		},
		{
			"https://api.openai.com/v1",
			"https://api.openai.com/v1",
			"lo que no es Azure no se toca",
		},
		{
			"http://localhost:11434/v1",
			"http://localhost:11434/v1",
			"un modelo local tampoco",
		},
		{"", "", "vacío se queda vacío"},
	}
	for _, c := range casos {
		if got := normalizarEndpoint(c.entrada); got != c.esperado {
			t.Errorf("%s\n  entrada:  %q\n  obtenido: %q\n  esperado: %q",
				c.porque, c.entrada, got, c.esperado)
		}
	}
}

func TestPistaDeErrorExplicaLoQueElProveedorNoDice(t *testing.T) {
	casos := []struct{ cuerpo, debeMencionar string }{
		{`{"error":{"message":"Missing required query parameter: api-version"}}`, "/openai/v1"},
		{`{"error":{"code":"DeploymentNotFound"}}`, "DESPLIEGUE"},
		{`{"error":{"code":"invalid_api_key"}}`, "clave"},
	}
	for _, c := range casos {
		pista := pistaDeError(c.cuerpo)
		if pista == "" {
			t.Errorf("sin pista para %q", c.cuerpo)
			continue
		}
		if !contiene(pista, c.debeMencionar) {
			t.Errorf("la pista para %q no menciona %q:\n%s", c.cuerpo, c.debeMencionar, pista)
		}
	}
	// Un error que no reconocemos no debe inventarse una explicación.
	if p := pistaDeError(`{"error":"algo raro"}`); p != "" {
		t.Errorf("no debía haber pista, hubo: %q", p)
	}
}

func contiene(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
