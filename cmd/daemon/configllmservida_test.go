package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// EL NOMBRE DE LA VARIABLE NO ES UNA CREDENCIAL, Y TAPARLO ROMPÍA EL GUARDADO.
//
// El enmascarado por nombre de campo tapaba "api_key_env" porque contiene "key".
// config.html llena con ese valor el campo del formulario y lo devuelve al
// guardar, así que guardarLLMLocal acababa escribiendo la clave bajo la variable
// "__codeguard_guardada__" y la capa de consejo buscaba una variable inexistente.
func TestElNombreDeLaVariableSeSirveEnClaro(t *testing.T) {
	crudo, err := configLLMParaServir(estadoConfigLLM{
		Provider:  "openai",
		Endpoint:  "https://api.openai.com/v1",
		APIKeyEnv: "OPENAI_API_KEY",
		Model:     "gpt-4o-mini",
		HayKey:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(crudo, &m); err != nil {
		t.Fatal(err)
	}
	if m["api_key_env"] != "OPENAI_API_KEY" {
		t.Errorf("el nombre de la variable no llega entero al formulario: %v", m["api_key_env"])
	}
	if strings.Contains(string(crudo), claveEnmascarada) {
		t.Errorf("el centinela de clave tapada no tiene nada que hacer en el payload: %s", crudo)
	}
	if m["hay_key"] != true {
		t.Error("la ventana necesita saber QUE hay clave")
	}
}

// LA LISTA BLANCA: un campo nuevo en estadoConfigLLM no puede salir por HTTP sin
// que alguien lo añada a configLLMServida a propósito.
//
// Se comprueba comparando los dos conjuntos de claves JSON: si estadoConfigLLM
// gana un campo y este test no se toca, el campo NO está servido —que es lo que
// se quiere— y la diferencia queda documentada aquí. Al revés (algo servido que
// no exista en el estado) es un error de copia.
func TestSoloSeSirvenLosCamposDeLaListaBlanca(t *testing.T) {
	servidos := clavesJSON(t, configLLMServida{})
	delEstado := clavesJSON(t, estadoConfigLLM{})

	for k := range servidos {
		if !delEstado[k] {
			t.Errorf("se sirve %q, que no existe en estadoConfigLLM: error de copia", k)
		}
	}
	// La lista blanca de HOY es exactamente el estado de hoy, porque hoy ninguno
	// de sus campos es sensible. Si mañana se añade uno y NO se sirve, este
	// aserto avisa para que la decisión sea explícita en vez de por descuido.
	for k := range delEstado {
		if !servidos[k] {
			t.Errorf("estadoConfigLLM tiene %q y no se sirve: si es deliberado (campo "+
				"sensible), quítalo de este aserto y déjalo dicho; si no, añádelo a "+
				"configLLMServida", k)
		}
	}
}

func clavesJSON(t *testing.T, v any) map[string]bool {
	t.Helper()
	crudo, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(crudo, &m); err != nil {
		t.Fatal(err)
	}
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}
