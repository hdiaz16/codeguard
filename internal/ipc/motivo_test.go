package ipc

// El motivo de un análisis omitido tiene que sobrevivir al pipe.
//
// El pipeline calcula POR QUÉ no analizó ("todos los archivos tocados están
// excluidos", "merge o revert"...) y el camino de CI lo imprime, pero por el
// canal del daemon —el del commit de todos los días— se perdía: Response no
// tenía dónde meterlo. El hook podía decir "no se revisó nada" y no por qué.
//
// Es el mismo fallo que ya se corrigió para la paridad con ParityReason: un
// aviso sin motivo es de los que se aprenden a ignorar.

import (
	"encoding/json"
	"testing"
)

// claves devuelve los nombres de campo del JSON, para poder afirmar sobre uno
// concreto.
//
// Buscar la subcadena "reason" no servía: "parity_reason" la contiene, así que
// la aserción pasaba con Reason vacío y ParityReason relleno —comprobado— y
// habría dado por bueno un campo que no existía. Es la clase de guardia que
// tranquiliza sin vigilar nada.
func claves(t *testing.T, crudo []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(crudo, &m); err != nil {
		t.Fatalf("el JSON del pipe no se pudo inspeccionar: %v", err)
	}
	return m
}

func TestElMotivoCruzaElPipe(t *testing.T) {
	const motivo = "todos los archivos tocados están excluidos"

	crudo, err := json.Marshal(Response{RunID: "r1", Verdict: "skipped", Reason: motivo})
	if err != nil {
		t.Fatalf("no se pudo serializar: %v", err)
	}
	if v, hay := claves(t, crudo)["reason"]; !hay {
		t.Errorf("el campo reason no aparece en el JSON que viaja:\n%s", crudo)
	} else if v != motivo {
		t.Errorf("el campo reason viaja con otro valor: %q", v)
	}

	var vuelta Response
	if err := json.Unmarshal(crudo, &vuelta); err != nil {
		t.Fatalf("no se pudo deserializar: %v", err)
	}
	if vuelta.Reason != motivo {
		t.Errorf("el motivo se perdió al cruzar: %q", vuelta.Reason)
	}
}

// Una actualización a medias no puede romper el canal. Son los dos casos reales
// mientras se sustituye el binario: el daemon viejo sigue vivo con la CLI nueva
// ya instalada, o al revés.
func TestElCampoNuevoNoRompeUnaActualizacionAMedias(t *testing.T) {
	// Daemon VIEJO → CLI nueva: la respuesta no trae el campo. Tiene que
	// deserializar sin error y dejar el motivo vacío, que es lo que el hook
	// interpreta como "no llegó".
	t.Run("respuesta sin el campo", func(t *testing.T) {
		vieja := `{"protocol_version":1,"run_id":"r1","verdict":"skipped","degraded":[]}`
		var resp Response
		if err := json.Unmarshal([]byte(vieja), &resp); err != nil {
			t.Fatalf("una respuesta vieja tiene que seguir leyéndose: %v", err)
		}
		if resp.Verdict != "skipped" {
			t.Errorf("veredicto: %q", resp.Verdict)
		}
		if resp.Reason != "" {
			t.Errorf("sin campo el motivo debe quedar vacío, y quedó %q", resp.Reason)
		}
	})

	// Daemon NUEVO → CLI vieja: la respuesta trae un campo que el struct de la
	// CLI vieja no conoce. encoding/json lo ignora en vez de fallar, y esta
	// prueba lo fija: si alguien pusiera DisallowUnknownFields, una
	// actualización a medias dejaría de hablarse y esto lo cazaría.
	t.Run("respuesta con un campo que no se conoce", func(t *testing.T) {
		nueva := `{"protocol_version":1,"run_id":"r1","verdict":"skipped","reason":"merge o revert","campo_del_futuro":42}`
		var resp Response
		if err := json.Unmarshal([]byte(nueva), &resp); err != nil {
			t.Fatalf("un campo desconocido no puede romper la lectura: %v", err)
		}
		if resp.Reason != "merge o revert" {
			t.Errorf("motivo: %q", resp.Reason)
		}
	})

	// Y cuando no hay motivo, los bytes son los de siempre: omitempty mantiene
	// el formato idéntico para quien no mira este campo. Por eso no hace falta
	// subir ProtocolVersion.
	//
	// Se comprueba la clave exacta y con ParityReason RELLENO a propósito: con
	// un Contains("reason") esta prueba daba un rojo espurio en cuanto una
	// respuesta llevara paridad rota, que es un caso normalísimo.
	t.Run("sin motivo el formato no cambia", func(t *testing.T) {
		crudo, err := json.Marshal(Response{RunID: "r1", Verdict: "pass",
			ParityReason: "el rulepack cambió durante el commit"})
		if err != nil {
			t.Fatal(err)
		}
		m := claves(t, crudo)
		if _, hay := m["reason"]; hay {
			t.Errorf("un análisis normal no debe llevar el campo:\n%s", crudo)
		}
		if _, hay := m["parity_reason"]; !hay {
			t.Errorf("y el campo de la paridad sí tiene que seguir viajando:\n%s", crudo)
		}
	})
}
