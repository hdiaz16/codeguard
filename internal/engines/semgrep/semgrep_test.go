package semgrep

import (
	"encoding/json"
	"strings"
	"testing"
)

// Los tres payloads de abajo son salidas REALES de semgrep 1.x capturadas
// contra este mismo repo. El primero es el que estuvo mintiendo durante toda la
// vida del proyecto.

// Escaneo abortado: una raíz inválida y semgrep no analiza NADA. El JSON es
// válido y results viene vacío, así que sin mirar errors es indistinguible de
// un repo impecable. Ocurría porque `git ls-files` entrecomilla y escapa las
// rutas con acentos, y ese literal se pasaba como target.
const salidaEscaneoAbortado = `{
  "results": [],
  "errors": [
    {"code": 2, "level": "error", "type": "SemgrepError",
     "message": "Invalid scanning root: C:\\repo\\\"docs\\Telemetr\\303\\255a.md\""}
  ]
}`

// Escaneo sano: corrió de verdad. Trae errores, pero ninguno invalida el
// resultado — cinco reglas del pack no compilan (patrones inválidos para C# y
// Go) y tres archivos se pasaron de tiempo. Nótese que "Rule parse error"
// también llega con level "error": por eso el discriminador es el tipo.
const salidaConAvisos = `{
  "results": [
    {"check_id": "rulepacks.2026.08.2.semgrep.go-dinero-float",
     "path": "internal/config/config.go",
     "start": {"line": 106}, "end": {"line": 106},
     "extra": {"message": "Importe monetario en float64.", "severity": "ERROR",
               "lines": "\tPriceInPerMTok  float64", "metadata": {"pillar": "data"}}}
  ],
  "errors": [
    {"code": 2, "level": "error", "type": "Rule parse error",
     "rule_id": "rulepacks.2026.08.2.semgrep.log-dato-sensible",
     "message": "Invalid pattern for C#"},
    {"code": 2, "level": "error", "type": "Rule parse error",
     "rule_id": "rulepacks.2026.08.2.semgrep.pii-en-telemetria",
     "message": "Invalid pattern for C#"},
    {"code": 2, "level": "warn", "type": "Timeout",
     "message": "Timeout in cmd/daemon/frontend/3d-force-graph.js"}
  ]
}`

// Repo limpio de verdad: cero resultados y cero errores.
const salidaLimpia = `{"results": [], "errors": []}`

func parsear(t *testing.T, s string) sgResult {
	t.Helper()
	var res sgResult
	if err := json.Unmarshal([]byte(s), &res); err != nil {
		t.Fatalf("payload de prueba ilegible: %v", err)
	}
	return res
}

// El fallo que costó mas caro del proyecto: cero hallazgos y "no pude mirar"
// se contaban como lo mismo. `codeguard report` anunciaba COMPLETADO mientras
// habia 28 hallazgos reales, y la baseline se genero igual de ciega.
func TestEscaneoAbortadoNoPasaPorLimpio(t *testing.T) {
	abortado := parsear(t, salidaEscaneoAbortado)
	if len(abortado.Results) != 0 {
		t.Fatal("el payload de prueba debe traer cero resultados: ese es el caso")
	}
	e := abortado.fatal()
	if e == nil {
		t.Fatal("un escaneo abortado debe detectarse como fatal, no leerse como repo limpio")
	}
	if !strings.Contains(e.Message, "Invalid scanning root") {
		t.Errorf("el error fatal perdio su mensaje: %q", e.Message)
	}

	// Y un repo genuinamente limpio no debe confundirse con uno abortado.
	if parsear(t, salidaLimpia).fatal() != nil {
		t.Error("cero resultados y cero errores es un repo limpio, no un fallo")
	}
}

// Un "Rule parse error" llega con level "error" pero el escaneo SI corrio: sus
// resultados valen. Tratarlo como fatal apagaria el motor entero cada vez que
// una sola regla del pack tenga un patron invalido — que es justo lo que le
// pasa hoy a cinco reglas de este rulepack.
func TestUnaReglaRotaNoInvalidaElEscaneo(t *testing.T) {
	res := parsear(t, salidaConAvisos)
	if res.fatal() != nil {
		t.Error("reglas rotas y timeouts no invalidan el escaneo: sus hallazgos son buenos")
	}
	if len(res.Results) != 1 {
		t.Fatalf("se esperaba 1 hallazgo, hubo %d", len(res.Results))
	}

	rotas := res.reglasRotas()
	if len(rotas) != 2 {
		t.Fatalf("se esperaban 2 reglas rotas, hubo %d: %v", len(rotas), rotas)
	}
	for _, esperada := range []string{"log-dato-sensible", "pii-en-telemetria"} {
		var encontrada bool
		for _, r := range rotas {
			if r == esperada {
				encontrada = true
			}
		}
		if !encontrada {
			t.Errorf("%q no aparece entre las reglas rotas: %v", esperada, rotas)
		}
	}
	// El timeout es un aviso por archivo, no una regla rota.
	for _, r := range rotas {
		if strings.Contains(r, "Timeout") {
			t.Errorf("un timeout no es una regla rota: %v", rotas)
		}
	}
}

// El id que semgrep reporta viene con la ruta del rulepack por delante; al dev
// se le muestra el nombre corto.
func TestShortRuleID(t *testing.T) {
	casos := map[string]string{
		"rulepacks.2026.08.2.semgrep.go-dinero-float": "go-dinero-float",
		"go-dinero-float": "go-dinero-float",
		"":                "",
	}
	for entrada, esperado := range casos {
		if got := shortRuleID(entrada); got != esperado {
			t.Errorf("shortRuleID(%q) = %q, se esperaba %q", entrada, got, esperado)
		}
	}
}
