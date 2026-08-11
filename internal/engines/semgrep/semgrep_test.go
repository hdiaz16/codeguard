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

// El campo "type" de un error NO siempre es string: para las variantes con
// argumentos semgrep serializa un arreglo cuyo primer elemento es el nombre.
// Payload real de bds.portal: un archivo TS parcialmente parseado. Declarar
// Type como string tumbaba el unmarshal COMPLETO — 45 hallazgos validos
// descartados por no poder leer el tipo de un aviso.
const salidaConTipoArreglo = `{
  "results": [
    {"check_id": "rulepacks.2026.08.2.semgrep.ts-explicit-any",
     "path": "frontend/src/lib/api.ts",
     "start": {"line": 12}, "end": {"line": 12},
     "extra": {"message": "any explicito", "severity": "ERROR",
               "lines": "function f(x: any) {", "metadata": {"pillar": "quality"}}}
  ],
  "errors": [
    {"code": 3, "level": "warn",
     "type": ["PartialParsing", [{"path": "frontend\\src\\features\\notifications\\index.ts",
       "start": {"line": 18, "col": 8, "offset": 0},
       "end": {"line": 18, "col": 12, "offset": 0}}]],
     "message": "Syntax error at line frontend\\src\\features\\notifications\\index.ts:18"}
  ]
}`

func TestTipoDeErrorComoArregloNoTumbaElEscaneo(t *testing.T) {
	res := parsear(t, salidaConTipoArreglo)
	if len(res.Results) != 1 {
		t.Fatalf("los hallazgos deben sobrevivir al tipo-arreglo; hubo %d", len(res.Results))
	}
	if got := res.Errors[0].Type; got != "PartialParsing" {
		t.Errorf("el nombre de la variante debe extraerse del arreglo: %q", got)
	}
	// Un archivo parcialmente parseado no invalida el escaneo.
	if res.fatal() != nil {
		t.Error("PartialParsing no es fatal: el resto del archivo y del repo se analizo")
	}
}

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

// Windows corta CreateProcess a 32767 caracteres y este motor pasa una ruta
// POR ARCHIVO. Medido: el repo bds.portal, con 854 archivos, genera 105 029
// caracteres — semgrep no llegaba a arrancar y las 112 reglas de la casa
// quedaban sin aplicar, tambien al generar la baseline. El repo del propio
// agente tiene 156 archivos (16 218 caracteres) y por eso nunca lo destapo.
func TestLotesRespetanElLimiteDeLineaDeComandos(t *testing.T) {
	// 854 rutas del largo real que tienen en ese repo.
	objetivos := make([]string, 854)
	for i := range objetivos {
		objetivos[i] = "C:\\Users\\alguien\\Desktop\\01-Proyectos-GitHub\\BODESA\\bds.portal\\backend\\internal\\infra\\archivo.go"
	}

	const limite = maxLineaComandos
	grupos := lotes(objetivos, limite)
	if len(grupos) < 2 {
		t.Fatalf("854 rutas largas deben trocearse; salio %d lote(s)", len(grupos))
	}

	var total int
	for i, g := range grupos {
		largo := 0
		for _, o := range g {
			largo += len(o) + 1
		}
		// Un lote de mas de un objetivo NUNCA debe pasarse del limite.
		if len(g) > 1 && largo > limite {
			t.Errorf("lote %d mide %d, por encima del limite %d", i, largo, limite)
		}
		total += len(g)
	}
	// Y sobre todo: no se puede perder ni un archivo por el camino. Analizar
	// un subconjunto en silencio es el fallo que esto viene a impedir.
	if total != len(objetivos) {
		t.Errorf("se perdieron objetivos: %d de %d", total, len(objetivos))
	}
}

// Una ruta tan larga que no cabe por si sola va en su propio lote, no se
// descarta: dejar de analizar un archivo sin decirlo es peor que una llamada
// que falle ruidosamente.
func TestLoteConUnObjetivoDemasiadoLargo(t *testing.T) {
	larga := strings.Repeat("x", 50)
	grupos := lotes([]string{larga, larga}, 40)
	if len(grupos) != 2 {
		t.Fatalf("se esperaban 2 lotes de uno, salieron %d", len(grupos))
	}
	for _, g := range grupos {
		if len(g) != 1 {
			t.Errorf("cada lote deberia llevar un solo objetivo, lleva %d", len(g))
		}
	}
}

// Pocos archivos —el caso del hook— siguen yendo en una sola invocacion: el
// troceado no puede costar arranques en frio de mas donde antes no los habia.
func TestPocosObjetivosVanEnUnSoloLote(t *testing.T) {
	grupos := lotes([]string{"a.go", "b.go", "c.go"}, maxLineaComandos)
	if len(grupos) != 1 {
		t.Errorf("tres archivos deben ir en un lote, salieron %d", len(grupos))
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
