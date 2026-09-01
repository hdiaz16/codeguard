package main

import (
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"codeguard/internal/capas"
	"codeguard/internal/daemon"
	"codeguard/internal/finding"
)

// El panel lee el payload por NOMBRE de campo JSON. Si un campo se renombra en
// Go, el HTML no falla: pinta `undefined`, o directamente no pinta — que es
// peor, porque un panel que se calla se lee como "no hay nada que decir".
//
// Ya pasó en este proyecto con el evento del panel al enrolar: la señal se
// emitía, nadie la recibía, y desde fuera era indistinguible de que no hubiera
// ocurrido nada. Esta prueba ata los dos lados: cada `p.campo` que el HTML lee
// tiene que existir en el JSON que Go manda.
func TestElPanelNoLeeCamposQueGoNoManda(t *testing.T) {
	html, err := os.ReadFile("frontend/index.html")
	if err != nil {
		t.Fatal(err)
	}

	// Un payload con TODO relleno: los campos con omitempty desaparecen del
	// JSON si van vacíos, y entonces esta prueba no probaría nada de ellos.
	p := &panelPayload{
		Repo: "demo", RepoRoot: "C:/repos/demo", Branch: "master",
		AIGenerated: true, Suppressed: 1,
		Languages:     []string{"go"},
		Capas:         []capas.Capa{{Motor: "gitleaks", Estado: capas.Corrio, Hallazgos: 1, Ms: 2, Detalle: "x"}},
		CapasRepo:     []string{"semgrep", "gofmt"},
		NoDisponibles: []daemon.NoDisponible{{Motor: "tsc", Falta: "npx", Motivo: "no encuentro npx"}},
		SecretosEn:    []string{"internal/pago/llave.go:3"},
		OtrosRepos:    []proyectoEnLista{{Marca: "✓", Nombre: "demo", Ruta: "C:/repos/demo", Activo: true, Verdict: "pass", Outcome: "clean", Blocking: 1, Advisory: 2, Cuando: "11:00"}},
		Verdict:       "pass", Reason: "x", Blocking: 1, Advisory: 2, CIParity: true,
		Outcome:      "clean",
		GarantiaRota: []string{"x"},
		Degraded:     []string{"x"},
		Findings:     []panelFinding{{Finding: finding.Finding{File: "a.go"}}},
		MaxShow:      7,
		ElapsedMs:    3,
		At:           "11:00",
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}

	// Los tres ámbitos que el HTML recorre: el payload, cada proyecto de la
	// lista y cada capa.
	repo := primerElemento(t, payload["otros_repos"])
	capa := primerElemento(t, payload["capas"])
	noDisp := primerElemento(t, payload["no_disponibles"])

	for _, c := range []struct {
		nombre   string
		variable string
		re       *regexp.Regexp
		campos   map[string]any
	}{
		{"payload", "p", regexp.MustCompile(`\bp\.([a-z_][a-z_0-9]*)`), payload},
		{"proyecto de la lista", "r", regexp.MustCompile(`\br\.([a-z_][a-z_0-9]*)`), repo},
		{"capa", "c", regexp.MustCompile(`\bc\.([a-z_][a-z_0-9]*)`), capa},
		// La variable se llama `nd` y no `d` a propósito: `d` ya se usa en el
		// panel para otras cosas (d.pillar, d.text…), y un ámbito de una sola
		// letra reutilizada haría que esta prueba comparase campos de objetos
		// distintos y fallara sin motivo.
		{"capa que no puede correr", "nd", regexp.MustCompile(`\bnd\.([a-z_][a-z_0-9]*)`), noDisp},
	} {
		vistos := map[string]bool{}
		for _, m := range c.re.FindAllStringSubmatch(string(html), -1) {
			campo := m[1]
			if vistos[campo] {
				continue
			}
			vistos[campo] = true
			if _, ok := c.campos[campo]; !ok {
				t.Errorf("index.html lee %s.%s y ese campo NO viaja en el JSON del %s.\n"+
					"  El panel pintaría «undefined» o se quedaría mudo, que es peor.\n"+
					"  campos que sí manda Go: %v",
					c.variable, campo, c.nombre, claves(c.campos))
			}
		}
		if len(vistos) == 0 {
			t.Errorf("no se encontró ninguna lectura del %s en index.html: "+
				"o cambió el nombre de la variable y esta prueba dejó de mirar nada", c.nombre)
		}
	}
}

func TestElPanelSoloPintaVerdeUnOutcomeClean(t *testing.T) {
	raw, err := os.ReadFile("frontend/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	if strings.Contains(html, `if (p.verdict === "block")`) {
		t.Fatal("el encabezado del panel volvió a derivar desde verdict legacy")
	}
	if !strings.Contains(html, `else if (outcome === "clean")`) {
		t.Fatal("el panel no tiene una rama explícita para el único estado verde")
	}
	if n := strings.Count(html, `ponVeredicto("pass"`); n != 1 {
		t.Fatalf("el verde debe tener un solo origen (outcome=clean); hay %d", n)
	}
	for _, estado := range []string{"findings", "degraded", "failed", "skipped"} {
		if !strings.Contains(html, `outcome === "`+estado+`"`) {
			t.Fatalf("el panel no representa explícitamente outcome=%s", estado)
		}
	}
}

func TestElPanelExplicaUnBloqueoPorCoberturaSinInventarCeroProblemas(t *testing.T) {
	raw, err := os.ReadFile("frontend/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(raw)
	for _, contrato := range []string{
		`if (p.blocking > 0)`,
		`Bloqueado: una capa obligatoria no pudo completar el análisis.`,
		`function garantiaEnClaro(codigo)`,
		`<b>Cobertura incompleta.</b>`,
		`<code>${esc(c)}`, // conserva el código técnico además de explicarlo
	} {
		if !strings.Contains(html, contrato) {
			t.Errorf("falta el contrato editorial/visual %q", contrato)
		}
	}
	if strings.Contains(html, `ponVeredicto("working", "Commit realizado, pero`) {
		t.Error("un análisis ya terminado conserva el spinner de 'analizando'")
	}
	if strings.Contains(html, "Commit realizado") {
		t.Error("el panel afirma que Git ya creó el commit durante pre-commit")
	}
}

// Los elementos que el render busca por id tienen que existir en el HTML.
// Renombrar un id no rompe nada visible: el panel simplemente deja de enseñar
// esa parte.
func TestLosElementosQueElPanelBuscaExisten(t *testing.T) {
	html, err := os.ReadFile("frontend/index.html")
	if err != nil {
		t.Fatal(err)
	}
	texto := string(html)
	for _, id := range []string{"verdict", "meta", "parity", "stack", "motores",
		"proyectos", "tabs", "main", "thinking", "card"} {
		if !regexp.MustCompile(`id="` + id + `"`).MatchString(texto) {
			t.Errorf("el panel hace $(%q) y no existe ningún id=%q en index.html", id, id)
		}
	}
}

func primerElemento(t *testing.T, v any) map[string]any {
	t.Helper()
	lista, ok := v.([]any)
	if !ok || len(lista) == 0 {
		t.Fatalf("esperaba una lista con al menos un elemento, llegó %#v", v)
	}
	m, ok := lista[0].(map[string]any)
	if !ok {
		t.Fatalf("esperaba un objeto, llegó %#v", lista[0])
	}
	return m
}

func claves(m map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
