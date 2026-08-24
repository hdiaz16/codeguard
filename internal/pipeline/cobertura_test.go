package pipeline

import (
	"context"
	"slices"
	"testing"

	"codeguard/internal/capas"
	"codeguard/internal/engines"
	"codeguard/internal/finding"
)

// motorConCobertura es un adaptador que DECLARA cobertura: fija su plan y los
// recibos que devuelve, para modelar el caso que el bool Applies no distinguía
// —«corrí y salí con 0» de «omití un objetivo y salí con 0»— (W6 Q2).
type motorConCobertura struct {
	nombre    string
	plan      []engines.Unidad
	recibos   []engines.Recibo
	hallazgos []finding.Finding
	err       error
}

func (m *motorConCobertura) Name() string               { return m.nombre }
func (m *motorConCobertura) Applies(engines.Input) bool { return true }

// Run existe porque ConCobertura embebe Engine; el pipeline usa
// RunConCobertura, así que este camino no debería tomarse.
func (m *motorConCobertura) Run(context.Context, engines.Input) ([]finding.Finding, error) {
	return m.hallazgos, m.err
}
func (m *motorConCobertura) Plan(engines.Input) []engines.Unidad { return m.plan }
func (m *motorConCobertura) RunConCobertura(context.Context, engines.Input) (engines.Resultado, error) {
	return engines.Resultado{Findings: m.hallazgos, Recibos: m.recibos}, m.err
}

func uni(ruta string) engines.Unidad { return engines.Unidad{Clase: "file", Ruta: ruta} }

// EL caso que da nombre a la tanda: un motor promete mirar dos archivos, mira
// UNO, y sale con éxito y cero hallazgos. Sin recibos eso era un «limpio»
// perfecto sobre un archivo que nadie miró. Con el contrato, la capa se degrada
// y el veredicto deja de ser limpio.
func TestUnMotorQueOmiteUnObjetivoNoEsLimpioAunqueSalgaConCero(t *testing.T) {
	omisor := &motorConCobertura{
		nombre: "omisor",
		plan:   []engines.Unidad{uni("a.py"), uni("b.py")},
		// b.py se quedó sin recibo: se prometió y no hay prueba de haberlo mirado.
		recibos: []engines.Recibo{{Unidad: uni("a.py"), Estado: engines.CoberturaCompleta}},
	}
	res := correrConMotores(t, []engines.Engine{omisor})

	if !slices.Contains(res.Degraded, "omisor:cobertura-parcial") {
		t.Errorf("una omisión silenciosa debe degradar la capa; Degraded = %v", res.Degraded)
	}
	c := capaDeMotor(t, res, "omisor")
	if c.Estado != capas.Degradada {
		t.Errorf("la capa con hueco debe estar Degradada, no %q", c.Estado)
	}
	if c.Planeadas != 2 || c.Completas != 1 || c.Parciales != 1 {
		t.Errorf("conteo de cobertura mal: planeadas=%d completas=%d parciales=%d (esperaba 2/1/1)",
			c.Planeadas, c.Completas, c.Parciales)
	}
	// El veredicto único lo confirma: garantía rota ⇒ Degradado, no Limpio.
	o := Finalizar(res, "", nil)
	if o.Estado != Degradado {
		t.Errorf("un motor que no cubrió lo prometido no puede dar %q; esperaba Degradado", o.Estado)
	}
}

// Un recibo PARCIAL (parser a medias, timeout de un objetivo) también es hueco,
// aunque el objetivo sí se tocó: lo que no se pudo leer no está cubierto.
func TestUnReciboParcialTambienDegrada(t *testing.T) {
	m := &motorConCobertura{
		nombre:  "parcial",
		plan:    []engines.Unidad{uni("x.py")},
		recibos: []engines.Recibo{{Unidad: uni("x.py"), Estado: engines.CoberturaParcial, Motivo: "parser-parcial"}},
		// Con hallazgos válidos: el contrato conserva los hallazgos Y degrada.
		hallazgos: []finding.Finding{mk("r1", "x.py", 3, false)},
	}
	res := correrConMotores(t, []engines.Engine{m})

	if !slices.Contains(res.Degraded, "parcial:cobertura-parcial") {
		t.Errorf("un parcial debe degradar; Degraded = %v", res.Degraded)
	}
	// Los hallazgos válidos NO se pierden: ese era el motivo de no degradar antes.
	if len(res.Findings) != 1 {
		t.Errorf("el hallazgo válido del análisis parcial debe conservarse; hubo %d", len(res.Findings))
	}
}

// El control positivo: cubrir TODO lo prometido no degrada nada y da limpio.
func TestUnMotorQueCubreTodoLoPrometidoEsLimpio(t *testing.T) {
	m := &motorConCobertura{
		nombre: "completo",
		plan:   []engines.Unidad{uni("a.py"), uni("b.py")},
		recibos: []engines.Recibo{
			{Unidad: uni("a.py"), Estado: engines.CoberturaCompleta},
			{Unidad: uni("b.py"), Estado: engines.CoberturaCompleta},
		},
	}
	res := correrConMotores(t, []engines.Engine{m})

	if slices.Contains(res.Degraded, "completo:cobertura-parcial") {
		t.Errorf("cubrir todo no debe degradar; Degraded = %v", res.Degraded)
	}
	c := capaDeMotor(t, res, "completo")
	if c.Estado != capas.Corrio {
		t.Errorf("cobertura completa ⇒ Corrio, no %q", c.Estado)
	}
	if c.Planeadas != 2 || c.Completas != 2 || c.Parciales != 0 {
		t.Errorf("conteo mal: %d/%d/%d (esperaba 2/2/0)", c.Planeadas, c.Completas, c.Parciales)
	}
	if o := Finalizar(res, "", nil); o.Estado != Limpio {
		t.Errorf("cobertura completa sin hallazgos ⇒ Limpio, no %q", o.Estado)
	}
}

func capaDeMotor(t *testing.T, res *Result, motor string) capas.Capa {
	t.Helper()
	for _, c := range res.Capas {
		if c.Motor == motor {
			return c
		}
	}
	t.Fatalf("no apareció la capa de %q en %+v", motor, res.Capas)
	return capas.Capa{}
}

// Unidad de resumirCobertura: el cruce plan-vs-recibos y la regla del peor
// estado (un objetivo que llega completo y parcial cuenta como parcial).
func TestResumirCoberturaCruzaPlanContraRecibos(t *testing.T) {
	plan := []engines.Unidad{uni("a"), uni("b"), uni("c")}
	recibos := []engines.Recibo{
		{Unidad: uni("a"), Estado: engines.CoberturaCompleta},
		{Unidad: uni("b"), Estado: engines.CoberturaParcial},
		// c no tiene recibo → omitida.
		// un recibo de una unidad que NO estaba en el plan se ignora:
		{Unidad: uni("z"), Estado: engines.CoberturaCompleta},
	}
	r := resumirCobertura(plan, recibos)
	if r.Planeadas != 3 || r.Completas != 1 || r.Parciales != 1 || r.Omitidas != 1 {
		t.Fatalf("resumen mal: planeadas=%d completas=%d parciales=%d omitidas=%d",
			r.Planeadas, r.Completas, r.Parciales, r.Omitidas)
	}
	if !r.hayHueco() {
		t.Error("con una parcial y una omitida tiene que haber hueco")
	}

	// El peor estado manda: si el mismo objetivo llega completo y luego parcial,
	// la unidad es parcial (un «completo» no borra un «parcial»).
	r2 := resumirCobertura([]engines.Unidad{uni("a")}, []engines.Recibo{
		{Unidad: uni("a"), Estado: engines.CoberturaCompleta},
		{Unidad: uni("a"), Estado: engines.CoberturaParcial},
	})
	if r2.Parciales != 1 || r2.Completas != 0 {
		t.Errorf("el peor estado debe mandar: %d parciales, %d completas (esperaba 1/0)", r2.Parciales, r2.Completas)
	}

	// Un motor que declara cobertura pero no planeó nada no tiene hueco.
	if resumirCobertura(nil, nil).hayHueco() {
		t.Error("sin plan no hay hueco que reportar")
	}
}
