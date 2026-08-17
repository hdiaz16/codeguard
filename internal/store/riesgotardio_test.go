package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// EL UPDATE QUE NO TOCA NINGUNA FILA NO ES UN ERROR PARA database/sql, Y ESO
// ERA JUSTO EL AGUJERO.
//
// El run lo escribe el proceso del HOOK; risk_score y llm_used los escribe la
// sombra desde el DAEMON, después. Si la sombra llegaba primero, el
// `UPDATE runs ... WHERE id = ?` no encontraba la fila, devolvía err=nil y los
// llamadores encima hacían `_ = ...`. El riesgo se perdía para siempre sin una
// línea de log, y como risk_score no se pinta en ninguna pantalla, nadie podía
// notarlo.
//
// El contrato ahora: cero filas es distinguible, tiene nombre y se puede probar
// con errors.Is.
func TestUpdateRunLLMDiceCuandoNoTocaNingunaFila(t *testing.T) {
	s := bd(t)
	repoID := CanonicalRepoID("local/tardio")
	if err := s.UpsertRepo(repoID, "", "tardio"); err != nil {
		t.Fatal(err)
	}
	runID := NewULID()

	// La sombra llega ANTES que el hook: la fila todavía no existe.
	err := s.UpdateRunLLM(runID, 7, true)
	if !errors.Is(err, ErrRunNoExiste) {
		t.Fatalf("un UPDATE sin filas tiene que decirlo con ErrRunNoExiste, y devolvió: %v", err)
	}
	if !strings.Contains(err.Error(), runID) {
		t.Errorf("el error debe nombrar el run perdido para poder buscarlo en el log: %v", err)
	}

	// Y cuando la fila sí está, el dato queda escrito y no hay error.
	guardarRun(t, s, runID, repoID, "pass", nil)
	if err := s.UpdateRunLLM(runID, 7, true); err != nil {
		t.Fatalf("con el run ya persistido no debía fallar: %v", err)
	}
	var risk, usado int
	if err := s.db.QueryRow(`SELECT risk_score, llm_used FROM runs WHERE id = ?`, runID).
		Scan(&risk, &usado); err != nil {
		t.Fatal(err)
	}
	if risk != 7 || usado != 1 {
		t.Errorf("el riesgo no quedó anotado: risk=%d llm_used=%d", risk, usado)
	}
}

// RunExiste es la señal con la que el daemon espera al hook. Tiene que
// distinguir "todavía no está" de "está", sin inventarse ninguno de los dos.
func TestRunExisteSoloDiceQueSiCuandoLaFilaEsta(t *testing.T) {
	s := bd(t)
	repoID := CanonicalRepoID("local/existe")
	if err := s.UpsertRepo(repoID, "", "existe"); err != nil {
		t.Fatal(err)
	}
	runID := NewULID()

	switch existe, err := s.RunExiste(runID); {
	case err != nil:
		t.Fatalf("preguntar por un run que no está no es un fallo: %v", err)
	case existe:
		t.Fatal("dijo que existe un run que nadie ha escrito")
	}
	guardarRun(t, s, runID, repoID, "pass", nil)
	switch existe, err := s.RunExiste(runID); {
	case err != nil:
		t.Fatalf("preguntar por un run que sí está falló: %v", err)
	case !existe:
		t.Fatal("no vio la fila del run recién persistido")
	}
}

// LA CARRERA COMPLETA, DE PUNTA A PUNTA: EL SYNC LE GANA A LA SOMBRA.
//
// Orden de los hechos, que es exactamente el que se da en producción:
//
//  1. el hook persiste el run — risk_score y llm_used nacen en su DEFAULT 0;
//  2. el empuje oportunista dispara (no se coordina con la sombra) y el run
//     viaja al central con riesgo 0;
//  3. la sombra termina, hasta un minuto después, y anota el riesgo de verdad.
//
// Con `ON CONFLICT (id) DO NOTHING` ese 0 era la versión oficial PARA SIEMPRE:
// el central es el único consumidor de risk_score, así que la métrica de riesgo
// de la organización quedaba falseada y nada lo delataba.
//
// La corrección necesita las dos piezas y este test las prueba juntas: el
// DO UPDATE de los campos mutables (sync.go) para que la fila re-empujada
// corrija, y el retroceso de la marca de agua (reencolarRunParaCentral) para
// que la fila LLEGUE a re-empujarse — con la marca intacta no volvía a viajar
// nunca y el DO UPDATE no habría servido de nada.
func TestElRiesgoQueLlegaTardeAlcanzaAlCentral(t *testing.T) {
	ruta := filepath.Join(t.TempDir(), "central.db")
	central, err := sql.Open("sqlite", ruta+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { central.Close() })
	dsn := "sqlite:" + ruta

	s := bd(t)
	ctx := context.Background()
	repoID := CanonicalRepoID("local/carrera")
	if err := s.UpsertRepo(repoID, "", "carrera"); err != nil {
		t.Fatal(err)
	}
	runID := NewULID()
	guardarRun(t, s, runID, repoID, "pass", nil)

	// ── El sync le gana a la sombra ──
	if _, err := s.SyncCentral(ctx, dsn); err != nil {
		t.Fatalf("primer empuje: %v", err)
	}
	riesgoCentral := func() (int, int) {
		t.Helper()
		var risk, usado int
		if err := central.QueryRow(`SELECT risk_score, llm_used FROM runs WHERE id = ?`, runID).
			Scan(&risk, &usado); err != nil {
			t.Fatalf("leyendo el run en el central: %v", err)
		}
		return risk, usado
	}
	if risk, usado := riesgoCentral(); risk != 0 || usado != 0 {
		t.Fatalf("el montaje de la carrera no es el que se cree: el run viajó con risk=%d llm_used=%d", risk, usado)
	}

	// ── La sombra termina y anota el riesgo, tarde ──
	if err := s.UpdateRunLLM(runID, 7, true); err != nil {
		t.Fatalf("anotando el riesgo: %v", err)
	}

	// ── El siguiente empuje oportunista tiene que corregir el central ──
	res, err := s.SyncCentral(ctx, dsn)
	if err != nil {
		t.Fatalf("segundo empuje: %v", err)
	}
	if res.Runs != 1 {
		t.Errorf("el run corregido tenía que volver a viajar (marca retrocedida): resumen %+v", res)
	}
	if risk, usado := riesgoCentral(); risk != 7 || usado != 1 {
		t.Errorf("el central se quedó con el riesgo viejo: risk=%d llm_used=%d, se esperaba 7 y 1", risk, usado)
	}
	// Corregir no es duplicar: sigue habiendo UN run.
	if n := contar(t, central, "runs"); n != 1 {
		t.Errorf("el re-empuje duplicó filas: %d runs en el central", n)
	}
	// Y lo inmutable del run no se toca al corregir.
	var verdict string
	if err := central.QueryRow(`SELECT verdict FROM runs WHERE id = ?`, runID).Scan(&verdict); err != nil {
		t.Fatal(err)
	}
	if verdict != "pass" {
		t.Errorf("el veredicto original se perdió en la corrección: %q", verdict)
	}
}

// LA FRONTERA ENTRE LO MUTABLE Y LO INMUTABLE, ESCRITA.
//
// Sólo runs cambia después de crearse (risk_score y llm_used, que la sombra
// rellena tarde) y por eso sólo runs lleva DO UPDATE. Fijarlo aquí es lo que
// evita las dos regresiones simétricas: que un refactor devuelva runs a
// DO NOTHING —y con él la pérdida silenciosa del riesgo— o que alguien
// generalice el DO UPDATE a las demás tablas y un id repetido machaque un
// hallazgo bueno con uno corrupto.
func TestSoloRunsSeCorrigeAlReempujar(t *testing.T) {
	vistas := map[string]bool{}
	for _, tb := range tablasIncrementales {
		vistas[tb.nombre] = true
		ins := strings.Join(strings.Fields(tb.ins), " ") // el SQL va alineado; el contrato no depende de los espacios
		_, clausula, hayUpdate := strings.Cut(ins, "DO UPDATE SET ")
		if tb.nombre != "runs" {
			if hayUpdate {
				t.Errorf("%s es inmutable y su INSERT debe quedarse en DO NOTHING; lleva DO UPDATE SET %s",
					tb.nombre, clausula)
			}
			if !strings.Contains(ins, "ON CONFLICT (id) DO NOTHING") {
				t.Errorf("%s perdió su ON CONFLICT (id) DO NOTHING: %s", tb.nombre, ins)
			}
			continue
		}
		if !hayUpdate {
			t.Fatalf("runs sin DO UPDATE: un run empujado antes de que la sombra anote el riesgo "+
				"se quedaría con risk_score=0 en el central para siempre. INSERT: %s", ins)
		}
		for _, campo := range []string{"risk_score = excluded.risk_score", "llm_used = excluded.llm_used"} {
			if !strings.Contains(clausula, campo) {
				t.Errorf("el DO UPDATE de runs no corrige %q: %s", campo, clausula)
			}
		}
		if n := strings.Count(clausula, "excluded."); n != 2 {
			t.Errorf("el DO UPDATE de runs debe tocar SÓLO los dos campos que la sombra escribe tarde; "+
				"toca %d: %s", n, clausula)
		}
	}
	for _, nombre := range []string{"runs", "findings", "feedback", "llm_calls"} {
		if !vistas[nombre] {
			t.Errorf("la tabla %s desapareció del sync: el contrato de arriba dejó de cubrirla", nombre)
		}
	}
}
