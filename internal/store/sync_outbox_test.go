package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"codeguard/internal/finding"
)

// La cuarentena no se traga el evento: un error PERMANENTE lo aísla y el resto
// de la cola sigue (muere el poison pill del lote de 500). Se fuerza un error
// permanente sembrando en el central una constraint que el evento viola, y se
// verifica que (a) ese evento queda en cuarentena con causa, (b) los demás
// llegan, (c) el evento no se perdió (sigue consultable).
func TestUnEventoEnvenenadoNoBloqueaElResto(t *testing.T) {
	ruta := filepath.Join(t.TempDir(), "central.db")
	dsn := "sqlite:" + ruta
	s := bd(t)
	ctx := context.Background()
	repoID := CanonicalRepoID("local/veneno")
	if err := s.UpsertRepo(repoID, "", "veneno"); err != nil {
		t.Fatal(err)
	}
	// Un run sano y su finding: viajan.
	runSano := NewULID()
	fSano := hallazgo("hallazgo sano")
	guardarRun(t, s, runSano, repoID, "pass", []finding.Finding{fSano})

	// El VENENO real: un finding cuyo evento NO viaja (lo dejo superseded, como
	// si su padre run se hubiera perdido), y un feedback que lo referencia. En
	// el central el feedback viola la FK feedback→findings (el finding ausente)
	// y su padre no está pendiente ⇒ error PERMANENTE, que antes habría
	// abortado el lote entero. El finding y el feedback existen en el LOCAL
	// (sus FK locales se cumplen); solo el central los rechaza.
	fHuerfano := hallazgo("hallazgo cuyo evento no viaja")
	runVeneno := NewULID()
	guardarRun(t, s, runVeneno, repoID, "pass", []finding.Finding{fHuerfano})
	insertarFeedbackConID(t, s, NewULID(), fHuerfano.ID, "useful")
	// Se marcan superseded los eventos del run veneno y su finding: no viajan,
	// así el feedback queda huérfano EN EL CENTRAL.
	if _, err := s.db.Exec(`UPDATE outbox SET state = ? WHERE entity IN (?, ?) AND row_id IN (?, ?)`,
		EstSuperseded, EntRuns, EntFindings, runVeneno, fHuerfano.ID); err != nil {
		t.Fatal(err)
	}

	if _, err := s.SyncCentral(ctx, dsn); err != nil {
		t.Fatalf("el sync entero no debía fallar por una fila envenenada: %v", err)
	}

	// El run y su finding sanos SÍ llegaron (la cola no se bloqueó).
	central, err := sql.Open("sqlite", ruta+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer central.Close()
	// El finding sano llegó (la cola no se bloqueó); el huérfano no (superseded).
	if n := contar(t, central, "findings"); n != 1 {
		t.Errorf("el finding sano no llegó: %d (¿el veneno bloqueó la cola?)", n)
	}
	// El feedback envenenado quedó en cuarentena, conservado (no perdido).
	n, err := s.EnCuarentena()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("el feedback envenenado debía quedar en cuarentena: %d", n)
	}
	evs, _ := s.ListarCuarentena()
	if len(evs) != 1 || evs[0].Entity != EntFeedback {
		t.Fatalf("la cuarentena no describe el evento: %+v", evs)
	}
}
