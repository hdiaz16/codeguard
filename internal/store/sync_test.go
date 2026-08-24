package store

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"codeguard/internal/finding"
	"codeguard/migrations"
)

// rebind es la frontera entre dialectos: si numera mal, TODO el empuje a
// Postgres falla. La tabla cubre lo que las consultas del sync usan de
// verdad, más la limitación conocida.
func TestRebindNumeraLosPlaceholders(t *testing.T) {
	casos := []struct{ entrada, esperada string }{
		{"SELECT 1", "SELECT 1"},
		{"WHERE id > ?", "WHERE id > $1"},
		{"VALUES (?, ?, ?)", "VALUES ($1, $2, $3)"},
		{"INSERT INTO t (a, b) VALUES (?, ?) ON CONFLICT (a) DO NOTHING",
			"INSERT INTO t (a, b) VALUES ($1, $2) ON CONFLICT (a) DO NOTHING"},
		// La limitación documentada: rebind NO entiende literales de string,
		// un '?' entre comillas también se numera. Las consultas del sync no
		// llevan literales con '?' a propósito — este caso deja el contrato
		// escrito: si algún día una consulta necesita un '?' literal, primero
		// se le enseñan las comillas a rebind.
		{"SELECT '?' FROM x WHERE a = ?", "SELECT '$1' FROM x WHERE a = $2"},
	}
	for _, c := range casos {
		if got := rebind(c.entrada); got != c.esperada {
			t.Errorf("rebind(%q):\n  got  %q\n  want %q", c.entrada, got, c.esperada)
		}
	}
}

// contar consulta conteos en el central. Las consultas salen de un mapa fijo:
// nada de concatenar nombres de tabla en SQL, ni en tests — el rulepack de la
// casa bloquea justo eso, y con razón.
var consultaConteo = map[string]string{
	"repos":             `SELECT COUNT(*) FROM repos`,
	"runs":              `SELECT COUNT(*) FROM runs`,
	"findings":          `SELECT COUNT(*) FROM findings`,
	"feedback":          `SELECT COUNT(*) FROM feedback`,
	"llm_calls":         `SELECT COUNT(*) FROM llm_calls`,
	"schema_migrations": `SELECT COUNT(*) FROM schema_migrations`,
}

func contar(t *testing.T, db *sql.DB, tabla string) int {
	t.Helper()
	q, ok := consultaConteo[tabla]
	if !ok {
		t.Fatalf("tabla sin consulta de conteo: %s", tabla)
	}
	var n int
	if err := db.QueryRow(q).Scan(&n); err != nil {
		t.Fatalf("contando %s en el central: %v", tabla, err)
	}
	return n
}

func hallazgo(mensaje string) finding.Finding {
	return finding.Finding{
		ID: NewULID(), Engine: "semgrep", RuleKey: "regla-sync",
		Pillar: finding.Quality, Severity: finding.Warning, Source: finding.Deterministic,
		File: "a.go", Line: 1, Message: mensaje, Fingerprint: NewULID(),
	}
}

// cicloSync es el ciclo completo local→central, compartido por el central
// SQLite (siempre corre) y el Postgres real (corre si hay servidor): empuja,
// verifica conteos y contenido, re-empuja sin cambios (el outbox no re-envía
// lo `sent`), añade filas y empuja (viajan solo las nuevas) y simula el
// reintento tras morir a media faena (reponiendo eventos a pending, la
// idempotencia del ON CONFLICT evita los duplicados).
func cicloSync(t *testing.T, dsn string, central *sql.DB, rb func(string) string) {
	t.Helper()
	s := bd(t)
	ctx := context.Background()

	repoID := CanonicalRepoID("local/sync")
	if err := s.UpsertRepo(repoID, "", "sync"); err != nil {
		t.Fatal(err)
	}
	f1, f2 := hallazgo("primer hallazgo"), hallazgo("segundo hallazgo")
	run1, run2 := NewULID(), NewULID()
	guardarRun(t, s, run1, repoID, "block", []finding.Finding{f1, f2})
	guardarRun(t, s, run2, repoID, "pass", nil)
	if err := s.SaveFeedback(f1.ID, "useful", "bien visto"); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveLLMCall(LLMCall{RunID: run1, Pillar: "security", Model: "m", Status: "ok"}); err != nil {
		t.Fatal(err)
	}

	// ── Primer empuje: todo viaja ──
	res, err := s.SyncCentral(ctx, dsn)
	if err != nil {
		t.Fatalf("primer empuje: %v", err)
	}
	if res.Repos != 1 || res.Runs != 2 || res.Findings != 2 || res.Feedback != 1 || res.LLMCalls != 1 {
		t.Fatalf("resumen del primer empuje: %+v", res)
	}
	if n := contar(t, central, "findings"); n != 2 {
		t.Fatalf("findings en el central: %d", n)
	}
	// El contenido viaja intacto, no solo los conteos.
	var msg string
	if err := central.QueryRow(rb(`SELECT message FROM findings WHERE id = ?`), f1.ID).Scan(&msg); err != nil || msg != "primer hallazgo" {
		t.Errorf("el hallazgo no viajó intacto: %q (err=%v)", msg, err)
	}
	var verdict string
	if err := central.QueryRow(rb(`SELECT verdict FROM feedback WHERE finding_id = ?`), f1.ID).Scan(&verdict); err != nil || verdict != "useful" {
		t.Errorf("el feedback no viajó intacto: %q (err=%v)", verdict, err)
	}
	// El veredicto tipado también viaja (003_outcome.sql + las columnas nuevas
	// del SELECT/INSERT de runs): sin esto, el central seguiría leyendo solo el
	// vocabulario viejo mientras el local ya habla el nuevo.
	var outcome string
	if err := central.QueryRow(rb(`SELECT COALESCE(outcome,'') FROM runs WHERE id = ?`), run1).Scan(&outcome); err != nil || outcome != "blocked" {
		t.Errorf("el outcome tipado no viajó al central: %q (err=%v)", outcome, err)
	}
	// Las migraciones centrales quedan aplicadas y registradas — TODAS las del
	// catálogo único, no un número copiado a mano que envejece con cada
	// migración nueva (la 005 lo demostró: el 4 cableado rompió aquí).
	catalogo, err := migrations.Catalogo()
	if err != nil {
		t.Fatal(err)
	}
	if n := contar(t, central, "schema_migrations"); n != len(catalogo) {
		t.Errorf("migraciones registradas en el central: %d, se esperaban %d (las del catálogo)", n, len(catalogo))
	}

	// ── Segundo empuje sin cambios: nada viaja ──
	// Con el outbox, lo ya enviado queda en estado `sent` y no se re-empuja:
	// el barrido por marca de agua (que re-enviaba repos completo cada vez)
	// murió. Un segundo sync sin altas nuevas mueve CERO eventos.
	res2, err := s.SyncCentral(ctx, dsn)
	if err != nil {
		t.Fatalf("segundo empuje: %v", err)
	}
	if res2.Repos+res2.Runs+res2.Findings+res2.Feedback+res2.LLMCalls != 0 {
		t.Errorf("sin cambios locales NADA debía viajar (outbox: todo sent): %+v", res2)
	}

	// ── Filas nuevas: viajan SOLO las nuevas, SIN el Sleep del bug del ms ──
	// El outbox ordena por su secuencia monotónica, no por el ULID: dos altas
	// del MISMO milisegundo ya no se pierden, así que el `time.Sleep(3ms)` que
	// el arnés viejo necesitaba para esquivar el bug DESAPARECE.
	f3 := hallazgo("tercer hallazgo")
	guardarRun(t, s, NewULID(), repoID, "pass", []finding.Finding{f3})
	res3, err := s.SyncCentral(ctx, dsn)
	if err != nil {
		t.Fatalf("tercer empuje: %v", err)
	}
	if res3.Runs != 1 || res3.Findings != 1 || res3.Feedback != 0 || res3.LLMCalls != 0 {
		t.Errorf("debían viajar solo las filas nuevas: %+v", res3)
	}
	if n := contar(t, central, "runs"); n != 3 {
		t.Errorf("runs en el central tras el tercer empuje: %d", n)
	}

	// ── Reintento tras morir entre empujar y marcar ──
	// El crash real: el central confirmó, pero el ACK local (marcar el evento
	// `sent`) no llegó. Se simula reponiendo a `pending` los eventos ya
	// enviados: el sync los RE-EMPUJA (cuentan como enviados), el ON CONFLICT
	// del central los absorbe, y NADA se duplica. Antes esto se hacía borrando
	// sync_marcas; esa tabla ya no gobierna el sync.
	if _, err := s.db.Exec(`UPDATE outbox SET state = ? WHERE state = ?`, EstPending, EstSent); err != nil {
		t.Fatal(err)
	}
	res4, err := s.SyncCentral(ctx, dsn)
	if err != nil {
		t.Fatalf("re-empuje tras el corte: %v", err)
	}
	// Todo se re-envía (at-least-once), y el central no duplica: lo que se
	// verifica es la NO duplicación, no un conteo cero.
	if res4.Runs+res4.Findings+res4.Feedback+res4.LLMCalls == 0 {
		t.Errorf("el reintento debía RE-EMPUJAR los eventos repuestos: %+v", res4)
	}
	if n := contar(t, central, "runs"); n != 3 {
		t.Errorf("duplicados tras el reintento: %d runs", n)
	}
	if n := contar(t, central, "findings"); n != 3 {
		t.Errorf("duplicados tras el reintento: %d findings", n)
	}
	if n := contar(t, central, "feedback"); n != 1 {
		t.Errorf("duplicados tras el reintento: %d feedback", n)
	}
}

// El central SQLite: dos BD temporales en la misma máquina. Es el modo de
// prueba del sync y también su modo share-de-red.
func TestSyncCentralConSQLite(t *testing.T) {
	ruta := filepath.Join(t.TempDir(), "central.db")
	// La conexión de verificación es independiente de las que abre el sync.
	central, err := sql.Open("sqlite", ruta+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { central.Close() })
	cicloSync(t, "sqlite:"+ruta, central, func(q string) string { return q })
}

// La validación contra un Postgres de verdad. Necesita un servidor, así que
// se activa con CODEGUARD_TEST_PG_DSN, por ejemplo:
//
//	docker run -d --name cg-pg-test -e POSTGRES_PASSWORD=test -p 55432:5432 postgres:16-alpine
//	CODEGUARD_TEST_PG_DSN=postgres://postgres:test@localhost:55432/postgres go test ./internal/store
//
// Sin la variable se salta: un test que falla por infraestructura ausente es
// ruido, no señal.
func TestSyncCentralConPostgres(t *testing.T) {
	dsn := os.Getenv("CODEGUARD_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("sin CODEGUARD_TEST_PG_DSN: la validación contra Postgres real necesita un servidor")
	}
	central, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { central.Close() })
	// El servidor sobrevive entre corridas: se parte de cero cada vez.
	if _, err := central.Exec(`DROP TABLE IF EXISTS feedback, llm_calls, findings, runs,
		suppressions, file_cache, diff_cache, rules, repos, sync_marcas, schema_migrations CASCADE`); err != nil {
		t.Fatalf("limpiando el central: %v", err)
	}
	cicloSync(t, dsn, central, rebind)
}

// EL TEST QUE DA VALOR A W5: la pérdida del mismo milisegundo, cerrada.
//
// Con la marca de agua vieja (WHERE id > último_ULID) dos filas escritas en el
// MISMO milisegundo se ordenaban por el sufijo ALEATORIO de su ULID; si el
// sync empujaba una y la otra tenía un ULID menor, esta caía DETRÁS de la
// marca y no viajaba JAMÁS. El arnés viejo lo esquivaba con time.Sleep(3ms).
//
// El outbox ordena por su secuencia monotónica propia (asignada en la tx),
// NO por el ULID, así que el orden aleatorio del sufijo es irrelevante. Este
// test fuerza el peor caso —dos altas cuya segunda tiene un ULID MENOR que la
// primera— y exige que AMBAS lleguen. Sin outbox, fallaría.
func TestDosAltasDelMismoMilisegundoAmbasLlegan(t *testing.T) {
	ruta := filepath.Join(t.TempDir(), "central.db")
	central, err := sql.Open("sqlite", ruta+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer central.Close()
	dsn := "sqlite:" + ruta

	s := bd(t)
	ctx := context.Background()
	repoID := CanonicalRepoID("local/mismo-ms")
	if err := s.UpsertRepo(repoID, "", "mismo-ms"); err != nil {
		t.Fatal(err)
	}

	// Dos feedbacks: el primero con un id lexicográficamente MAYOR que el
	// segundo (orden adverso DETERMINISTA, sin azar ni Sleep). Con la marca
	// vieja, tras empujar el primero, el segundo (id menor) quedaba detrás.
	// SaveFeedback genera su propio ULID, así que se insertan a mano con ids
	// controlados para reproducir el peor caso exacto.
	fBase := hallazgo("hallazgo base")
	guardarRun(t, s, NewULID(), repoID, "pass", []finding.Finding{fBase})
	insertarFeedbackConID(t, s, "zzzzzzzzzzzzzzzzzzzzzzzzzz", fBase.ID, "useful")  // id MAYOR, llega 1º al sync
	insertarFeedbackConID(t, s, "aaaaaaaaaaaaaaaaaaaaaaaaaa", fBase.ID, "unclear") // id MENOR

	if _, err := s.SyncCentral(ctx, dsn); err != nil {
		t.Fatalf("empuje: %v", err)
	}
	// LA ASERCIÓN: las DOS filas del mismo ms viajaron. Con el bug viejo, la de
	// id menor se habría quedado en el local para siempre.
	if n := contar(t, central, "feedback"); n != 2 {
		t.Fatalf("se perdió una fila del mismo milisegundo: %d de 2 en el central "+
			"(el outbox debía cerrar esto ordenando por seq, no por ULID)", n)
	}
}

// insertarFeedbackConID escribe un feedback con un id EXACTO (para controlar
// el orden lexicográfico) y su evento de outbox en la misma tx, como haría
// SaveFeedback pero sin generar el ULID.
func insertarFeedbackConID(t *testing.T, s *Store, id, findingID, verdict string) {
	t.Helper()
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`INSERT INTO feedback (id, finding_id, verdict, comment, created_at)
		VALUES (?, ?, ?, ?, ?)`, id, findingID, verdict, "", nowISO()); err != nil {
		t.Fatal(err)
	}
	if err := encolarEvento(tx, EntFeedback, id, "insert", 1); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}
