package store

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"codeguard/internal/finding"
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
// verifica conteos y contenido, re-empuja sin cambios (la marca corta el
// reenvío), añade filas y empuja (viajan solo las nuevas) y simula el
// reintento tras morir a media faena (sin marcas, la idempotencia evita los
// duplicados).
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
	// Las migraciones centrales quedan aplicadas y registradas (001 y 002).
	if n := contar(t, central, "schema_migrations"); n != 2 {
		t.Errorf("migraciones registradas en el central: %d, se esperaban 2", n)
	}

	// ── Segundo empuje sin cambios: la marca corta el reenvío ──
	// (repos sí viaja siempre: es upsert completo a propósito.)
	res2, err := s.SyncCentral(ctx, dsn)
	if err != nil {
		t.Fatalf("segundo empuje: %v", err)
	}
	if res2.Runs+res2.Findings+res2.Feedback+res2.LLMCalls != 0 {
		t.Errorf("sin cambios locales nada incremental debía viajar: %+v", res2)
	}
	if res2.Repos != 1 {
		t.Errorf("repos viaja completa en cada empuje (upsert): %+v", res2)
	}

	// ── Filas nuevas: viajan SOLO las nuevas ──
	// La pausa garantiza otro milisegundo: dentro del mismo, el orden de los
	// ULID es aleatorio y el nuevo id podría caer detrás de la marca.
	time.Sleep(3 * time.Millisecond)
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
	// Borrar las marcas simula el peor caso: TODO se re-empuja, y el
	// ON CONFLICT (id) DO NOTHING lo deja pasar sin duplicar. El resumen
	// cuenta cero porque nada entró de verdad — RowsAffected no miente.
	if _, err := s.db.Exec(`DELETE FROM sync_marcas`); err != nil {
		t.Fatal(err)
	}
	res4, err := s.SyncCentral(ctx, dsn)
	if err != nil {
		t.Fatalf("re-empuje sin marcas: %v", err)
	}
	if res4.Runs+res4.Findings+res4.Feedback+res4.LLMCalls != 0 {
		t.Errorf("el reintento no debía contar filas repetidas: %+v", res4)
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
