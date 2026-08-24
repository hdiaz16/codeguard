package squawk

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"codeguard/internal/engines"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
)

// Contrato con squawk 2.62: formato plano file/line/level/message/help.
// (La versión 1.x usaba un arreglo "messages" — ese cambio ya nos mordió.)
const recordedSquawk = `[
  {"file":"migrations\\002.sql","line":0,"column":0,"level":"Warning",
   "message":"Missing lock_timeout","help":"Configure a lock_timeout",
   "rule_name":"require-lock-timeout","column_end":49,"line_end":0},
  {"file":"migrations\\002.sql","line":2,"column":0,"level":"Warning",
   "message":"UNIQUE requires ACCESS EXCLUSIVE","help":"Create the index CONCURRENTLY",
   "rule_name":"disallowed-unique-constraint","column_end":10,"line_end":2}
]`

func TestParseFormatoSquawk262(t *testing.T) {
	var vs []violation
	if err := json.Unmarshal([]byte(recordedSquawk), &vs); err != nil {
		t.Fatalf("el JSON grabado de squawk 2.62 no parsea: %v", err)
	}
	if len(vs) != 2 {
		t.Fatalf("esperaba 2 violaciones, hubo %d", len(vs))
	}
	if vs[0].Message != "Missing lock_timeout" || vs[0].Help != "Configure a lock_timeout" {
		t.Errorf("message/help planos no se leyeron: %+v", vs[0])
	}
	if vs[1].Line != 2 {
		t.Errorf("line debe leerse tal cual (base 0, se corrige en Run): %d", vs[1].Line)
	}
}

// Squawk analiza PostgreSQL y sólo PostgreSQL. Contra otro motor sus reglas
// no fallan por exceso de celo: exigen sintaxis que allí no existe. El caso
// real fue el esquema SQLite de este mismo repo, al que pedía CREATE INDEX
// CONCURRENTLY — y como la política §7 promueve esa regla a bloqueante, el
// commit quedaba detenido por un consejo que habría roto la base de datos.
func TestDialectoDecideSiCorre(t *testing.T) {
	in := engines.Input{Files: []gitdiff.ChangedFile{{Path: "migrations/001_init.sql", Status: "M"}}}

	for _, caso := range []struct {
		dialecto string
		aplica   bool
	}{
		{"", true},           // sin declarar = postgres, para no quitar cobertura en silencio
		{"postgres", true},   //
		{"sqlite", false},    // el caso que destapó el bug
		{"mysql", false},     //
		{"sqlserver", false}, //
		{"POSTGRES", true},   // el dialecto llega normalizado, pero no se confía en ello
	} {
		e := &Engine{MigrationGlobs: []string{"migrations/*.sql"}, Dialect: caso.dialecto}
		if got := e.Applies(in); got != caso.aplica {
			t.Errorf("dialecto %q: Applies=%v, esperaba %v", caso.dialecto, got, caso.aplica)
		}
	}
}

// Sin migraciones no hay nada que analizar, aunque el dialecto sea el correcto.
func TestSinMigracionesNoAplica(t *testing.T) {
	in := engines.Input{Files: []gitdiff.ChangedFile{{Path: "internal/store/store.go", Status: "M"}}}
	e := &Engine{MigrationGlobs: []string{"migrations/*.sql"}, Dialect: "postgres"}
	if e.Applies(in) {
		t.Error("no hay .sql en el diff: squawk no debería aplicar")
	}
}

// El fingerprint de squawk usaba el nombre de la regla como contenido, así
// que TODAS las ocurrencias de una regla en un archivo colapsaban en un solo
// hash: baselinear un índice inseguro suprimía también los futuros del mismo
// archivo. En un repo Postgres real eso es un agujero en "sólo lo nuevo
// bloquea" justo en la capa que protege producción. Ahora el contenido es la
// línea REAL del SQL.
func TestFingerprintDistingueOcurrenciasEnElMismoArchivo(t *testing.T) {
	dir := t.TempDir()
	sql := "CREATE TABLE usuarios (id int);\n" +
		"CREATE INDEX idx_a ON usuarios (nombre);\n" +
		"CREATE INDEX idx_b ON usuarios (correo);\n"
	if err := os.WriteFile(filepath.Join(dir, "001.sql"), []byte(sql), 0o644); err != nil {
		t.Fatal(err)
	}

	cache := map[string][]string{}
	hacer := func(linea int) finding.Finding {
		f := finding.Finding{
			Engine: "squawk", RuleKey: "require-concurrent-index-creation",
			File: "001.sql", Line: linea + 1,
			LineContent: lineaSQL(dir, "001.sql", linea, cache),
		}
		f.ComputeFingerprint()
		return f
	}

	a, b := hacer(1), hacer(2) // las dos CREATE INDEX
	if a.Fingerprint == b.Fingerprint {
		t.Error("dos índices inseguros distintos no pueden compartir fingerprint: " +
			"baselinear el primero suprimiría el segundo")
	}

	// Y la estabilidad que el fingerprint promete se conserva: la MISMA línea
	// desplazada a otro número de línea sigue dando el mismo hash.
	sqlCorrido := "-- comentario nuevo arriba\n" + sql
	if err := os.WriteFile(filepath.Join(dir, "001.sql"), []byte(sqlCorrido), 0o644); err != nil {
		t.Fatal(err)
	}
	a2 := finding.Finding{
		Engine: "squawk", RuleKey: "require-concurrent-index-creation",
		File: "001.sql", Line: 3,
		LineContent: lineaSQL(dir, "001.sql", 2, map[string][]string{}),
	}
	a2.ComputeFingerprint()
	if a2.Fingerprint != a.Fingerprint {
		t.Error("la misma línea desplazada debe conservar su fingerprint: es la clave de supresión")
	}

	// Archivo ilegible: no revienta, cae al marcador estable.
	if got := lineaSQL(dir, "no-existe.sql", 5, map[string][]string{}); got != "sin-contenido-de-linea" {
		t.Errorf("fallback inesperado: %q", got)
	}
}

func TestReglasDeAltoRiesgoBloquean(t *testing.T) {
	// La política §7 exige que migración insegura BLOQUEE aunque squawk la
	// reporte como Warning. Estas tres son las de la spec.
	for _, rule := range []string{"disallowed-unique-constraint", "require-concurrent-index-creation", "adding-required-field"} {
		if !blockingRules[rule] {
			t.Errorf("%s debe estar promovida a bloqueante", rule)
		}
	}
	if blockingRules["require-lock-timeout"] {
		t.Error("require-lock-timeout es aviso, no bloqueante")
	}
}
