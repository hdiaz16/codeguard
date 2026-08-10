package squawk

import (
	"encoding/json"
	"testing"

	"codeguard/internal/engines"
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
