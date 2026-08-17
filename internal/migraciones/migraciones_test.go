package migraciones

import (
	"strings"
	"testing"

	"github.com/gobwas/glob"
)

// vigilado responde la única pregunta que importa: con los globs que escribió
// `init` en el config, ¿este archivo lo mira la compuerta de migraciones?
//
// Se comprueba COMPILANDO el glob y casándolo contra la ruta, exactamente como
// hace squawk.migrationFiles y shadow.matchAny. Comparar cadenas ("¿salió
// 'db/*.sql'?") daría por bueno un glob sintácticamente plausible que en la
// práctica no casa con nada — que es justo la forma que tenía este fallo.
func vigilado(t *testing.T, globs []string, ruta string) bool {
	t.Helper()
	for _, p := range globs {
		g, err := glob.Compile(p, '/')
		if err != nil {
			t.Errorf("init escribió un glob que ni siquiera compila: %q (%v)", p, err)
			continue
		}
		if g.Match(ruta) {
			return true
		}
	}
	return false
}

// Los layouts de migraciones que existen de verdad. Ninguno es exótico: son los
// que generan Rails, Flyway, Supabase, Prisma y el patrón numerado a mano.
//
// El caso que destapó esto fue `db/002_moneda.sql`: un ALTER TABLE ... DROP
// COLUMN más un ADD COLUMN NOT NULL sin default —peligrosos de manual— pasaron
// con "listo — commit permitido" porque `paths.migrations` había quedado vacío.
func TestVigilamosLosLayoutsDeMigracionesQueExistenDeVerdad(t *testing.T) {
	for _, c := range []struct {
		nombre   string
		archivos []string
		// debeVigilar: rutas que la compuerta TIENE que mirar.
		debeVigilar []string
	}{
		{
			"numerado a mano bajo db/ (el caso medido)",
			[]string{"db/001_init.sql", "db/002_moneda.sql"},
			[]string{"db/002_moneda.sql"},
		},
		{
			"Rails: db/migrate",
			[]string{"db/migrate/20230101120000_crear_pedidos.sql", "db/migrate/20230202090000_indices.sql"},
			[]string{"db/migrate/20230202090000_indices.sql"},
		},
		{
			"Flyway: sql/V1__init.sql",
			[]string{"sql/V1__init.sql", "sql/V2__moneda.sql"},
			[]string{"sql/V2__moneda.sql"},
		},
		{
			"Supabase",
			[]string{"supabase/migrations/001_base.sql", "supabase/migrations/002_moneda.sql"},
			[]string{"supabase/migrations/002_moneda.sql"},
		},
		{
			"Prisma: una carpeta por migración",
			[]string{
				"prisma/migrations/20240101_init/migration.sql",
				"prisma/migrations/20240202_moneda/migration.sql",
			},
			// La de MAÑANA es la que importa: si el glob se ancla a las carpetas
			// que ya existen, cada migración nueva nace sin vigilancia.
			[]string{"prisma/migrations/20250303_nueva/migration.sql"},
		},
		{
			"schema/ numerado",
			[]string{"schema/001_init.sql", "schema/002_moneda.sql"},
			[]string{"schema/002_moneda.sql"},
		},
		{
			"el canónico: migrations/ (control positivo, esto ya funcionaba)",
			[]string{"migrations/001_init.sql", "migrations/002_moneda.sql"},
			[]string{"migrations/002_moneda.sql"},
		},
		{
			"en la raíz del repo",
			[]string{"001_init.sql", "002_moneda.sql"},
			[]string{"002_moneda.sql"},
		},
	} {
		t.Run(c.nombre, func(t *testing.T) {
			globs, _ := Globs(c.archivos)
			for _, ruta := range c.debeVigilar {
				if !vigilado(t, globs, ruta) {
					t.Errorf("%s NO lo vigila nadie.\n"+
						"  globs generados: %v\n"+
						"  con esto, `migration_unsafe: block` no se dispara jamás y "+
						"touches_migration (peso 30) nunca suma.", ruta, globs)
				}
				// Globs y Parece tienen que estar de acuerdo: el pipeline usa el
				// segundo para decidir de qué quejarse, y si discrepan avisaría
				// de archivos que init decidió ignorar a propósito, o callaría
				// sobre migraciones de verdad.
				if !Parece(ruta) {
					t.Errorf("%s se vigila pero Parece() dice que no es una migración", ruta)
				}
			}
		})
	}
}

// El control que impide el arreglo barato.
//
// Vigilar *.sql a lo bruto pasaría el test de arriba y sería un fix falso: los
// .sql que NO son migraciones (consultas de sqlc, modelos de dbt, semillas)
// entrarían al peso touches_migration=30 y subirían el riesgo de cada commit
// que los toque, además de mandarlos a squawk, que sólo entiende DDL.
func TestNoSeVigilaTodoSqlAlBulto(t *testing.T) {
	archivos := []string{
		"migrations/001_init.sql", // esto sí
		"queries/get_user.sql",    // consultas: no son migraciones
		"queries/list_orders.sql",
		"models/staging/stg_orders.sql", // dbt: SELECTs, no DDL
	}
	globs, sinVigilar := Globs(archivos)

	if !vigilado(t, globs, "migrations/001_init.sql") {
		t.Error("la migración de verdad tiene que quedar vigilada")
	}
	for _, ruta := range []string{"queries/get_user.sql", "models/staging/stg_orders.sql"} {
		if vigilado(t, globs, ruta) {
			t.Errorf("%s no es una migración y quedó vigilada: globs=%v", ruta, globs)
		}
		if Parece(ruta) {
			t.Errorf("%s no es una migración y Parece() dice que sí", ruta)
		}
	}

	// Y lo que se deja fuera se DICE. Un .sql sin vigilar es una decisión
	// razonable; tomarla en silencio, por omisión y sin que nadie se entere, es
	// exactamente el fallo que este arreglo persigue.
	if len(sinVigilar) == 0 {
		t.Error("hay .sql fuera de la vigilancia y no se reportan: " +
			"el dev no puede corregir lo que no sabe que pasó")
	}
	for _, ruta := range sinVigilar {
		if strings.HasPrefix(ruta, "migrations/") {
			t.Errorf("se reporta como no vigilado algo que sí lo está: %s", ruta)
		}
	}
}

// Lo que un validador adversarial encontró midiendo, no leyendo: la regla del
// nombre versionado se llevaba por delante medio repositorio.
//
// El daño medido no era teórico. `init` metía `test/fixtures/001_datos.sql` en
// paths.migrations sin avisar, y tocar ese fixture sacaba EXIT=1 con
// [ban-drop-table] y [adding-required-field] — sobre un archivo que existe
// justamente para crear y tirar tablas, y que no toca producción jamás.
func TestNoSeVigilaLoQueVaNumeradoPeroNoEsEsquema(t *testing.T) {
	archivos := []string{
		"db/001_init.sql", // la migración de verdad
		"test/fixtures/001_datos.sql",
		"db/seeds/001_paises.sql",
		"dumps/2024_backup.sql",
		"reportes/2024_ventas.sql",
		"analytics/models/2024_cohorte.sql",
		"sql/queries/001_usuarios.sql",
		"docs/ejemplos/01-select.sql",
		// Semillas DENTRO del árbol de migraciones: son datos de arranque, no
		// un cambio de esquema, así que el veto de CONTENIDO gana igual.
		"supabase/migrations/seeds/paises.sql",
	}
	globs, _ := Globs(archivos)

	if !vigilado(t, globs, "db/001_init.sql") {
		t.Error("la migración de verdad tiene que seguir vigilada")
	}
	for _, ruta := range archivos[1:] {
		if vigilado(t, globs, ruta) {
			t.Errorf("%s no es esquema y quedó vigilada — un commit que lo toque "+
				"puede salir BLOQUEADO sin remedio. globs=%v", ruta, globs)
		}
		if Parece(ruta) {
			t.Errorf("%s no es esquema y Parece() dice que sí: el pipeline daría "+
				"la lata en cada commit que lo toque", ruta)
		}
	}
}

// El veto de directorios se comió migraciones de PRODUCCIÓN, y esto también lo
// midió el validador: un DROP COLUMN que antes bloqueaba pasó con EXIT=0.
//
// La causa era confundir dos cosas distintas. "seeds" o "fixtures" dicen QUÉ
// hay dentro y nunca es esquema; "analytics" o "reports" nombran un ÁREA del
// proyecto, y debajo de un directorio de migraciones son dominios, no
// contenidos. Hasura numera `migrations/<fuente>/<ver>_<nombre>/up.sql` y
// llamarle "analytics" a una fuente es el layout canónico, no una rareza.
func TestBajoUnDirectorioDeMigracionesElDominioNoDescalifica(t *testing.T) {
	for _, ruta := range []string{
		"migrations/analytics/1699_init/up.sql",    // Hasura, fuente "analytics"
		"migrations/reports/1700_moneda/up.sql",    // Hasura, fuente "reports"
		"supabase/migrations/reports/001_init.sql", // Supabase, esquema "reports"
		"services/docs/db/migrations/001_init.sql", // monorepo con un servicio "docs"
	} {
		if !Parece(ruta) {
			t.Errorf("%s ES una migración de producción y quedó descartada: "+
				"el DROP COLUMN que contenga pasará sin que nadie lo mire", ruta)
		}
		globs, _ := Globs([]string{ruta})
		if !vigilado(t, globs, ruta) {
			t.Errorf("%s sin vigilar: globs=%v", ruta, globs)
		}
	}

	// Y el contenido sigue descartándose aunque el árbol de migraciones esté
	// por encima: es lo que distingue esta regla de "no vetar nada".
	for _, ruta := range []string{
		"migrations/seeds/paises.sql",
		"migrations/fixtures/001_datos.sql",
		// Supabase, dbmate y goose nombran la semilla en el ARCHIVO, no en una
		// carpeta. Medido: una de estas con TRUNCATE + DROP TABLE salía
		// BLOQUEADA por ban-drop-table, sobre datos que no tocan producción.
		"supabase/migrations/20240103_seed_datos.sql",
		"db/migrations/002_seeds.sql",
	} {
		if Parece(ruta) {
			t.Errorf("%s son datos de arranque, no esquema", ruta)
		}
	}

	// Pero la palabra tiene que ir al principio del nombre. Si bastara con que
	// apareciera, esta migración legítima dejaría de vigilarse — y ese error va
	// hacia el lado peligroso.
	for _, ruta := range []string{
		"migrations/20240101_create_seed_table.sql",
		"migrations/003_add_test_flag.sql",
	} {
		if !Parece(ruta) {
			t.Errorf("%s ES una migración: la palabra aparece, pero describe la tabla, "+
				"no el tipo de archivo", ruta)
		}
	}
}

// Layouts reales que la primera versión dejaba fuera, encontrados por el
// validador. Los dos son silenciosos: la compuerta simplemente no mira.
func TestLosLayoutsQueSeEscapabanDeLaPrimeraVersion(t *testing.T) {
	for _, c := range []struct{ nombre, archivo, otro string }{
		// Flyway numera con punto tanto como con guion bajo.
		{"Flyway con puntos", "sql/V1.1__moneda.sql", "sql/V2.0.1__idx.sql"},
		// El volcado de esquema de Rails, y su equivalente a mano.
		{"structure.sql de Rails", "db/structure.sql", "db/structure.sql"},
		{"schema.sql en la raíz", "schema.sql", "schema.sql"},
	} {
		t.Run(c.nombre, func(t *testing.T) {
			globs, sinVigilar := Globs([]string{c.archivo, c.otro})
			if !vigilado(t, globs, c.archivo) {
				t.Errorf("%s sin vigilar: globs=%v, fuera=%v", c.archivo, globs, sinVigilar)
			}
			if !Parece(c.archivo) {
				t.Errorf("%s se vigila pero Parece() dice que no es migración", c.archivo)
			}
		})
	}
}

// Un repo con SQL cuya lista sale vacía es el caso peligroso, y tiene que ser
// distinguible de "aquí no hay SQL": en el primero la compuerta está apagada
// teniendo trabajo, en el segundo no hay nada que hacer.
func TestSqlSinNingunaMigracionReconocibleSeDelata(t *testing.T) {
	globs, sinVigilar := Globs([]string{"queries/get_user.sql", "queries/list.sql"})
	if len(globs) != 0 {
		t.Errorf("no había ninguna migración y se inventaron globs: %v", globs)
	}
	if len(sinVigilar) != 2 {
		t.Errorf("los 2 .sql sin vigilar tienen que salir reportados; salieron %v", sinVigilar)
	}

	// Sin SQL no se reporta nada: el aviso tiene que significar algo.
	globs, sinVigilar = Globs([]string{"main.go", "README.md"})
	if len(globs) != 0 || len(sinVigilar) != 0 {
		t.Errorf("un repo sin SQL no genera ni globs ni avisos; salió %v / %v", globs, sinVigilar)
	}
}

// Windows entrega rutas con barra invertida en varios caminos del producto, y
// los globs se compilan siempre con '/' como separador. Sin normalizar, una
// misma migración se vigila o no según por dónde llegó su ruta.
func TestLasRutasDeWindowsNoCambianElVeredicto(t *testing.T) {
	if !Parece(`db\002_moneda.sql`) {
		t.Error(`db\002_moneda.sql es la misma migración que db/002_moneda.sql`)
	}
	globs, sinVigilar := Globs([]string{`db\001_init.sql`, `db\002_moneda.sql`})
	if len(sinVigilar) != 0 {
		t.Errorf("con barras de Windows quedaron sin vigilar: %v (globs=%v)", sinVigilar, globs)
	}
	if !vigilado(t, globs, "db/002_moneda.sql") {
		t.Errorf("los globs tienen que salir con barras normales para casar; salieron %v", globs)
	}
}

// Documenta la semántica de gobwas de la que depende la generación de globs.
// Si un día cambia, que lo diga este test y no un repo en producción.
func TestSemanticaDeGobwasQueDamosPorSupuesta(t *testing.T) {
	for _, c := range []struct {
		patron, ruta string
		casa         bool
	}{
		{"a/**/*.sql", "a/b/x.sql", true},
		{"a/**/*.sql", "a/x.sql", false}, // ← el que obliga a emitir el segundo glob
		{"a/*.sql", "a/x.sql", true},
		{"a/*.sql", "a/b/x.sql", false},
		{"*.sql", "x.sql", true},
		{"./*.sql", "x.sql", false}, // el glob que generaba init para la raíz
	} {
		g, err := glob.Compile(c.patron, '/')
		if err != nil {
			t.Fatalf("%q no compila: %v", c.patron, err)
		}
		if got := g.Match(c.ruta); got != c.casa {
			t.Errorf("gobwas cambió: %q vs %q → %v, este código asume %v", c.patron, c.ruta, got, c.casa)
		}
	}
}
