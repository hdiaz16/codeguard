// Package migraciones decide qué archivos .sql son migraciones de esquema.
//
// Lo usan dos sitios que tienen que estar de acuerdo: `codeguard init`, que
// escribe `paths.migrations` en el config, y el pipeline, que avisa cuando un
// cambio de esquema queda fuera de esa lista. Si cada uno tuviera su propia
// idea de qué es una migración, el segundo se pasaría el día quejándose de lo
// que el primero decidió ignorar.
//
// Esa lista alimenta DOS cosas: la compuerta `migration_unsafe: block` —squawk
// sólo mira los archivos que casan— y `touches_migration`, el peso más alto
// del modelo de riesgo (30 sobre un umbral de 35). Una lista vacía no recorta
// la cobertura: apaga las dos, y lo hace sin decir nada.
//
// La versión anterior de esta detección pedía la palabra "migration" DENTRO de
// la ruta. Medido sobre los layouts que existen de verdad, dejaba fuera 6 de 8:
// el numerado a mano (`db/002_moneda.sql`, el caso que lo destapó), Rails
// (`db/migrate/`, que dice "migrate" y no "migration"), Flyway
// (`sql/V1__init.sql`), `schema/`, cualquier .sql en la raíz —el glob salía
// `./*.sql`, que no casa con nada— y Prisma, que sí llevaba la palabra pero
// generaba un glob por cada carpeta ya existente: la migración del mes que
// viene nacía sin vigilancia.
package migraciones

import (
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/gobwas/glob"
)

// dirsDeMigraciones: directorios cuyo NOMBRE ya declara que ahí dentro vive el
// esquema. Se vigila el árbol entero, porque en varios de estos layouts cada
// migración trae su propia subcarpeta.
var dirsDeMigraciones = map[string]bool{
	"migrations": true, "migration": true, "migrate": true,
	"ddl": true, "changelog": true, "changelogs": true,
	"schema": true, "schemas": true,
}

// dirsQueNoSonMigraciones: directorios cuyo nombre dice que ahí NO vive el
// esquema, por mucho que sus archivos vayan numerados.
//
// Sin este veto, la regla del nombre versionado se llevaba por delante medio
// repositorio: `test/fixtures/001_datos.sql` entraba en paths.migrations y un
// commit que tocara el fixture salía BLOQUEADO por `ban-drop-table` — un
// fixture que existe justamente para crear y tirar tablas. También caían
// semillas, volcados, informes numerados por año y las consultas de sqlc bajo
// `sql/queries/`. Vigilar de más no es prudencia: es un bloqueo sin salida en
// un archivo que no toca producción.
// El veto va en DOS niveles, y la diferencia importa más de lo que parece.
//
// dirsDeOtroContenido nombra QUÉ hay dentro: semillas, fixtures, volcados,
// ejemplos. Eso no es esquema esté donde esté, ni siquiera dentro del árbol de
// migraciones — `supabase/migrations/seeds/paises.sql` son datos de arranque.
//
// dirsDeOtroAsunto nombra un ÁREA del proyecto: informes, analítica, modelos.
// Esas palabras sólo descartan cuando NO hay un directorio de migraciones por
// encima, porque ahí abajo son dominios, no contenidos. Confundir los dos
// niveles se comió migraciones de producción reales: Hasura numera
// `migrations/<fuente>/<ver>_<nombre>/up.sql` y llamarle "analytics" a una
// fuente es lo normal — medido, un DROP COLUMN que antes bloqueaba pasaba con
// EXIT=0 y callaban a la vez `init`, `status` y el aviso del pipeline.
var dirsDeOtroContenido = map[string]bool{
	"seed": true, "seeds": true, "semillas": true,
	"fixture": true, "fixtures": true,
	"test": true, "tests": true, "testdata": true, "spec": true,
	"dump": true, "dumps": true, "backup": true, "backups": true,
	"ejemplo": true, "ejemplos": true, "example": true, "examples": true, "samples": true,
	"query": true, "queries": true, "consultas": true,
	"snapshot": true, "snapshots": true,
}

var dirsDeOtroAsunto = map[string]bool{
	"doc": true, "docs": true, "documentacion": true,
	"report": true, "reports": true, "reporte": true, "reportes": true,
	"analytics": true, "analitica": true, "models": true, "modelos": true,
}

// versionDeMigracion reconoce los nombres de archivo versionados, que es como
// se marca una migración cuando el directorio no lo dice:
//
//	001_init.sql · 20240101120000_moneda.sql · 1-init.sql   (numerado)
//	V1__init.sql · V1_2__moneda.sql · V1.1__moneda.sql      (Flyway)
//	U3__vuelta.sql · R__vistas.sql                          (Flyway undo/repetible)
//
// Los puntos importan: Flyway numera con `.` tanto como con `_`, y
// `sql/V1.1__moneda.sql` es un layout corriente que la primera versión de esto
// dejaba fuera.
var versionDeMigracion = regexp.MustCompile(`^(\d+[_-]|[vu]\d[\d._]*__|r__)`)

// archivosDeEsquema: nombres que son el esquema aunque no vayan numerados ni
// vivan en un directorio que lo declare. `db/structure.sql` es el volcado de
// esquema de Rails, y `schema.sql` el patrón equivalente a mano.
var archivosDeEsquema = map[string]bool{
	"structure.sql": true, "schema.sql": true, "esquema.sql": true,
}

// EsSQL: la extensión, sin depender de mayúsculas ni del separador del sistema.
func EsSQL(ruta string) bool {
	return strings.EqualFold(path.Ext(Normalizar(ruta)), ".sql")
}

// Normalizar deja la ruta en la forma que usan los globs: barras hacia
// adelante y sin "./" delante. Git entrega así las rutas, pero no todo lo que
// llega aquí viene de git.
func Normalizar(ruta string) string {
	return path.Clean(strings.ReplaceAll(ruta, "\\", "/"))
}

// Parece responde si esta ruta es una migración de esquema.
//
// Se usa para decidir de qué merece la pena quejarse: un .sql que cambia el
// esquema y nadie vigila es un agujero en la compuerta; una consulta de sqlc o
// un modelo de dbt fuera de la lista es lo correcto, y avisar de ellos en cada
// commit convertiría el aviso en ruido que se aprende a ignorar.
func Parece(ruta string) bool {
	p := Normalizar(ruta)
	if !EsSQL(p) {
		return false
	}
	segs := strings.Split(path.Dir(p), "/")
	// Otro contenido nunca es esquema, ni dentro del árbol de migraciones.
	if EsOtroContenido(p) {
		return false
	}
	// Bajo un directorio que DECLARA migraciones, lo demás son dominios: una
	// fuente llamada "analytics" o un esquema llamado "reports" siguen siendo
	// migraciones, y tratarlas de otra cosa apaga la compuerta sobre cambios de
	// esquema de producción.
	if _, ok := raizDeMigraciones(p); ok {
		return true
	}
	for _, seg := range segs {
		if dirsDeOtroAsunto[strings.ToLower(seg)] {
			return false
		}
	}
	base := strings.ToLower(path.Base(p))
	return archivosDeEsquema[base] || versionDeMigracion.MatchString(base)
}

// EsOtroContenido responde si esta ruta es contenido VETADO: semillas,
// fixtures, volcados, ejemplos, consultas. Es el veto de Parece, y sólo el
// veto — no clasifica migraciones, no mira versionado ni nombres de esquema.
//
// Existe como función pública porque el veto tiene que aplicarse en DOS
// sitios que no pueden compartir a Parece entera:
//
//   - Aquí, al clasificar: una semilla no es migración.
//   - En el consumo de paths.migrations (squawk): los globs de árbol que
//     escribe Globs (`migrations/**/*.sql`) recapturan lo vetado que vive
//     DENTRO del árbol — `supabase/migrations/seeds/paises.sql` — y un glob
//     puesto a mano por el usuario puede recapturarlo también. Filtrar ahí
//     con Parece sería un error en la otra dirección: descartaría archivos
//     no versionados que el usuario incluyó deliberadamente en su config.
//     Lo que nunca puede llegar a la compuerta de migración insegura es el
//     contenido vetado, venga de donde venga el glob.
//
// Medido: sin este filtro en el consumo, un DROP TABLE en una semilla de
// arranque casaba `migrations/**/*.sql` y salía BLOQUEADO por ban-drop-table
// sobre datos que no tocan producción.
func EsOtroContenido(ruta string) bool {
	p := Normalizar(ruta)
	for _, seg := range strings.Split(path.Dir(p), "/") {
		if dirsDeOtroContenido[strings.ToLower(seg)] {
			return true
		}
	}
	return semillaPorNombre(path.Base(p))
}

// Globs devuelve los patrones para `paths.migrations` y, aparte, los .sql que
// quedaron FUERA de la vigilancia.
//
// Los dos valores importan. Vigilar de menos apaga la compuerta en silencio,
// que es el fallo que se está arreglando; vigilar de más manda a squawk
// archivos que no son DDL —consultas de sqlc, modelos de dbt, semillas— y sube
// el riesgo de cada commit que los toque. Por eso lo que se deja fuera no se
// descarta: se devuelve para que quien llame lo diga en voz alta.
func Globs(rutas []string) (globs []string, sinVigilar []string) {
	patrones := map[string]bool{}
	var archivosSQL []string

	for _, p := range rutas {
		p = Normalizar(p)
		if !EsSQL(p) {
			continue
		}
		archivosSQL = append(archivosSQL, p)
		// Un solo criterio para las dos superficies: Globs escribe la lista y
		// Parece decide de qué se queja el pipeline. Si discreparan, `init`
		// dejaría de vigilar algo de lo que el análisis sigue avisando, o al
		// revés — y esa incoherencia no la ve nadie hasta que muerde.
		if !Parece(p) {
			continue
		}

		if raiz, ok := raizDeMigraciones(p); ok {
			// El árbol entero. Hacen falta los DOS patrones: `**` no casa con
			// cero directorios, así que `x/**/*.sql` se salta `x/001.sql`.
			// Con uno solo, o se pierden las subcarpetas o se pierde la raíz.
			patrones[raiz+"/*.sql"] = true
			patrones[raiz+"/**/*.sql"] = true
			continue
		}
		base := strings.ToLower(path.Base(p))
		if archivosDeEsquema[base] {
			// Un nombre así vigila ESE archivo, no su carpeta: `db/structure.sql`
			// vive junto a cosas que no son esquema.
			patrones[p] = true
			continue
		}
		if versionDeMigracion.MatchString(base) {
			patrones[globDelDirectorio(path.Dir(p))] = true
		}
	}

	for g := range patrones {
		globs = append(globs, g)
	}
	sort.Strings(globs)

	// Qué queda fuera se calcula CASANDO contra los globs que de verdad se van
	// a escribir, no repitiendo la clasificación. Así el aviso no puede
	// contradecir a la lista: si un patrón sale mal formado y no casa con lo
	// que pretendía cubrir, ese archivo aparece aquí en vez de darse por
	// vigilado.
	compilados := Compilar(globs)
	for _, p := range archivosSQL {
		if !CasaAlguno(compilados, p) {
			sinVigilar = append(sinVigilar, p)
		}
	}
	sort.Strings(sinVigilar)
	return globs, sinVigilar
}

// semillaPorNombre reconoce las semillas que NO viven en su propia carpeta
// sino que se nombran en el archivo: `20240103_seed_datos.sql`. Es la
// convención de Supabase, dbmate y goose, y el veto por directorio no las veía.
//
// Medido: una de esas con `TRUNCATE pais;` y `DROP TABLE IF EXISTS pais_tmp;`
// salía BLOQUEADA por `ban-drop-table` — sobre datos de arranque que no tocan
// producción.
//
// La palabra tiene que ser el PRIMER término después de la versión, que es como
// se nombra de verdad. Si bastara con que apareciera en cualquier sitio, una
// migración legítima como `20240101_create_seed_table.sql` dejaría de vigilarse
// —y ese error va hacia el lado peligroso: no mirar.
func semillaPorNombre(base string) bool {
	nombre := strings.ToLower(strings.TrimSuffix(base, path.Ext(base)))
	campos := strings.FieldsFunc(nombre, func(r rune) bool {
		return r == '_' || r == '-' || r == '.'
	})
	// Se salta el prefijo de versión (001, 20240103, v1…), si lo hay. Y la versión
	// puede ocupar VARIOS campos: la propia regexp admite `v1.1__` porque —como
	// dice su comentario— Flyway numera con puntos tanto como con guiones bajos, y
	// el troceo de arriba parte por '.', así que `v1.1__seed_datos.sql` llega aquí
	// como [v1, 1, seed, datos]. Saltando sólo el primero quedaba "1" como primer
	// término, la semilla se vigilaba como migración de esquema y su TRUNCATE
	// volvía a salir BLOQUEADO — el fallo que esta función nació para evitar,
	// entrando por el layout que la regexp sí reconocía.
	//
	// Se descartan los campos puramente numéricos que siguen al prefijo, y sólo
	// esos: la guarda del lado peligroso queda intacta, porque en
	// `20240101_create_seed_table.sql` el término tras la versión es "create", no
	// es numérico y no está en dirsDeOtroContenido, así que sigue vigilada.
	if len(campos) > 1 && versionDeMigracion.MatchString(nombre) {
		campos = campos[1:]
		for len(campos) > 1 && soloDigitos(campos[0]) {
			campos = campos[1:]
		}
	}
	return len(campos) > 0 && dirsDeOtroContenido[campos[0]]
}

// soloDigitos: el campo es el resto de una versión multi-segmento, como el "1"
// de `v1.1__` o el "2" de `1_2__` una vez troceado el nombre.
func soloDigitos(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// raizDeMigraciones corta la ruta justo después del directorio que declara
// migraciones. Se queda con el PRIMERO que aparece: en
// `prisma/migrations/20240101_init/migration.sql` la raíz es
// `prisma/migrations`, no la carpeta de esa migración concreta.
func raizDeMigraciones(p string) (string, bool) {
	partes := strings.Split(path.Dir(p), "/")
	for i, seg := range partes {
		if dirsDeMigraciones[strings.ToLower(seg)] {
			return strings.Join(partes[:i+1], "/"), true
		}
	}
	return "", false
}

// globDelDirectorio: path.Dir devuelve "." en la raíz del repo, y "./*.sql" no
// casa con "002_moneda.sql". Era el glob que escribía init para cualquier
// migración en la raíz: sintácticamente válido, y vigilando el vacío.
func globDelDirectorio(dir string) string {
	if dir == "." || dir == "" {
		return "*.sql"
	}
	return dir + "/*.sql"
}

// Compilar descarta los patrones inválidos en vez de fallar: un glob mal
// escrito a mano en el config no puede tumbar el análisis entero. Lo que sí
// hace es quedar fuera de la vigilancia, y de eso avisa quien llama.
func Compilar(patrones []string) []glob.Glob {
	var out []glob.Glob
	for _, p := range patrones {
		if g, err := glob.Compile(p, '/'); err == nil {
			out = append(out, g)
		}
	}
	return out
}

func CasaAlguno(gs []glob.Glob, ruta string) bool {
	for _, g := range gs {
		if g.Match(ruta) {
			return true
		}
	}
	return false
}
