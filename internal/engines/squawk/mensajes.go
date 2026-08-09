package squawk

// Squawk explica sus hallazgos en inglés. Todo lo demás que ve el
// desarrollador —el panel, el hook, el informe— está en español, y una
// migración bloqueada es justo el momento en que menos apetece traducir
// mentalmente por qué.
//
// Estos textos no son la traducción literal: dicen QUÉ pasa en la base de
// datos y QUÉ hacer en su lugar, que es lo que hace falta a las once de la
// noche con el despliegue a medias.

type explicacion struct {
	Mensaje string
	Arreglo string
}

var enEspanol = map[string]explicacion{
	"adding-required-field": {
		"Columna NOT NULL sin valor por defecto en una tabla que ya existe",
		"Hazlo en tres pasos: añade la columna como NULL, rellena los datos por lotes, " +
			"y sólo entonces ponle NOT NULL. Añadirla directa obliga a Postgres a " +
			"reescribir la tabla entera con la escritura bloqueada.",
	},
	"require-concurrent-index-creation": {
		"Índice creado sin CONCURRENTLY: bloquea las escrituras mientras se construye",
		"Usa CREATE INDEX CONCURRENTLY. Tarda más y no puede ir dentro de una " +
			"transacción, pero la tabla sigue aceptando escrituras.",
	},
	"disallowed-unique-constraint": {
		"Restricción UNIQUE directa: toma un lock exclusivo sobre toda la tabla",
		"Crea primero un índice único con CREATE UNIQUE INDEX CONCURRENTLY y después " +
			"añade la restricción con ADD CONSTRAINT ... USING INDEX, que ya no bloquea.",
	},
	"changing-column-type": {
		"Cambiar el tipo de una columna reescribe la tabla con lectura y escritura bloqueadas",
		"Añade una columna nueva con el tipo deseado, copia los datos por lotes, cambia " +
			"el código para que use la nueva, y retira la vieja en otro despliegue.",
	},
	"ban-drop-column": {
		"Eliminar una columna rompe cualquier versión anterior que siga desplegada",
		"Deja de usarla en el código, despliega, y bórrala en una migración posterior. " +
			"Durante un despliegue por fases conviven dos versiones del código.",
	},
	"ban-drop-table": {
		"Eliminar una tabla es irreversible y rompe lo que aún la lea",
		"Renómbrala primero (por ejemplo a tabla_obsoleta), despliega, comprueba que " +
			"nadie la toca, y bórrala después.",
	},
	"ban-drop-database": {
		"Eliminar la base de datos completa",
		"Esto no debería ocurrir en una migración. Si es intencional, hazlo fuera del " +
			"flujo de despliegue y con un respaldo verificado.",
	},
	"ban-drop-not-null": {
		"Quitar NOT NULL puede dejar entrar nulos donde el código no los espera",
		"Comprueba que todo lo que lee esa columna maneja el nulo ANTES de relajar la " +
			"restricción.",
	},
	"adding-serial-primary-key-field": {
		"Añadir una clave primaria serial reescribe la tabla y la bloquea",
		"Añade la columna, rellénala por lotes, crea el índice único con CONCURRENTLY y " +
			"promuévela a clave primaria al final.",
	},
	"disallowed-not-null-constraint": {
		"Añadir NOT NULL a una columna existente exige revisar toda la tabla",
		"Añade primero una restricción CHECK ... NOT VALID, valídala aparte con VALIDATE " +
			"CONSTRAINT, y convierte a NOT NULL después.",
	},
	"renaming-column": {
		"Renombrar una columna rompe la versión del código que sigue desplegada",
		"Añade la columna nueva, escribe en las dos durante una versión, migra las " +
			"lecturas, y retira la vieja al final.",
	},
	"renaming-table": {
		"Renombrar una tabla rompe la versión del código que sigue desplegada",
		"Crea una vista con el nombre viejo apuntando al nuevo, o haz el cambio en dos " +
			"despliegues.",
	},
	"prefer-robust-stmts": {
		"La migración no es reintentable si falla a medias",
		"Envuélvela en una transacción, o usa IF NOT EXISTS para que volver a lanzarla " +
			"sea inofensivo.",
	},
	"prefer-text-field": {
		"varchar(n) obliga a reescribir la tabla cuando el límite se queda corto",
		"Usa text con una restricción CHECK de longitud: cambiar el límite pasa a ser " +
			"instantáneo.",
	},
	"require-concurrent-index-deletion": {
		"Borrar un índice sin CONCURRENTLY bloquea las consultas sobre la tabla",
		"Usa DROP INDEX CONCURRENTLY.",
	},
	"constraint-missing-not-valid": {
		"Añadir una restricción sin NOT VALID revisa todas las filas con la tabla bloqueada",
		"Añádela con NOT VALID y valídala después con VALIDATE CONSTRAINT, que no bloquea.",
	},
	"transaction-nesting": {
		"Transacciones anidadas: la migración puede quedar a medias",
		"Deja que la herramienta de migraciones gestione la transacción; no abras otra dentro.",
	},
}

// traducir devuelve el texto en español de una regla. Si no la conocemos, se
// entrega lo que dijo squawk: es preferible un mensaje en inglés a ninguno.
func traducir(regla, mensajeOriginal, ayudaOriginal string) (string, string) {
	if e, ok := enEspanol[regla]; ok {
		return e.Mensaje, e.Arreglo
	}
	if mensajeOriginal == "" {
		mensajeOriginal = regla
	}
	return mensajeOriginal, ayudaOriginal
}
