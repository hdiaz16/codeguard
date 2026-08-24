package migraciones

import (
	"regexp"
	"strings"
)

// Dialecto deduce el motor de base de datos leyendo el DDL, y devuelve "" si
// no encuentra ninguna prueba.
//
// Existe por un daño medido. Mientras `init` dejaba `paths.migrations` vacío,
// escribir `migrations_dialect: postgres` a ciegas no costaba nada: squawk no
// corría de todas formas. En cuanto la lista se llenó de verdad, ese default se
// convirtió en un bloqueo: un `CREATE INDEX` legal en SQLite salió BLOQUEADO
// exigiendo CONCURRENTLY —sintaxis que en SQLite no existe— y el desarrollador
// se queda sin salida, porque el arreglo que se le propone es imposible.
//
// La regla es "sólo pruebas positivas". El comentario de `init` avisaba, con
// razón, de que un detector que ADIVINA acierta a veces y se equivoca callado
// el resto; el esquema de este mismo repo es SQLite y no tiene una sola marca
// que lo delate. Por eso aquí no se adivina: sin marca se devuelve "" y manda
// el valor por defecto de siempre. Lo que se arregla es el caso contrario —el
// repo que SÍ grita lo que es y al que no se le estaba escuchando.
// Deteccion son las PISTAS que dejó el DDL sobre su motor. No es un veredicto,
// y eso es deliberado.
//
// Este paquete llegó a decidir el dialecto y escribirlo en la config. Se quitó
// después de tres rondas de fallos medidos, todos de la misma forma: cuando el
// detector se equivoca, `paths.migrations_dialect` deja de ser postgres, squawk
// deja de correr, y la compuerta de migraciones queda APAGADA sin que nada lo
// diga — con un ✓ verde encima. Los casos no eran rebuscados: `NVARCHAR(n)` es
// MySQL legal, `jsonb()` es SQLite desde la 3.45, y PostgreSQL moderno no deja
// ninguna huella reconocible, así que un volcado heredado decidía por todo el
// repo.
//
// El problema no era la heurística sino quién decide. Una detección que ACIERTA
// ahorra una línea de configuración; una que falla apaga una capa entera en
// silencio, y ese silencio es exactamente lo que este producto existe para no
// producir. Así que ahora se informa y decide el equipo.
type Deteccion struct {
	// Pistas: motor → índices de los archivos donde aparecieron sus marcas.
	// Se guardan los índices y no un conteo para poder NOMBRAR el archivo: un
	// aviso que dice "vi marcas de MySQL" sin decir dónde no se puede
	// comprobar, y lo que no se puede comprobar se ignora.
	Pistas map[string][]int
	// Archivos leídos, para poder hablar de proporciones ("1 de 4").
	Archivos int
}

// OtrosMotores devuelve los motores distintos de PostgreSQL con marcas, en
// orden estable. Es lo que hay que contarle al desarrollador.
func (d Deteccion) OtrosMotores() []string {
	var out []string
	for _, m := range motores {
		if m.nombre != "postgres" && len(d.Pistas[m.nombre]) > 0 {
			out = append(out, m.nombre)
		}
	}
	return out
}

// Analizar busca marcas de cada motor en el DDL y devuelve dónde las vio.
// No decide nada: ver Deteccion.
func Analizar(contenidos []string) Deteccion {
	d := Deteccion{Pistas: map[string][]int{}, Archivos: len(contenidos)}
	for i, texto := range contenidos {
		limpio := sinComentariosNiCadenas(texto)
		for _, m := range motores {
			for _, re := range m.marcas {
				if re.MatchString(limpio) {
					d.Pistas[m.nombre] = append(d.Pistas[m.nombre], i)
					break // un archivo cuenta una vez por motor
				}
			}
		}
	}
	return d
}

var motores = []struct {
	nombre string
	marcas []*regexp.Regexp
}{
	// PostgreSQL entra en la lista aunque sea el valor por defecto, y no es
	// redundante: sirve para DETECTAR EL CONFLICTO. Sin él, un repo PostgreSQL
	// con un volcado MySQL heredado sólo tenía marcas de MySQL y se clasificaba
	// entero como MySQL, apagando la compuerta sobre las migraciones nuevas.
	// Sólo marcas que NO existen en los otros tres. Se descartaron varias que
	// parecían obvias y no lo son, y cada una habría reintroducido el bloqueo
	// imposible en el repo equivocado: `SERIAL` es un alias en MySQL,
	// `RETURNING` existe en MariaDB y en SQLite desde 3.35, y `USING BTREE` /
	// `USING HASH` son sintaxis de índice de MySQL. Una marca ambigua aquí no
	// se queda en "no detecto": provoca un CONFLICTO, y el conflicto devuelve
	// el valor por defecto.
	{"postgres", []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(big|small)serial\b`),
		// `jsonb` como TIPO, no como función: SQLite tiene jsonb() nativa desde
		// la 3.45, y con la marca a secas un esquema SQLite disparaba la de
		// PostgreSQL, provocaba conflicto y acababa bloqueado. Se exige que lo
		// siguiente no sea un paréntesis.
		regexp.MustCompile(`(?i)\bjsonb\b\s*[^(\s]`),
		regexp.MustCompile(`(?i)\btimestamptz\b`),
		regexp.MustCompile(`(?i)\bconcurrently\b`),
		regexp.MustCompile(`(?i)\bcreate\s+extension\b`),
		regexp.MustCompile(`(?i)\busing\s+(gin|gist)\b`),
		regexp.MustCompile(`(?i)\blanguage\s+plpgsql\b`),
		// PostgreSQL moderno no usa nada de lo de arriba: ni bigserial ni
		// timestamptz. Sin esta marca, un repo así no dejaba huella y cualquier
		// volcado heredado decidía por él.
		regexp.MustCompile(`(?i)\bgenerated\s+(always|by\s+default)\s+as\s+identity\b`),
	}},
	{"sqlite", []*regexp.Regexp{
		regexp.MustCompile(`(?i)\bautoincrement\b`), // en Postgres no existe; en MySQL es AUTO_INCREMENT
		regexp.MustCompile(`(?im)^\s*pragma\s`), // multilínea: rara vez está en la primera línea
		regexp.MustCompile(`(?i)\bwithout\s+rowid\b`),
		regexp.MustCompile(`(?i)\bsqlite_[a-z]+\b`),
	}},
	{"mysql", []*regexp.Regexp{
		regexp.MustCompile(`(?i)\bengine\s*=\s*(innodb|myisam|memory|archive)\b`),
		regexp.MustCompile(`(?i)\bauto_increment\b`),
		regexp.MustCompile("`[A-Za-z_][A-Za-z0-9_]*`"), // identificadores entre acentos graves
		regexp.MustCompile(`(?i)\bunsigned\b`),
		regexp.MustCompile(`(?i)\btinyint\s*\(`),
	}},
	{"sqlserver", []*regexp.Regexp{
		regexp.MustCompile(`(?i)\bidentity\s*\(\s*\d`),
		regexp.MustCompile(`(?i)\bn?varchar\s*\(\s*max\s*\)`),
		// `NVARCHAR(n)` a secas NO vale: es sinónimo documentado de
		// `VARCHAR(n) CHARACTER SET utf8` en MySQL y MariaDB (NATIONAL VARCHAR).
		// Con esa marca, un repo MySQL de un solo motor disparaba también la de
		// SQL Server, daba conflicto y acababa bloqueado por el default de
		// PostgreSQL. Medido. Sólo queda la forma (n)varchar(max), que sí es
		// exclusiva de SQL Server.
		regexp.MustCompile(`\[dbo\]`),
		regexp.MustCompile(`(?im)^\s*go\s*$`), // separador de lotes
	}},
}

// delimitadorDolar reconoce un $$ o $etiqueta$ que empiece en i, y devuelve el
// delimitador y su longitud (0 si ahí no empieza ninguno).
//
// La etiqueta va vacía o empieza por letra o guion bajo, que es la regla de
// PostgreSQL. Importa para no confundir los parámetros posicionales: en
// `WHERE id = $1 AND x = $2`, un `$1$` inventado partiría la consulta en dos y
// se tragaría el DDL que viniera detrás.
func delimitadorDolar(s string, i int) (string, int) {
	if s[i] != '$' {
		return "", 0
	}
	j := i + 1
	for j < len(s) && (s[j] == '_' ||
		(s[j] >= 'a' && s[j] <= 'z') || (s[j] >= 'A' && s[j] <= 'Z') ||
		(j > i+1 && s[j] >= '0' && s[j] <= '9')) {
		j++
	}
	if j < len(s) && s[j] == '$' {
		return s[i : j+1], j + 1 - i
	}
	return "", 0
}

// sinComentariosNiCadenas quita lo que no es código antes de buscar marcas.
//
// Sin esto, un comentario como "aquí no usamos AUTO_INCREMENT" bastaría para
// clasificar mal el repo entero y apagar squawk sin que nadie lo hubiera
// decidido — exactamente el fallo silencioso que este paquete persigue, sólo
// que provocado por una frase en prosa.
func sinComentariosNiCadenas(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	const (
		normal = iota
		linea  // -- hasta el fin de línea
		bloque // /* … */
		cadena // '…'
	)
	estado := normal
	nivelBloque := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch estado {
		case normal:
			// Cadena con signos de dólar ($$…$$ o $tag$…$tag$). Es lo que se usa
			// en PostgreSQL para cuerpos de función y para documentar sin escapar
			// comillas, y dentro cabe CUALQUIER texto. Sin saltarlo, un
			// `COMMENT ON COLUMN id IS $$equivale al AUTO_INCREMENT de MySQL$$`
			// clasificaba el repo como MySQL y apagaba squawk en silencio — el
			// fallo peor de los dos posibles, y medido sobre DDL de PostgreSQL
			// perfectamente normal.
			if c == '$' {
				if delim, n := delimitadorDolar(s, i); n > 0 {
					if fin := strings.Index(s[i+n:], delim); fin >= 0 {
						i += n + fin + n - 1 // el for avanza al carácter siguiente
					} else {
						i = len(s) // sin cierre: el resto es cuerpo, no se analiza
					}
					continue
				}
			}
			switch {
			case c == '-' && i+1 < len(s) && s[i+1] == '-':
				estado, i = linea, i+1
			case c == '/' && i+1 < len(s) && s[i+1] == '*':
				estado, i = bloque, i+1
				nivelBloque = 0
			case c == '\'':
				estado = cadena
			default:
				b.WriteByte(c)
			}
		case linea:
			if c == '\n' {
				estado = normal
				b.WriteByte(c) // el salto se conserva: hay marcas ancladas a la línea
			}
		case bloque:
			if c == '/' && i+1 < len(s) && s[i+1] == '*' {
				nivelBloque++
				i++
			} else if c == '*' && i+1 < len(s) && s[i+1] == '/' {
				if nivelBloque > 0 {
					nivelBloque--
				} else {
					estado = normal
				}
				i++
			}
		case cadena:
			if c == '\'' {
				estado = normal
			}
		}
	}
	return b.String()
}
