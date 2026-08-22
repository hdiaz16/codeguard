package pipeline

import (
	"strings"
)

// palabrasQueBifurcan son las que abren un camino nuevo en los lenguajes de
// llaves. "else" no cuenta: no añade un camino, completa el de su if.
var palabrasQueBifurcan = []string{"if", "for", "while", "case", "catch"}

// complejidadLlaves aproxima la complejidad en TS/JS/C#/Java sin un parser por
// lenguaje. Sigue la profundidad de llaves para saber dónde acaba cada
// función y cuenta palabras clave dentro.
//
// Es una aproximación consciente: no entiende cadenas de texto ni comentarios
// que contengan estas palabras, así que puede contar de más. Por eso sólo
// avisa, y por eso el umbral es holgado. Un parser por lenguaje daría números
// exactos a cambio de mantener cuatro gramáticas.
func complejidadLlaves(src []byte) []funcion {
	lineas := strings.Split(string(src), "\n")
	var out []funcion
	var actual *funcion
	var candidata *funcion
	profundidad, profundidadInicio := 0, 0

	for i, linea := range lineas {
		limpia := sinTextoNiComentarios(linea)

		// Reconocer una firma y ver abrirse su cuerpo son dos eventos, y en
		// estilo Allman caen en líneas distintas. La candidata es la firma que
		// ya vimos y todavía espera su llave.
		if actual == nil {
			switch {
			case pareceDeclaracionDeFuncion(limpia):
				actual = &funcion{Nombre: nombreDeFuncion(limpia), Linea: i + 1, Complejidad: 1}
				profundidadInicio = profundidad
				candidata = nil
			case candidata != nil && strings.HasPrefix(strings.TrimSpace(limpia), "{"):
				actual = candidata
				profundidadInicio = profundidad
				candidata = nil
			case strings.TrimSpace(limpia) == "":
				// Línea en blanco (o sólo comentario): la candidata sigue esperando.
			case pareceCandidataDeFirma(limpia):
				candidata = &funcion{Nombre: nombreDeFuncion(limpia), Linea: i + 1, Complejidad: 1}
			default:
				candidata = nil
			}
		}
		if actual != nil {
			for _, p := range palabrasQueBifurcan {
				actual.Complejidad += contarPalabra(limpia, p)
			}
			actual.Complejidad += strings.Count(limpia, "&&") + strings.Count(limpia, "||")
		}

		profundidad += strings.Count(limpia, "{") - strings.Count(limpia, "}")
		if actual != nil && profundidad <= profundidadInicio && strings.Contains(limpia, "}") {
			out = append(out, *actual)
			actual = nil
		}
	}
	if actual != nil {
		out = append(out, *actual) // archivo sin cerrar: contamos lo que vimos
	}
	return out
}

// sinTextoNiComentarios quita literales de cadena y comentarios de línea para
// no contar palabras clave que sólo aparecen en un mensaje o una nota.
func sinTextoNiComentarios(l string) string {
	var b strings.Builder
	var comilla rune
	anterior := rune(0)
	for i, r := range l {
		if comilla == 0 && (r == '/' && i+1 < len(l) && l[i+1] == '/') {
			break
		}
		switch {
		case comilla != 0:
			if r == comilla && anterior != '\\' {
				comilla = 0
			}
		case r == '"' || r == '\'' || r == '`':
			comilla = r
		default:
			b.WriteRune(r)
		}
		anterior = r
	}
	return b.String()
}

// pareceDeclaracionDeFuncion reconoce el caso de una sola línea: la firma y la
// llave de su cuerpo juntas (estilo K&R).
func pareceDeclaracionDeFuncion(l string) bool {
	return strings.Contains(l, "{") && pareceFirmaDeFuncion(l)
}

// pareceCandidataDeFirma reconoce una firma que aún no ha abierto su cuerpo.
// Descarta lo que termina en ';' o ',' porque ahí no hay cuerpo que abrir: una
// llamada, una declaración abstracta o de interfaz, un argumento a medias.
func pareceCandidataDeFirma(l string) bool {
	t := strings.TrimSpace(l)
	if strings.HasSuffix(t, ";") || strings.HasSuffix(t, ",") {
		return false
	}
	return !strings.Contains(t, "{") && pareceFirmaDeFuncion(t)
}

// palabrasQueIntroducenUnTipo son las que declaran un TIPO en vez de una
// función. Es la diferencia de verdad entre `public class Repo(IDb db)` y
// `public Repo(IDb db)`: los modificadores, el nombre y los paréntesis son
// idénticos, y lo único que distingue a uno del otro es esta palabra.
// "namespace" y "module" NO están, a propósito: ninguna declaración suya lleva
// paréntesis, así que no podían producir el fantasma que esta lista viene a
// cerrar — quitarlas no cambia ni uno de los cinco casos ni el censo del corpus.
// Lo que sí hacían era coste: eran la mitad de lo que apagaba
// `module.exports = function (x)`.
var palabrasQueIntroducenUnTipo = []string{
	"class", "record", "struct", "interface", "enum", // C#, Java, TypeScript
}

// declaraUnTipo mira SÓLO la cabecera —lo que va delante del primer '(' o '=',
// parámetros— y sólo las palabras que llevan un nombre detrás. Las dos
// restricciones se ganaron con casos reales:
//
//   - Sólo la cabecera, porque en C# la restricción genérica `where T : class`
//     va DETRÁS de los paréntesis y aparece en montones de métodos legítimos:
//     buscar "class" en la línea entera se los cargaría a todos.
//   - Sólo si lleva nombre detrás, porque `record` es palabra contextual en C# e
//     identificador restringido en Java, y en JavaScript nada impide una
//     `function record(x)`. Cuando la palabra es la ÚLTIMA de la cabecera es el
//     nombre de lo que se declara, no lo que lo introduce.
func declaraUnTipo(t string) bool {
	// La cabecera se corta en el primer '(' O '=' — no sólo en el paréntesis.
	// Con `const record = (x) => {` los campos son [const, record, =], así que
	// `record` dejaba de ser el último y se leía como palabra que INTRODUCE un
	// tipo: la función desaparecía del informe. Cortar también en '=' devuelve
	// la regla a su sentido, y no rompe `operator ==(A a, B b)` ni un parámetro
	// con valor por defecto, porque ahí el '(' viene antes.
	cabecera := t
	if i := strings.IndexAny(t, "(="); i >= 0 {
		cabecera = t[:i]
	}
	campos := strings.Fields(cabecera)
	for i, campo := range campos {
		if i == len(campos)-1 {
			break // la última es el nombre de lo declarado
		}
		for _, p := range palabrasQueIntroducenUnTipo {
			// Igualdad EXACTA del campo, no "contiene la palabra". El punto no
			// es carácter de palabra, así que `module.exports` daba positivo
			// para "module" y apagaba `module.exports = function (x)`, que es
			// el patrón CommonJS canónico. Lo mismo con `this.record` y
			// `obj.module`. Una declaración de tipo nunca lleva el introductor
			// pegado a un punto.
			if campo == p {
				return true
			}
		}
	}
	return false
}

// sentenciasConParentesis abren un bloque con una cláusula entre paréntesis.
// Se parecen mucho a una firma —palabra, paréntesis, llave— pero no declaran
// nada, así que contarlas como función parte el archivo por donde no es.
//
// Se comparan como PRIMERA PALABRA y no como prefijo de texto. Con prefijo,
// `format(x) {` empezaba por "for" y dejaba de detectarse: un método llamado
// `format` es de lo más común en TS/JS, y lo mismo les pasaba a `ifPresent`,
// `whileLoop`, `switchTo` o `catchAll`.
var sentenciasConParentesis = map[string]bool{
	"if": true, "else": true, "for": true, "foreach": true, "while": true,
	"do": true, "switch": true, "case": true, "try": true, "catch": true,
	"finally": true,
	// C#: abren bloque con paréntesis y no son funciones.
	"using": true, "lock": true, "fixed": true,
	// Java.
	"synchronized": true,
}

// primeraPalabra devuelve el identificador con el que arranca la línea, o ""
// si empieza por algo que no es carácter de palabra (una llave, un corchete de
// atributo, un decorador).
func primeraPalabra(t string) string {
	for i, r := range t {
		if !esCaracterDePalabra(r) {
			return t[:i]
		}
	}
	return t
}

func pareceFirmaDeFuncion(l string) bool {
	t := strings.TrimSpace(l)
	if !strings.Contains(t, "(") {
		return false
	}
	// Antes que nada: una declaración de tipo no es una firma por mucho que
	// lleve paréntesis y modificadores. Si se cuela, el escáner abre ahí un
	// cuerpo que no cierra hasta el final de la clase y se traga todos sus
	// métodos en una función fantasma con la complejidad sumada.
	if declaraUnTipo(t) {
		return false
	}
	switch {
	case strings.HasPrefix(t, "}"):
		return false
	// Va por delante del caso de la flecha a propósito: una condición con un
	// lambda dentro —`foreach (var x in lista.Where(y => y.Ok))`— lleva "=>" y
	// se contaba como función.
	case sentenciasConParentesis[primeraPalabra(t)]:
		return false
	case strings.HasPrefix(t, "function ") || strings.Contains(t, " function "):
		return true
	case strings.Contains(t, "=>"):
		return true
	case contarPalabra(t, "public")+contarPalabra(t, "private")+
		contarPalabra(t, "protected")+contarPalabra(t, "static")+
		contarPalabra(t, "async") > 0:
		return true
	}
	// Método suelto de clase: nombre(args) {
	i := strings.Index(t, "(")
	return i > 0 && esIdentificador(strings.TrimSpace(t[:i]))
}

func esIdentificador(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		esLetra := r == '_' || r == '$' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		esDigitoInterno := i > 0 && r >= '0' && r <= '9'
		if !esLetra && !esDigitoInterno {
			return false
		}
	}
	return true
}

func nombreDeFuncion(l string) string {
	t := strings.TrimSpace(l)
	i := strings.Index(t, "(")
	if i <= 0 {
		return "(anónima)"
	}
	campos := strings.FieldsFunc(t[:i], func(r rune) bool {
		return r == ' ' || r == '\t' || r == '=' || r == ':'
	})
	if len(campos) == 0 {
		return "(anónima)"
	}
	return campos[len(campos)-1]
}

// contarPalabra cuenta apariciones como palabra completa, para que "iffy" o
// "forEach" no cuenten como bifurcaciones.
func contarPalabra(l, palabra string) int {
	n, desde := 0, 0
	for {
		i := strings.Index(l[desde:], palabra)
		if i < 0 {
			return n
		}
		i += desde
		antes := i == 0 || !esCaracterDePalabra(rune(l[i-1]))
		fin := i + len(palabra)
		despues := fin >= len(l) || !esCaracterDePalabra(rune(l[fin]))
		if antes && despues {
			n++
		}
		desde = fin
	}
}

func esCaracterDePalabra(r rune) bool {
	return r == '_' || r == '$' || (r >= 'a' && r <= 'z') ||
		(r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}
