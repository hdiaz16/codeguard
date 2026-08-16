package pipeline

import (
	"fmt"
	"strings"
	"testing"
)

// tresMetodos devuelve el cuerpo de tres métodos de complejidad 7 cada uno
// (el camino base más seis `if`). Se comparte entre los casos para que el
// número que se espera sea evidente y no haya que recontarlo en cada uno.
func tresMetodos() string {
	metodo := func(nombre string) string {
		return "    public int " + nombre + "(int x)\n" +
			"    {\n" +
			"        if (x == 1) { return 1; }\n" +
			"        if (x == 2) { return 2; }\n" +
			"        if (x == 3) { return 3; }\n" +
			"        if (x == 4) { return 4; }\n" +
			"        if (x == 5) { return 5; }\n" +
			"        if (x == 6) { return 6; }\n" +
			"        return 0;\n" +
			"    }\n"
	}
	return metodo("A") + "\n" + metodo("B") + "\n" + metodo("C")
}

// cuerpoDeDiecinueve devuelve el cuerpo de una función de complejidad 19 —el
// camino base más dieciocho `if`—, cuatro por encima del umbral por defecto.
// El número es lo que hace que estos casos importen: no son una rareza del
// censo interno, son un aviso que se emitía y dejó de emitirse.
func cuerpoDeDiecinueve() string {
	var b strings.Builder
	for i := 1; i <= 18; i++ {
		fmt.Fprintf(&b, "    if (x === %d) { return %d; }\n", i, i)
	}
	b.WriteString("    return 0;\n")
	return b.String()
}

// comprobar exige el censo exacto de funciones: nombre, línea y complejidad.
// Comparar sólo la longitud dejaría pasar justo el fallo que se persigue —una
// función fantasma que se come a las de verdad mantiene el recuento bajo.
func comprobar(t *testing.T, src string, esperado []funcion) {
	t.Helper()
	got := complejidadLlaves([]byte(src))
	if len(got) != len(esperado) {
		t.Fatalf("esperaba %d función(es) %+v, hubo %d: %+v", len(esperado), esperado, len(got), got)
	}
	for i, q := range esperado {
		if got[i] != q {
			t.Errorf("función %d: esperaba %+v, hubo %+v", i, q, got[i])
		}
	}
}

// H025-bis — el arreglo del estilo Allman despertó un falso positivo que sí
// dispara hallazgos, y de la peor manera: escondiendo los de verdad.
//
// `pareceFirmaDeFuncion` daba por firma cualquier declaración con paréntesis y
// un modificador delante. Un constructor primario de C# 12 —`public class
// Repo(IDb db)`— cumple las dos cosas, así que la línea de la CLASE se leía
// como una firma; con la llave en Allman, el escáner abría ahí el "cuerpo de la
// función" y no lo cerraba hasta la llave final de la clase.
//
// Resultado: tres métodos de complejidad 7 se fundían en una función fantasma
// llamada `Repo` de complejidad 19 —la suma de las ramas de los tres—, que
// supera el umbral de 15 y emite un aviso apuntando a la línea de la clase.
// Los tres métodos reales DESAPARECÍAN del informe. Un aviso inventado es
// molesto; perder las funciones que había que mirar es lo que hace daño.
//
// En K&R esto ya fallaba, pero C# se escribe en Allman: el arreglo de H025 es
// el que lo puso en circulación.
func TestLaClaseConConstructorPrimarioNoSeTragaSusMetodos(t *testing.T) {
	src := "public class Repo(IDb db)\n" +
		"{\n" +
		tresMetodos() +
		"}\n"

	comprobar(t, src, []funcion{
		{Nombre: "A", Linea: 3, Complejidad: 7},
		{Nombre: "B", Linea: 14, Complejidad: 7},
		{Nombre: "C", Linea: 25, Complejidad: 7},
	})

	// Explícito, porque es EL síntoma: si vuelve el fantasma, este mensaje dice
	// exactamente qué pasó en vez de dejar un recuento raro que hay que descifrar.
	for _, fn := range complejidadLlaves([]byte(src)) {
		if fn.Nombre == "Repo" {
			t.Errorf("la declaración de la clase se leyó como función: %+v", fn)
		}
	}
}

// Y lo mismo por donde se ve: el aviso. La función fantasma salía con
// complejidad 19, por encima del umbral de 15, así que no se quedaba en una
// rareza del censo interno —emitía un hallazgo `complejidad-excesiva` apuntando
// a la línea de la clase, por unos métodos que individualmente están todos por
// debajo del umbral. Aquí no debe salir ningún aviso.
func TestElConstructorPrimarioNoInventaUnAvisoDeComplejidad(t *testing.T) {
	src := "public class Repo(IDb db)\n" +
		"{\n" +
		tresMetodos() +
		"}\n"

	cfg := repoTemporal(t, map[string]string{"Repo.cs": src})
	fs := revisarComplejidad(cfg, cambios("Repo.cs"))
	if len(fs) != 0 {
		t.Errorf("ningún método pasa de 7 y el umbral es %d; se emitieron %d aviso(s): %+v",
			UmbralComplejidadPorDefecto, len(fs), fs)
	}
}

// Un record de C# con cuerpo es el mismo agujero con otra palabra.
func TestElRecordDeCSharpNoSeTragaSuCuerpo(t *testing.T) {
	src := "public record Punto(int X, int Y)\n" +
		"{\n" +
		tresMetodos() +
		"}\n"

	comprobar(t, src, []funcion{
		{Nombre: "A", Linea: 3, Complejidad: 7},
		{Nombre: "B", Linea: 14, Complejidad: 7},
		{Nombre: "C", Linea: 25, Complejidad: 7},
	})
}

// Java también tiene records desde 16, y la misma forma.
func TestElRecordDeJavaNoSeTragaSuCuerpo(t *testing.T) {
	src := "public record Punto(int x, int y)\n" +
		"{\n" +
		tresMetodos() +
		"}\n"

	comprobar(t, src, []funcion{
		{Nombre: "A", Linea: 3, Complejidad: 7},
		{Nombre: "B", Linea: 14, Complejidad: 7},
		{Nombre: "C", Linea: 25, Complejidad: 7},
	})
}

// El caso de control: la MISMA clase sin constructor primario ya funcionaba y
// tiene que seguir funcionando. Y trae dentro la otra mitad de la comprobación
// —un constructor de verdad, `public Repo(IDb db)`, que no lleva ninguna
// palabra de tipo y por tanto SÍ es una función y debe seguir contándose.
func TestElConstructorDeVerdadSigueSiendoUnaFuncion(t *testing.T) {
	src := "public class Repo\n" +
		"{\n" +
		"    private readonly IDb db;\n" +
		"\n" +
		"    public Repo(IDb db)\n" +
		"    {\n" +
		"        if (db == null) { throw new ArgumentNullException(); }\n" +
		"        this.db = db;\n" +
		"    }\n" +
		"\n" +
		tresMetodos() +
		"}\n"

	comprobar(t, src, []funcion{
		{Nombre: "Repo", Linea: 5, Complejidad: 2},
		{Nombre: "A", Linea: 11, Complejidad: 7},
		{Nombre: "B", Linea: 22, Complejidad: 7},
		{Nombre: "C", Linea: 33, Complejidad: 7},
	})
}

// La trampa de arreglar esto con "¿la línea contiene la palabra class?": en C#
// la restricción genérica `where T : class` va DESPUÉS de los paréntesis y
// aparece en montones de métodos legítimos. Lo que distingue una declaración de
// TIPO no es que la palabra esté en la línea, sino que esté en la cabecera, por
// delante de la lista de parámetros.
func TestLaRestriccionGenericaWhereTClassSigueSiendoUnMetodo(t *testing.T) {
	src := "public T Buscar<T>(int id) where T : class\n" +
		"{\n" +
		"    if (id == 1) { return null; }\n" +
		"    if (id == 2) { return null; }\n" +
		"    return null;\n" +
		"}\n"

	// El nombre sale con el parámetro de tipo pegado porque así lo compone
	// nombreDeFuncion; es cosmético y no es lo que se prueba aquí. Lo que
	// importa es que la línea SIGA siendo una función y con su complejidad.
	comprobar(t, src, []funcion{{Nombre: "Buscar<T>", Linea: 1, Complejidad: 3}})
}

// Y la simétrica: un parámetro que se LLAME `record` (en C# y en Java es
// identificador válido, no palabra reservada) no convierte el método en un
// tipo.
func TestUnParametroLlamadoRecordNoConvierteElMetodoEnTipo(t *testing.T) {
	src := "public void Guardar(Registro record)\n" +
		"{\n" +
		"    if (record == null) { return; }\n" +
		"}\n"

	comprobar(t, src, []funcion{{Nombre: "Guardar", Linea: 1, Complejidad: 2}})
}

// Y la mitad que faltaba de esa misma simetría, que es donde se rompió de
// verdad: la palabra contextual en JavaScript y TypeScript. Ahí `record`,
// `struct`, `namespace` y `module` no son palabras reservadas de nada —son
// nombres de variable corrientes—, y `module.exports` es el patrón CommonJS
// canónico.
//
// Rechazar la línea por contener una de esas palabras apagaba la función
// entera. Dos causas distintas, las dos con el mismo efecto:
//
//   - Buscar la palabra DENTRO del campo en vez de exigir el campo entero: el
//     punto no es carácter de palabra, así que `module.exports` daba positivo
//     para "module", y lo mismo `this.record` y `obj.module`.
//   - Dar por hecho que la palabra que lleva un nombre detrás introduce un
//     tipo: en `const record = (x) => {` el último campo de la cabecera es el
//     `=`, no `record`, así que `record` parecía introducir algo.
//
// Los seis casos valen 19 de complejidad a propósito, por encima del umbral de
// 15: cada uno era un aviso que se emitía y dejó de emitirse. Un falso negativo
// no deja rastro —el aviso que no sale nadie lo echa de menos—, así que se
// comprueba por donde se ve, contando los hallazgos, y no sólo en el censo.
func TestLaPalabraContextualDeJavaScriptNoApagaLaFuncion(t *testing.T) {
	casos := []struct {
		nombre  string
		archivo string
		abre    string
		cierra  string
	}{
		{"module.exports, el patrón CommonJS canónico", "manejador.js",
			"module.exports = function (x) {", "};"},
		{"module.exports con propiedad", "manejador.js",
			"module.exports.handler = async function (x) {", "};"},
		{"const record, que es como se escribe hoy function record", "registro.ts",
			"const record = (x) => {", "};"},
		{"export const namespace", "espacio.ts",
			"export const namespace = (x) => {", "};"},
		{"let struct", "forma.js",
			"let struct = function (x) {", "};"},
		{"this.record", "registro.js",
			"this.record = function (x) {", "};"},
		{"obj.module", "objeto.js",
			"obj.module = function (x) {", "};"},
		// El control, y no es de adorno: es la forma que el comentario de
		// `declaraUnTipo` dice cubrir —"en JavaScript nada impide una
		// `function record(x)`"— y que hasta ahora no tenía ni una prueba.
		{"function record, la forma clásica", "registro.js",
			"function record(x) {", "}"},
	}

	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			src := c.abre + "\n" + cuerpoDeDiecinueve() + c.cierra + "\n"

			fns := complejidadLlaves([]byte(src))
			if len(fns) != 1 {
				t.Fatalf("%s: esperaba una función, hubo %d: %+v", c.abre, len(fns), fns)
			}
			// El nombre no se comprueba: `nombreDeFuncion` se queda con el
			// último campo de la cabecera, así que en las asignaciones sale
			// "function". Es cosmético y no es lo que está en juego aquí.
			if fns[0].Linea != 1 || fns[0].Complejidad != 19 {
				t.Errorf("esperaba línea 1 y complejidad 19, hubo %+v", fns[0])
			}

			cfg := repoTemporal(t, map[string]string{c.archivo: src})
			hs := revisarComplejidad(cfg, cambios(c.archivo))
			if len(hs) != 1 {
				t.Fatalf("complejidad 19 con umbral %d: esperaba un aviso, hubo %d: %+v",
					UmbralComplejidadPorDefecto, len(hs), hs)
			}
			if hs[0].Line != 1 {
				t.Errorf("el aviso debe apuntar a la línea de la firma; apunta a la %d", hs[0].Line)
			}
		})
	}
}

// Las demás formas de declarar un tipo que llevan paréntesis por algún sitio.
// El mixin de TypeScript —`class Servicio extends Base(Mixin)`— es el caso
// realista: la llamada al mixin mete paréntesis en la línea de la clase.
func TestOtrasDeclaracionesDeTipoNoSonFunciones(t *testing.T) {
	casos := []struct {
		nombre   string
		src      string
		esperado []funcion
	}{
		{
			nombre: "mixin de TypeScript: la clase no es una función, su método sí",
			src: "export class Servicio extends Base(Mixin)\n" +
				"{\n" +
				"    metodo() { if (a) { } }\n" +
				"}\n",
			esperado: []funcion{{Nombre: "metodo", Linea: 3, Complejidad: 2}},
		},
		{
			// Lleva un método detrás a propósito. Un caso que sólo espera
			// "nada" pasaría igual si el escáner estuviera roto del todo y no
			// devolviera nunca nada; con el método detrás, el caso exige las
			// dos cosas: que el tipo no cuente Y que el escáner siga vivo
			// después, atribuyendo a su línea de verdad.
			nombre: "interfaz genérica de Java",
			src: "public interface Repositorio<T> extends Base<T>\n" +
				"{\n" +
				"    T buscar(int id);\n" +
				"}\n" +
				"\n" +
				"public int contar(int x)\n" +
				"{\n" +
				"    if (x > 0) { return 1; }\n" +
				"    return 0;\n" +
				"}\n",
			esperado: []funcion{{Nombre: "contar", Linea: 6, Complejidad: 2}},
		},
		{
			nombre: "enum",
			src: "public enum Estado\n" +
				"{\n" +
				"    Alta,\n" +
				"    Baja\n" +
				"}\n" +
				"\n" +
				"public int contar(int x)\n" +
				"{\n" +
				"    if (x > 0) { return 1; }\n" +
				"    return 0;\n" +
				"}\n",
			esperado: []funcion{{Nombre: "contar", Linea: 7, Complejidad: 2}},
		},
		{
			nombre: "struct de C# con constructor primario",
			src: "public struct Punto(int x, int y)\n" +
				"{\n" +
				"    public int Cuadrante() { if (x > 0) { return 1; } return 0; }\n" +
				"}\n",
			esperado: []funcion{{Nombre: "Cuadrante", Linea: 3, Complejidad: 2}},
		},
		{
			// `record struct` lleva DOS palabras de tipo seguidas y el nombre
			// detrás de las dos.
			nombre: "readonly record struct de C#",
			src: "public readonly record struct Medida(int Alto, int Ancho)\n" +
				"{\n" +
				"    public int Area() { if (Alto > 0) { return Alto * Ancho; } return 0; }\n" +
				"}\n",
			esperado: []funcion{{Nombre: "Area", Linea: 3, Complejidad: 2}},
		},
		{
			// Las dos sutilezas en la misma línea: una clase con constructor
			// primario —que hay que rechazar— y una restricción `where T :
			// class` detrás de los paréntesis —que no debe contar—. Si la
			// cabecera se cortara mal, este caso se lee como el fantasma.
			nombre: "clase con constructor primario y restricción genérica",
			src: "public class Repo<T>(IDb db) where T : class\n" +
				"{\n" +
				"    public int A(int x) { if (x > 0) { return 1; } return 0; }\n" +
				"}\n",
			esperado: []funcion{{Nombre: "A", Linea: 3, Complejidad: 2}},
		},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) { comprobar(t, c.src, c.esperado) })
	}
}

// `using`, `lock` y `fixed` abren un bloque con una cláusula entre paréntesis,
// igual que `if` o `while`, y se contaban como funciones. Por sí solos salen con
// complejidad 1 y no disparan nada, pero el daño no es el aviso: es que se
// COMEN el bloque. En un Program.cs con instrucciones de nivel superior (C# 9+)
// no hay ningún método envolviendo, así que el `using` se traga lo que venga
// dentro y lo que hubiera después queda mal atribuido.
func TestLasSentenciasConParentesisNoSonFunciones(t *testing.T) {
	casos := []struct {
		nombre   string
		src      string
		esperado []funcion
	}{
		{
			nombre: "using de nivel superior con un método detrás",
			src: "using (var conexion = new SqlConnection(cadena))\n" +
				"{\n" +
				"    if (conexion.Ok) { Console.WriteLine(1); }\n" +
				"}\n" +
				"\n" +
				"public int Calcular(int x)\n" +
				"{\n" +
				"    if (x > 0) { return 1; }\n" +
				"    return 0;\n" +
				"}\n",
			esperado: []funcion{{Nombre: "Calcular", Linea: 6, Complejidad: 2}},
		},
		// Los cuatro que siguen llevan el mismo método detrás que el caso del
		// `using`, y por la misma razón: esperar "nada" a secas se cumpliría
		// también con un escáner que no devolviera nunca nada. Con el método
		// detrás cada caso comprueba las dos mitades —que la sentencia no
		// cuente como función y que no se coma lo que viene después—, que es
		// justo el daño que hacían.
		{
			nombre: "lock",
			src: "lock (candado)\n{\n    if (a) { }\n}\n\n" +
				"public int Calcular(int x)\n{\n    if (x > 0) { return 1; }\n    return 0;\n}\n",
			esperado: []funcion{{Nombre: "Calcular", Linea: 6, Complejidad: 2}},
		},
		{
			nombre: "fixed",
			src: "fixed (byte* p = &datos[0])\n{\n    if (a) { }\n}\n\n" +
				"public int Calcular(int x)\n{\n    if (x > 0) { return 1; }\n    return 0;\n}\n",
			esperado: []funcion{{Nombre: "Calcular", Linea: 6, Complejidad: 2}},
		},
		{
			nombre: "synchronized de Java",
			src: "synchronized (this)\n{\n    if (a) { }\n}\n\n" +
				"public int Calcular(int x)\n{\n    if (x > 0) { return 1; }\n    return 0;\n}\n",
			esperado: []funcion{{Nombre: "Calcular", Linea: 6, Complejidad: 2}},
		},
		{
			nombre: "foreach con un lambda dentro de la condición",
			// Lleva "=>" y por eso se contaba como función: la rama de la
			// flecha se evaluaba antes que la de las sentencias.
			src: "foreach (var x in lista.Where(y => y.Ok))\n{\n    if (x.A) { }\n}\n\n" +
				"public int Calcular(int x)\n{\n    if (x > 0) { return 1; }\n    return 0;\n}\n",
			esperado: []funcion{{Nombre: "Calcular", Linea: 6, Complejidad: 2}},
		},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) { comprobar(t, c.src, c.esperado) })
	}
}

// El reverso, y es un falso NEGATIVO: la exclusión de sentencias comparaba por
// prefijo de texto, así que un método llamado `format` empezaba por "for" y
// desaparecía del análisis. Perder funciones es peor que inventarlas —el aviso
// que no sale nadie lo echa de menos—, y `format`, `ifPresent` o `switchTo` son
// nombres de lo más normal en TS/JS y Java.
func TestUnMetodoQueEmpiezaComoUnaPalabraClaveSeSigueDetectando(t *testing.T) {
	casos := []struct {
		nombre string
		src    string
	}{
		{"format", "format(valor) {\n    if (a) { }\n}\n"},
		{"ifPresent", "ifPresent(valor) {\n    if (a) { }\n}\n"},
		{"whileLoop", "whileLoop(valor) {\n    if (a) { }\n}\n"},
		{"switchTo", "switchTo(valor) {\n    if (a) { }\n}\n"},
		{"catchAll", "catchAll(valor) {\n    if (a) { }\n}\n"},
		{"usingCache", "usingCache(valor) {\n    if (a) { }\n}\n"},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			comprobar(t, c.src, []funcion{{Nombre: c.nombre, Linea: 1, Complejidad: 2}})
		})
	}
}

// El escáner de llaves nació mirando una sola línea: exigía ver la firma y la
// llave de apertura juntas. C# y buena parte de Java se escriben en estilo
// Allman, con la llave en la línea siguiente, así que ningún archivo .cs o
// .java devolvía función alguna y la regla complejidad-excesiva callaba en dos
// de las extensiones que dice cubrir.
func TestComplejidadLlavesEstiloAllman(t *testing.T) {
	casos := []struct {
		nombre   string
		src      string
		esperado []funcion
	}{
		{
			nombre: "allman: la llave abre en la línea siguiente",
			src: "public void Foo()\n" +
				"{\n" +
				"    if (a && b)\n" +
				"    {\n" +
				"        if (c) { }\n" +
				"    }\n" +
				"}\n",
			// 1 (camino base) + if + && + if
			esperado: []funcion{{Nombre: "Foo", Linea: 1, Complejidad: 4}},
		},
		{
			nombre: "K&R: lo que ya se detectaba se sigue detectando igual",
			src: "public void Bar() {\n" +
				"    if (a) { }\n" +
				"}\n",
			esperado: []funcion{{Nombre: "Bar", Linea: 1, Complejidad: 2}},
		},
		{
			// Con un método detrás, por lo mismo que los demás casos
			// negativos: "no detecta nada" se cumpliría también con un escáner
			// que no detectara nunca nada.
			nombre: "una llamada seguida de un bloque no es una función",
			src: "Foo(x);\n" +
				"{\n" +
				"    int y = 0;\n" +
				"}\n" +
				"\n" +
				"public void Bar()\n" +
				"{\n" +
				"    if (a) { }\n" +
				"}\n",
			esperado: []funcion{{Nombre: "Bar", Linea: 6, Complejidad: 2}},
		},
	}

	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			got := complejidadLlaves([]byte(c.src))
			if len(got) != len(c.esperado) {
				t.Fatalf("esperaba %d función(es) %v, hubo %d: %v",
					len(c.esperado), c.esperado, len(got), got)
			}
			for i, q := range c.esperado {
				if got[i] != q {
					t.Errorf("función %d: esperaba %+v, hubo %+v", i, q, got[i])
				}
			}
		})
	}
}
