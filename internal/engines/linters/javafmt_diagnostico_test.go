package linters

import "testing"

// Un .java que no parsea NO es una avería del formateador.
//
// google-java-format sale con 1 y sin nada en stdout en dos situaciones muy
// distintas: porque un archivo del lote no parsea, o porque lo que corrió no era
// la herramienta (un impostor, un envoltorio corporativo, un mensaje de la JVM
// que no reconocemos). Las dos degradan la capa —stdout vacío no permite decir
// que los demás archivos del lote estén bien formateados—, pero el mensaje tiene
// que mandar al dev al sitio correcto: a su sintaxis o a su instalación.
//
// Lo que las separa es que stderr nombre a un archivo del lote. La tabla fija esa
// frontera; el orden de las guardas en jfmtCorrer hace que un stderr que no case
// caiga del lado de la avería, que es el lado seguro.
func TestSeDistingueElArchivoQueNoParseaDeLaAveriaDelMotor(t *testing.T) {
	args := []string{"-jar", "gjf.jar", "--dry-run", "--set-exit-if-changed",
		`src\main\java\Pedido.java`, `src\main\java\Cliente.java`}

	casos := []struct {
		nombre string
		stderr string
		espera string
		porque string
	}{
		{
			"el diagnóstico de un archivo del lote",
			`src\main\java\Pedido.java:7:14: error: class, interface, enum, or record expected`,
			`src\main\java\Pedido.java`,
			"es el caso del hallazgo: hoy se acusaba al formateador de estar averiado",
		},
		{
			"stderr vacío (impostor mudo)",
			"", "",
			"sin evidencia de la herramienta, la única lectura honesta es que no corrió",
		},
		{
			"ruido de la JVM que no nombra ningún archivo",
			"Picked up JAVA_TOOL_OPTIONS: -Dfile.encoding=UTF-8\nError: no se pudo abrir el jar",
			"",
			"un envoltorio corporativo o un error de la JVM siguen siendo avería",
		},
		{
			"nombra el jar pero ningún .java",
			"Error: Unable to access jarfile gjf.jar", "",
			"el filtro por sufijo .java evita colgarle el fallo a un archivo del lote",
		},
		{
			"nombra un .java que NO estaba en el lote",
			`otro\Ajeno.java:3:1: error: reached end of file while parsing`,
			"",
			"si la herramienta habla de algo que no le pedimos, no es la herramienta esperada",
		},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			if got := jfmtArchivoQueNoParsea([]byte(c.stderr), args); got != c.espera {
				t.Errorf("salió %q y se esperaba %q — %s", got, c.espera, c.porque)
			}
		})
	}
}

// La segunda pasada le pasa UN archivo y sin --dry-run, así que la frontera tiene
// que funcionar igual con esa forma de argumentos.
func TestLaFronteraFuncionaTambienEnLaSegundaPasada(t *testing.T) {
	args := []string{"-jar", "gjf.jar", `src\main\java\Pedido.java`}
	stderr := `src\main\java\Pedido.java:1:1: error: illegal character`
	if got := jfmtArchivoQueNoParsea([]byte(stderr), args); got != `src\main\java\Pedido.java` {
		t.Errorf("no reconoció el archivo en la segunda pasada: %q", got)
	}
}
