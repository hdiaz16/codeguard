package pipeline_test

// EXPERIMENTO del bug #8 (plan W1, protocolo firmado por el consejo): la
// bitácora registró líneas DESACTUALIZADAS servidas por caché tras un cambio
// de solo-comentario (~55 ms uniformes en todos los motores), con el mecanismo
// del re-mapeo ausente confirmado en código y el DISPARADOR del acierto sin
// explicar. La regla de la casa manda experimento instrumentado ANTES de
// arreglar: cada dimensión que pase queda como regresión congelada; la que
// falle ES el disparador, con datos.
//
// Dimensión (a): cambio de solo-comentario sobre un archivo cacheado.
// Dimensión (b): dos archivos de contenido IDÉNTICO — el caché por contenido
// comparte la entrada y la re-hidratación reescribe ruta y huella; la línea
// viaja congelada dentro (semgrep.go:115-121, el mecanismo confirmado).

import (
	"database/sql"

	"path/filepath"
	"strings"
	"testing"
)

// lineasDelRun lee archivo+regla → línea de los hallazgos REGISTRADOS del run
// más reciente: lo que el desarrollador ve, no lo que un motor devolvió en
// memoria.
func lineasDelRun(t *testing.T, datos string) map[string]int {
	t.Helper()
	db := abrirBase(t, filepath.Join(datos, "codeguard", "codeguard.db"))
	defer db.Close()
	fila := db.QueryRow(`SELECT id FROM runs ORDER BY started_at DESC, id DESC LIMIT 1`)
	var run string
	if err := fila.Scan(&run); err != nil {
		t.Fatalf("sin run del que leer líneas: %v", err)
	}
	filas, err := db.Query(`SELECT file_path, rule_key, line_start FROM findings WHERE run_id = ?`, run)
	if err != nil {
		t.Fatal(err)
	}
	defer filas.Close()
	out := map[string]int{}
	for filas.Next() {
		var archivo, regla string
		var linea sql.NullInt64
		if err := filas.Scan(&archivo, &regla, &linea); err != nil {
			t.Fatal(err)
		}
		out[archivo+"|"+regla] = int(linea.Int64)
	}
	return out
}

func lineaDe(t *testing.T, lineas map[string]int, archivo, regla string) int {
	t.Helper()
	l, ok := lineas[archivo+"|"+regla]
	if !ok {
		var claves []string
		for k := range lineas {
			claves = append(claves, k)
		}
		t.Fatalf("no hay hallazgo %s en %s; había: %s", regla, archivo, strings.Join(claves, ", "))
	}
	return l
}

// Dimensión (a): tres líneas de comentario encima desplazan la violación; la
// línea reportada tiene que seguirla. El control del medio (corrida sin
// cambios) confirma que el caché SÍ está sirviendo — sin él, «la línea se
// movió bien» también sería el resultado de un caché que nunca acertó.
func TestBug8LaLineaSigueAlCodigoTrasComentario(t *testing.T) {
	bin, repo, datos := prepararCache(t)

	base := lineaDe(t, lineasDelRun(t, mideRun(t, bin, repo, datos)),
		"app/inseguro.py", "python-subprocess-shell")

	entradas := entradasDeCache(t, datos)
	if entradas == 0 {
		t.Fatal("la primera corrida no cacheó nada: el experimento no mide un caché")
	}

	// Control: misma corrida otra vez — el acierto debe servir la MISMA línea.
	control := lineaDe(t, lineasDelRun(t, mideRun(t, bin, repo, datos)),
		"app/inseguro.py", "python-subprocess-shell")
	if control != base {
		t.Fatalf("sin cambios, la línea cambió de %d a %d: el control no controla", base, control)
	}

	// El desplazamiento: tres comentarios encima, y la línea debe seguirlo.
	escribir(t, repo, "app/inseguro.py",
		"# uno\n# dos\n# tres\n"+elDefecto)
	git(t, repo, "add", "-A")
	despues := lineaDe(t, lineasDelRun(t, mideRun(t, bin, repo, datos)),
		"app/inseguro.py", "python-subprocess-shell")
	if despues != base+3 {
		t.Fatalf("el bug #8 en vivo: la violación vive en la línea %d y se reportó la %d "+
			"(antes del comentario era la %d)", base+3, despues, base)
	}
}

// Dimensión (b): gemelos de contenido idéntico comparten entrada de caché
// (direccionado por contenido). Al desplazar la violación SOLO en el gemelo A,
// B acierta en el caché con la entrada que nació de A o de B — y su línea
// tiene que ser la de SU contenido, no la del momento en que se cacheó.
func TestBug8GemelosDeMismoContenidoNoSeContagianLaLinea(t *testing.T) {
	bin, repo, datos := prepararCache(t)
	escribir(t, repo, "app/gemelo_a.py", elDefecto)
	escribir(t, repo, "app/gemelo_b.py", elDefecto)
	git(t, repo, "add", "-A")

	lineas := lineasDelRun(t, mideRun(t, bin, repo, datos))
	a, b := lineaDe(t, lineas, "app/gemelo_a.py", "python-subprocess-shell"),
		lineaDe(t, lineas, "app/gemelo_b.py", "python-subprocess-shell")
	if a != b {
		t.Fatalf("contenido idéntico con líneas distintas de entrada (%d vs %d): el fixture no vale", a, b)
	}

	// A se desplaza; B no se toca. B debe acertar en caché y conservar SU línea.
	escribir(t, repo, "app/gemelo_a.py", "# uno\n# dos\n# tres\n"+elDefecto)
	git(t, repo, "add", "-A")
	lineas = lineasDelRun(t, mideRun(t, bin, repo, datos))
	nuevaA := lineaDe(t, lineas, "app/gemelo_a.py", "python-subprocess-shell")
	nuevaB := lineaDe(t, lineas, "app/gemelo_b.py", "python-subprocess-shell")
	if nuevaA != a+3 {
		t.Errorf("el gemelo editado reporta la línea %d y la violación vive en la %d", nuevaA, a+3)
	}
	if nuevaB != b {
		t.Errorf("el gemelo INTACTO cambió de línea (%d → %d) sin cambiar de contenido: "+
			"la entrada compartida contagió la línea del otro", b, nuevaB)
	}
}

// mideRun corre el gancho y devuelve el directorio de datos, para encadenar
// con lineasDelRun. Existe para que cada aserción diga qué corrida mide.
func mideRun(t *testing.T, bin, repo, datos string) string {
	t.Helper()
	salida, _ := correrCon(t, bin, repo, datos, "hook", "pre-commit")
	exigirQueLoAnaliceElBinarioDePrueba(t, salida)
	if strings.Contains(salida, "diff_too_large") {
		t.Fatalf("corrida degradada a solo-secretos: no mide el caché\n%s", salida)
	}
	return datos
}
