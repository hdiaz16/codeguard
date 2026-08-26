package linters

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"codeguard/internal/engines/contrato"
	"codeguard/internal/engines/proc"
	"codeguard/internal/finding"
)

func jfmtDesformateados(ctx context.Context, repoRoot, absProyecto, dirProyecto, jar string, rutas []string) ([]string, error) {
	args := append([]string{"-jar", jar, "--dry-run", "--set-exit-if-changed"}, rutas...)
	stdout, err := jfmtCorrer(ctx, absProyecto, dirProyecto, jar, args)
	if err != nil {
		return nil, err
	}
	cambiadas := jfmtRutasCambiadas(repoRoot, dirProyecto, stdout)

	// La respuesta tiene que ser un SUBCONJUNTO de lo que preguntamos.
	//
	// --dry-run contesta con las rutas del lote que cambiarían, así que una línea
	// que no estaba en el lote no es una ruta: es que lo que corrió no era
	// google-java-format. Sin esta comprobación, cualquier texto en stdout se
	// tomaba por una lista de archivos, la segunda pasada intentaba leerlos, no
	// existían, y la rama de "desapareció entre las dos pasadas" lo daba por
	// bueno. Resultado: CERO hallazgos, o sea "revisé y está bien" sobre un
	// archivo que nadie miró.
	//
	// Lo destapó el test de contrato de internal/daemon poniendo un `java`
	// impostor que escribe en stdout y sale con 1. No hace falta un impostor para
	// que ocurra: basta un envoltorio corporativo delante del java real, o un
	// mensaje de la JVM en otro idioma. Es la misma clase que tuvo govet y que
	// tuvo tsc — el silencio de la avería confundido con el del éxito.
	pedidas := make(map[string]bool, len(rutas))
	for _, r := range rutas {
		pedidas[rutaRepoJava(repoRoot, dirProyecto, r)] = true
	}
	for _, c := range cambiadas {
		if !pedidas[c] {
			return nil, fmt.Errorf("google-java-format contestó con %q, que no estaba en el "+
				"lote que se le pasó: lo que corrió no es la herramienta esperada (¿un java "+
				"distinto, o un envoltorio delante?). Salida: %s",
				c, jRecortar(colapsar(string(stdout)), 200))
		}
	}
	return cambiadas, nil
}

// jfmtRutasCambiadas traduce el stdout de --dry-run (una ruta por línea, con la
// barra invertida de Windows y relativa al cwd) a rutas relativas al repo.
func jfmtRutasCambiadas(repoRoot, dirProyecto string, stdout []byte) []string {
	var out []string
	for _, l := range strings.Split(string(stdout), "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		out = append(out, rutaRepoJava(repoRoot, dirProyecto, l))
	}
	return out
}

// jfmtSoloFinalesDeLinea comprueba si la única diferencia con lo que produciría
// la herramienta son los finales de línea.
//
// Es la lección que gofmt.go dejó escrita: en Windows autocrlf deja CRLF en
// disco, los finales de línea son asunto de git (.gitattributes) y no del
// formato, y bloquear un commit por eso convertiría al agente en un obstáculo —
// y un obstáculo se desinstala.
//
// Medido con 1.36.1: google-java-format CONSERVA el final de línea dominante del
// archivo, así que un archivo CRLF bien formateado ni siquiera aparece en la
// primera pasada. Esta segunda existe para el caso mixto —un archivo con
// mayoría LF que un editor de Windows dejó con alguna línea en CRLF, donde la
// herramienta unifica y por tanto "cambia"— y para no depender de que esa
// detección siga comportándose igual en la versión siguiente: si un día deja de
// conservarlos, aquí no se bloquea a nadie por ello.
//
// Cuesta un proceso más POR ARCHIVO SEÑALADO, no por archivo analizado: en un
// repo formateado la primera pasada no señala nada y esto no llega a correr.
func jfmtSoloFinalesDeLinea(ctx context.Context, repoRoot, absProyecto, dirProyecto, jar, rel string) (bool, error) {
	raw, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(rel)))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// Desapareció entre las dos pasadas. Sin contenido con el que comparar no
			// se puede afirmar nada, y afirmar "está mal formateado" de un archivo que
			// ya no existe es peor que callar.
			return true, nil
		}
		return false, fmt.Errorf("jfmtSoloFinalesDeLinea leyendo %s: %w", rel, err)
	}
	stdout, err := jfmtCorrer(ctx, absProyecto, dirProyecto, jar, []string{"-jar", jar, enProyecto(dirProyecto, rel)})
	if err != nil {
		return false, err
	}
	return bytes.Equal(jfmtNormalizar(stdout), jfmtNormalizar(raw)), nil
}

// jfmtNormalizar deja el contenido comparable: CRLF a LF y sin los saltos del
// final. Lo segundo es lo que hace gofmt.go por el mismo motivo — que el archivo
// termine o no en salto de línea lo arregla el editor, no es formato.
func jfmtNormalizar(b []byte) []byte {
	return bytes.TrimRight(bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")), "\n")
}

// jfmtCorrer ejecuta google-java-format y separa los tres desenlaces que
// importan: no arrancó, arrancó y falló de verdad, o arrancó y tiene algo que
// decir.
func jfmtCorrer(ctx context.Context, absProyecto, dirProyecto, jar string, args []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "java", args...)
	cmd.Dir = absProyecto
	cmd.Env = proc.EntornoDeMotor("google-java-format", proc.PerfilJava)
	salida, runErr := proc.Correr(ctx, cmd, proc.MaxSalida)

	if salida.Recortada {
		return nil, fmt.Errorf("google-java-format devolvió más de %d MB en %s: la salida llega a medias y no se puede comparar", proc.MaxSalida>>20, dirProyecto)
	}
	var exitErr *exec.ExitError
	if runErr != nil && !errors.As(runErr, &exitErr) {
		// No arrancó: java ausente, permisos, plazo agotado. %w conserva el
		// centinela (exec.ErrNotFound, context.DeadlineExceeded) para que el
		// orquestador diga "falta: google-java-format" o "tardó de más" en vez de
		// un ":error" genérico que manda al dev a buscar una avería que no existe.
		return nil, fmt.Errorf("google-java-format no corrió en %s: %w", dirProyecto, runErr)
	}
	codigo := 0
	if exitErr != nil {
		codigo = exitErr.ExitCode()
	}
	// La distinción que importa: salir con 1 es la forma NORMAL de decir "esto
	// cambiaría" (con --set-exit-if-changed) y también la que usa el lanzador de
	// Java cuando no pudo abrir el jar. Lo que los separa es el texto de stderr,
	// no el código — ver jErrorDeJVM. Cualquier otro código es un fallo real.
	if jvm := jErrorDeJVM(salida.Stderr); jvm != "" {
		return nil, fmt.Errorf("google-java-format no llegó a ejecutarse en %s: %s", dirProyecto, jvm)
	}
	if codigo > 1 {
		return nil, fmt.Errorf("google-java-format falló en %s (código %d): %s",
			dirProyecto, codigo, jRecortar(colapsar(string(salida.Combinada())), 400))
	}
	// Salió con 1 y no escribió NADA en stdout: entonces no formateó nada, y no
	// se puede afirmar que el archivo esté bien.
	//
	// Con --set-exit-if-changed, el 1 significa "esto cambiaría" — y para decir
	// eso la herramienta tiene que haber emitido el archivo ya formateado, que es
	// justo lo que se compara. Salir con 1 y stdout vacío no es ninguno de los
	// desenlaces previstos: es que no llegó a hacer su trabajo.
	//
	// Lo destapó el test de contrato de internal/daemon sustituyendo `java` por un
	// impostor que escribe en stdout y sale con 1: jErrorDeJVM sólo reconoce los
	// mensajes de la JVM que empiezan por "Error: " en STDERR, así que el impostor
	// pasaba por "esto cambiaría", no había nada que comparar, y el motor devolvía
	// CERO hallazgos — o sea, "revisé y está bien" sobre un archivo que nadie
	// miró. Es la misma clase de fallo que tuvo govet y que tuvo tsc: el silencio
	// de una avería confundido con el silencio del éxito.
	//
	// No hace falta que el impostor sea artificial para que ocurra: basta un java
	// que escriba su queja en stdout, un mensaje de la JVM en otro idioma que no
	// empiece por "Error: ", o un envoltorio corporativo delante del java real.
	//
	// Pero esa forma —código 1, stdout vacío— la comparten DOS desenlaces, y
	// achacárselos los dos al motor manda al dev a reinstalar algo que está
	// sano. El otro es que UN .java del lote no parsea: la herramienta escribe
	// el diagnóstico en stderr con la ruta tal como se la pasamos
	// ("ruta:línea:columna: error: …") y no lista nada en stdout.
	//
	// Se sigue devolviendo error —esta capa NO puede decir "limpio"—, y eso es
	// deliberado: en un lote de diez archivos con uno roto, stdout vacío no
	// significa "los otros nueve están bien formateados", significa que no se
	// llegó a saber. Tratarlo como limpio sería el "no se miró parece se miró"
	// de siempre. Lo que cambia es QUÉ se dice: se nombra el archivo que no
	// parsea en vez de acusar a la herramienta, porque el dev tiene que ir a
	// arreglar su código, no su instalación. El detalle con línea y columna lo
	// da javalint.
	//
	// La heurística está medida en la dirección segura: si una versión futura
	// cambia el formato del diagnóstico y deja de casar, cae en el mensaje de
	// avería de abajo — degrada igual, sólo con peor texto.
	if codigo == 1 && len(salida.Stdout) == 0 && jfmtArchivoQueNoParsea(salida.Stderr, args) != "" {
		return nil, fmt.Errorf("google-java-format no pudo parsear %s en %s, así que el "+
			"formato del lote se queda sin juzgar: arregla la sintaxis y vuelve a intentar "+
			"(javalint lo señala con línea y columna). Salida: %s",
			jfmtArchivoQueNoParsea(salida.Stderr, args), dirProyecto,
			jRecortar(colapsar(string(salida.Stderr)), 200))
	}
	if codigo == 1 && len(salida.Stdout) == 0 {
		return nil, fmt.Errorf("google-java-format salió con 1 en %s y no devolvió el archivo "+
			"formateado: no llegó a hacer su trabajo (¿un java que no es el esperado, o un "+
			"error de la JVM que no reconocimos?). Salida: %s",
			dirProyecto, jRecortar(colapsar(string(salida.Combinada())), 200))
	}

	// Y EL SIMÉTRICO, que es el que quedaba: SALIR CON 0 Y CALLAR.
	//
	// La comprobación de arriba cubre el 1; con 0 y stdout vacío el motor daba el
	// lote por bien formateado. En la primera pasada (--dry-run
	// --set-exit-if-changed) eso ES el resultado legítimo de un lote impecable, y
	// ahí está el problema: es idéntico a lo que devuelve un `java` que no ejecutó
	// el jar. En la segunda pasada ni siquiera es legítimo —se pide el archivo
	// formateado por stdout y un .java no formatea a la nada—, pero las dos
	// llegaban aquí igual de mudas.
	//
	// A diferencia de gitleaks o `go vet -json`, aquí no hay ninguna huella que
	// aprovechar: google-java-format limpio no escribe NADA, y ése es su contrato.
	// Así que toca preguntarle quién es. Cuesta un arranque de JVM, sólo en el lote
	// que sale limpio, y una vez por proceso (contrato.Identidad lo memoriza).
	//
	// Y esta es justo la avería que hay en la máquina donde se escribió esto: el
	// jar de la 1.36.1 está compilado para JDK 21 (class file 65) y aquí hay JDK 17
	// (61), así que `java -jar` muere con UnsupportedClassVersionError y la
	// compuerta de formato de Java está apagada. Con la JVM contestando ese error,
	// preguntar por la versión falla y el motor lo dice, que es lo que hay que hacer.
	if codigo == 0 && len(salida.Stdout) == 0 {
		if err := contrato.Identidad(ctx, contrato.Prueba{
			Motor:  "google-java-format",
			Bin:    "java",
			Args:   []string{"-jar", jar, "--version"},
			Dir:    absProyecto,
			Espera: contestaAlgo,
			Pista: "Comprueba que `java -jar \"" + jar + "\" --version` funcione: si la JVM " +
				"es más vieja que el jar, muere con UnsupportedClassVersionError y la compuerta " +
				"de formato de Java queda apagada.",
		}); err != nil {
			return nil, err
		}
	}
	return salida.Stdout, nil
}

// jfmtArchivoQueNoParsea devuelve la ruta del archivo del lote que stderr señala
// como imparseable, o "" si stderr no habla de ninguno.
//
// Es la evidencia que separa "un archivo tuyo no compila" de "la herramienta no
// corrió": google-java-format emite sus diagnósticos con la ruta TAL COMO se la
// pasamos por línea de comandos, así que basta buscar cada argumento que acabe
// en .java dentro de stderr, sin normalizar nada. Los args que terminan en .java
// son exactamente las rutas pedidas (en la primera pasada van tras los flags; en
// la segunda es el único archivo).
//
// NO está verificado contra un google-java-format real: esta máquina no tiene
// java y los tests que lo necesitan se saltan. Por eso el orden de las guardas
// importa — si esto no casa, el llamador cae en el mensaje de avería, que es el
// lado seguro.
var reJfmtError = regexp.MustCompile(`(?m)^([^\r\n:]+\.java)(?::\d+)?(?::\d+)?:\s*error:`)

func jfmtArchivoQueNoParsea(stderr []byte, args []string) string {
	matches := reJfmtError.FindAllSubmatch(stderr, -1)
	if len(matches) == 0 {
		return ""
	}
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		candidato := string(m[1])
		for _, a := range args {
			if strings.HasSuffix(a, ".java") && (a == candidato || strings.EqualFold(filepath.Clean(a), filepath.Clean(candidato))) {
				return a
			}
		}
	}
	return ""
}

// contestaAlgo acepta cualquier respuesta con contenido, y la tolerancia es
// deliberada y está medida al revés de lo habitual: en esta máquina el jar NO
// ARRANCA (JDK 17 contra un jar de 21), así que no pude ver qué texto exacto
// imprime `--version` un google-java-format que funciona. Exigir una palabra que
// no he podido medir sería apostar la capa de formato de Java de todos los repos
// limpios a mi memoria.
//
// No se pierde casi nada: la regla fuerte de este motor es la de arriba —salir
// con 1 sin decir qué cambiaría es avería— y esa sí está medida. Lo que esta
// comprobación añade es cazar al que no sabe ni contestar, que es exactamente el
// caso del jar que no arranca.
var contestaAlgo = regexp.MustCompile(`\S`)

const porQueJavaFmt = "El formato inconsistente genera diffs ruidosos y discusiones sin valor. " +
	"google-java-format es determinista: no hay dos formas de tener razón."

func jfmtHallazgo(jar, dirProyecto, rel string) finding.Finding {
	// El comando lleva la ruta REAL del jar instalado para que se pueda pegar en
	// la terminal tal cual. Un consejo que no se puede ejecutar enseña al dev a
	// dejar de leer los consejos.
	orden := `java -jar "` + jar + `" -i ` + enProyecto(dirProyecto, rel)
	f := finding.Finding{
		Engine:   "google-java-format",
		RuleKey:  "google-java-format",
		Pillar:   finding.Quality,
		Severity: finding.Error,
		Blocking: true,
		File:     rel,
		// El archivo ENTERO es lo que está mal formateado, no una línea: la 1 es
		// la única posición honesta (mismo criterio que gofmt.go y que el
		// diagnóstico "format" de biome).
		Line:        1,
		Message:     "Archivo sin formatear (google-java-format)",
		Why:         porQueJavaFmt,
		FixHint:     "Auto-corregible: " + comandoJava(dirProyecto, orden) + ".",
		Verified:    true,
		Source:      finding.Deterministic,
		LineContent: rel,
		Identidad:   finding.IdentidadSemantica,
	}
	return f
}

// comandoJava arma la orden que el dev debe teclear. Cuando el proyecto no está
// en la raíz hay que decir desde dónde: la ruta que se le pasa a la herramienta
// es relativa al proyecto, y tecleada desde la raíz del monorepo no existe.
func comandoJava(dir, orden string) string {
	if dir == "." || dir == "" {
		return "`" + orden + "`"
	}
	return "`" + orden + "` desde " + dir + "/"
}
