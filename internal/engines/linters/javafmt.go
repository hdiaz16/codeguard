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

	"codeguard/internal/engines"
	"codeguard/internal/engines/contrato"
	"codeguard/internal/engines/proc"
	"codeguard/internal/finding"
)

// JavaFmt es la compuerta de formato de Java (§7: el formato BLOQUEA — es
// auto-corregible y no tiene ambigüedad, igual que gofmt y dotnet format).
//
// Hasta aquí Java sólo tenía las reglas de la casa (semgrep) y las dependencias
// (trivy): ni formato ni lint. Un .java con la llave donde le vino en gana
// llegaba entero al CI y la discusión sobre dónde va el espacio se pagaba en la
// revisión, que es justo lo que un formateador determinista existe para evitar.
//
// La herramienta es google-java-format, que sólo mira el FUENTE: no compila, no
// necesita classpath ni dependencias resueltas. Eso es lo que la hace apta para
// un pre-commit, donde no hay ni tiempo ni red para un build de Maven.
//
// Comprobar, nunca reescribir: el agente no toca el árbol de trabajo del
// desarrollador. Lo que hace es preguntarle a la herramienta qué archivos
// CAMBIARÍA y, de esos, confirmar uno a uno que la diferencia no sea sólo de
// finales de línea.
type JavaFmt struct {
	// Cache es por ARCHIVO: google-java-format formatea cada archivo por su
	// cuenta, sin mirar el resto del proyecto ni ninguna configuración (no
	// tiene: el estilo de Google no se configura). Mismo contenido = mismo
	// veredicto, siempre. La clave es la versión de la herramienta más el sha
	// del contenido; ver claveJavaFmt.
	Cache engines.Cache
}

func (JavaFmt) Name() string { return "google-java-format" }

func (JavaFmt) Applies(in engines.Input) bool { return len(proyectosJava(in)) > 0 }

// patrónJarGJF localiza el jar instalado. El artefacto publicado se llama
// google-java-format-<version>-all-deps.jar y se instala con ese nombre: la
// versión va dentro del nombre porque entra en la clave de caché (ver
// herramientaJava).
const (
	jarGJFPatron  = "google-java-format-*-all-deps.jar"
	jarGJFPrefijo = "google-java-format-"
	jarGJFSufijo  = "-all-deps.jar"
)

func (e JavaFmt) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	proys := proyectosJava(in)
	if len(proys) == 0 {
		return nil, nil
	}
	// El jar sin instalar sube envuelto en fs.ErrNotExist y el orquestador lo
	// etiqueta "falta: google-java-format". Con java ausente pasa lo mismo por
	// otro camino (exec.ErrNotFound), y por eso el error de exec se envuelve más
	// abajo con %w y no con %v: con %v se pierde el centinela y un motor que
	// simplemente no está instalado se reportaría como avería del análisis,
	// pintando de naranja commits sanos.
	jar, version, err := herramientaJava(jarGJFPatron, jarGJFPrefijo, jarGJFSufijo)
	if err != nil {
		return nil, err
	}
	var out []finding.Finding
	for _, p := range proys {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		fs, err := e.correrProyectoJava(ctx, in.RepoRoot, p, jar, version)
		if err != nil {
			return nil, err
		}
		out = append(out, fs...)
	}
	return out, nil
}

// objetivoJava es un archivo a analizar: la ruta que viaja en el hallazgo
// (relativa al repo), la que recibe la herramienta (relativa al proyecto, que es
// su cwd) y su clave de caché.
type objetivoJava struct {
	rel   string
	enPry string
	clave string
}

// claveJavaFmt compone la clave de caché de un archivo.
//
// Lleva la versión delante del sha porque google-java-format cambia de criterio
// entre versiones menores (reflow de strings largos, orden de modificadores):
// servir el veredicto guardado tras una actualización sería reportar el formato
// de la versión anterior. No lleva nada del proyecto porque no hay nada que
// llevar — esta herramienta no tiene configuración.
func claveJavaFmt(version, sha string) string {
	return "google-java-format:" + version + ":" + sha
}

func (e JavaFmt) correrProyectoJava(ctx context.Context, repoRoot string, p proyectoJava, jar, version string) ([]finding.Finding, error) {
	abs := filepath.Join(repoRoot, filepath.FromSlash(p.dir))

	var pendientes []objetivoJava
	for _, f := range p.archivos {
		o := objetivoJava{rel: f.Path, enPry: enProyecto(p.dir, f.Path)}
		if e.Cache != nil && f.SHA256 != "" {
			o.clave = claveJavaFmt(version, f.SHA256)
		}
		pendientes = append(pendientes, o)
	}

	// ── Aciertos de caché ──
	// La clave está direccionada por CONTENIDO (no lleva la ruta), así que dos
	// archivos idénticos comparten entrada; al reproducir un acierto hay que
	// reescribir la ruta y recalcular el fingerprint para el archivo de ESTA
	// corrida. Mismo mecanismo que eslint y semgrep.
	var findings []finding.Finding
	if e.Cache != nil {
		var claves []string
		for _, o := range pendientes {
			if o.clave != "" {
				claves = append(claves, o.clave)
			}
		}
		aciertos := e.Cache.Leer(claves)
		var quedan []objetivoJava
		for _, o := range pendientes {
			fs, ok := aciertos[o.clave]
			if o.clave == "" || !ok {
				quedan = append(quedan, o)
				continue
			}
			for _, f := range fs {
				if f.File != o.rel {
					f.File = o.rel
					f.ComputeFingerprint()
				}
				findings = append(findings, f)
			}
		}
		pendientes = quedan
	}

	// Un archivo que desapareció entre el diff y el análisis no se le pasa a la
	// herramienta: google-java-format sale con 1 y escribe "could not read file"
	// por él, y con eso perderíamos el lote entero. Tampoco hay nada que
	// formatear en un archivo que ya no está.
	var vivos []objetivoJava
	for _, o := range pendientes {
		if st, err := os.Stat(filepath.Join(repoRoot, filepath.FromSlash(o.rel))); err == nil && !st.IsDir() {
			vivos = append(vivos, o)
		}
	}
	if len(vivos) == 0 {
		return findings, nil
	}

	rutas := make([]string, len(vivos))
	for i, o := range vivos {
		rutas[i] = o.enPry
	}
	var sospechosos []string
	for _, lote := range lotesDeRutas(rutas, maxLineaComandosJava) {
		fs, err := jfmtDesformateados(ctx, repoRoot, abs, p.dir, jar, lote)
		if err != nil {
			return nil, err
		}
		sospechosos = append(sospechosos, fs...)
	}

	// ── Segunda pasada: descartar los que sólo difieren en los finales de línea ──
	nuevos := []finding.Finding{}
	for _, rel := range sospechosos {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		soloEOL, err := jfmtSoloFinalesDeLinea(ctx, repoRoot, abs, p.dir, jar, rel)
		if err != nil {
			return nil, err
		}
		if soloEOL {
			continue
		}
		nuevos = append(nuevos, jfmtHallazgo(jar, p.dir, rel))
	}

	if e.Cache != nil {
		e.Cache.Guardar(cacheDeArchivosJava(nuevos, vivos))
	}
	return append(findings, nuevos...), nil
}

// maxLineaComandosJava acota los argumentos de una invocación. Lo usan los dos
// motores de Java.
//
// Es alto —el número de semgrep, no el de eslint— porque aquí se ejecuta
// java.exe, un binario de verdad: lo limita CreateProcess (32767). Los 6000 de
// eslint.go salen de que los binarios de node son shims .cmd y Windows los pasa
// por cmd.exe, que corta en 8191. Por eso PMD se invoca con `java -cp` y no con
// su pmd.bat: el lanzador batch heredaría ese límite.
const maxLineaComandosJava = 30000

// cacheDeArchivosJava atribuye los hallazgos nuevos a su archivo y devuelve
// clave → hallazgos. Los archivos analizados sin hallazgos entran con lista
// vacía: "analizado y limpio" es el resultado que más veces se reutiliza, y en
// un motor de formato es la inmensa mayoría.
func cacheDeArchivosJava(fs []finding.Finding, analizados []objetivoJava) map[string][]finding.Finding {
	clavePorRel := make(map[string]string, len(analizados))
	out := make(map[string][]finding.Finding, len(analizados))
	for _, o := range analizados {
		if o.clave == "" {
			continue
		}
		clavePorRel[o.rel] = o.clave
		out[o.clave] = []finding.Finding{}
	}
	for _, f := range fs {
		if clave, ok := clavePorRel[f.File]; ok {
			out[clave] = append(out[clave], f)
		}
	}
	return out
}

// jfmtDesformateados pregunta qué archivos del lote cambiaría la herramienta.
// Devuelve rutas relativas al REPO.
//
// --dry-run imprime en stdout la ruta de cada archivo que cambiaría y
// --set-exit-if-changed hace que salga con 1 cuando hay alguno. Medido con
// 1.36.1: las rutas van a stdout y los diagnósticos por archivo (parseo, archivo
// ilegible) a stderr, limpiamente separados, y el código 1 cubre los dos casos.
// Por eso el código de salida NO decide nada por sí solo: decide el stream.
// Lo que la herramienta deje en stderr son errores de UN archivo: no parsea, o
// no se pudo leer. NO se convierten en hallazgo a propósito. Un .java que no
// parsea lo reporta javalint con su processingError y un mensaje mucho mejor
// (línea, columna y qué esperaba el parser); duplicarlo aquí sería el mismo
// problema con dos nombres, igual que dotnet-build calla los NU1901 que ya
// cuenta dotnet-vuln. Y el formato no es el problema de ese archivo.
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
	cmd.Env = proc.Entorno()
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
	}
	f.ComputeFingerprint()
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
