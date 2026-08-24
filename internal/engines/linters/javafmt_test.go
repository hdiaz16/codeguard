package linters

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"codeguard/internal/engines"
	"codeguard/internal/finding"
)

// Todas las capturas de este archivo son salida REAL de google-java-format
// 1.36.1 sobre el JDK 21.0.12 en Windows, no payloads inventados. Se dejan
// literales —barra invertida incluida— porque cada rareza del formato es una
// que el parseo tiene que sobrevivir en producción.

// `java -jar google-java-format-1.36.1-all-deps.jar --dry-run
// --set-exit-if-changed src/main/java/com/ejemplo/MalFormateado.java
// src/main/java/com/ejemplo/ConProblemas.java
// src/main/java/com/ejemplo/Limpio.java` desde backend/, código de salida 1.
//
// Dos cosas que sólo se ven midiendo: se le pasan las rutas con barra normal y
// las devuelve con la INVERTIDA, y sólo nombra los que cambiarían — los dos que
// ya están formateados no aparecen.
const salidaGJFDryRun = "src\\main\\java\\com\\ejemplo\\MalFormateado.java\n"

// Mismo comando con un archivo que no parsea en el lote. Esto va a STDERR
// mientras la ruta del mal formateado sigue yendo a stdout: el código de salida
// (1) es el mismo en los dos casos, así que lo que decide es el stream.
const salidaGJFErrorDeParseo = `Roto.java:4:17: error: illegal start of type
  public int x( {
                ^
Roto.java:5:2: error: reached end of file while parsing
}
 ^
`

// Contenido tal cual lo deja google-java-format: es la salida literal de
// `java -jar ... Limpio.java`, byte a byte igual al archivo en disco.
const fuenteJavaLimpio = `package com.ejemplo;

/** Clase sin nada que reportar: formato de google-java-format y sin reglas de PMD tocadas. */
public final class Limpio {

  private final String nombre;

  public Limpio(String nombre) {
    this.nombre = nombre;
  }

  public String saluda() {
    return "hola " + nombre;
  }
}
`

// El mismo archivo con el formato destrozado a mano: espacios de más, sangrías
// inventadas y la llave donde no toca.
const fuenteJavaMalFormateado = `package com.ejemplo;

public class MalFormateado {
    public   int suma( int a,int b ) {
            return a+b;
  }
      public String saluda(String nombre){
        return "hola "+nombre;
    }
}
`

// ── parseo de la salida ─────────────────────────────────────────────────────

func TestJavaFmtRutasCambiadasDesdeLaCapturaReal(t *testing.T) {
	rutas := jfmtRutasCambiadas(`C:\repos\demo`, "backend", []byte(salidaGJFDryRun))
	if len(rutas) != 1 {
		t.Fatalf("esperaba 1 ruta, obtuve %d: %v", len(rutas), rutas)
	}
	if rutas[0] != "backend/src/main/java/com/ejemplo/MalFormateado.java" {
		t.Errorf("ruta = %q; debe venir relativa al REPO y con separador /, con el "+
			"directorio del proyecto delante", rutas[0])
	}
}

func TestJavaFmtRutasCambiadasEnLaRaizNoPrefijaNada(t *testing.T) {
	rutas := jfmtRutasCambiadas(`C:\repos\demo`, ".", []byte(salidaGJFDryRun))
	if len(rutas) != 1 || rutas[0] != "src/main/java/com/ejemplo/MalFormateado.java" {
		t.Fatalf("ruta = %v", rutas)
	}
}

func TestJavaFmtSalidaVaciaNoInventaHallazgos(t *testing.T) {
	if rutas := jfmtRutasCambiadas(`C:\repos\demo`, ".", []byte("\n  \n")); len(rutas) != 0 {
		t.Fatalf("una salida en blanco no puede producir rutas: %v", rutas)
	}
}

// El error de parseo viaja por STDERR y el lanzador de Java escribe los suyos
// con "Error: " al principio de línea. Separarlos es lo que evita degradar el
// motor entero por un archivo con un paréntesis de más, y lo contrario: anunciar
// "0 problemas de formato" con la JVM sin arrancar.
func TestJavaFmtElErrorDeParseoNoEsUnFalloDeLaJVM(t *testing.T) {
	if jvm := jErrorDeJVM([]byte(salidaGJFErrorDeParseo)); jvm != "" {
		t.Errorf("un archivo que no parsea no puede degradar el motor, se leyó como %q", jvm)
	}
}

// ── el caso CRLF ────────────────────────────────────────────────────────────

// En Windows autocrlf deja CRLF en disco. Los finales de línea son asunto de
// git (.gitattributes), no del formato: bloquear un commit por eso convertiría
// al agente en un obstáculo, y un obstáculo se desinstala. Es la misma decisión
// que ya tomó gofmt.go.
func TestJavaFmtNoBloqueaPorFinalesDeLinea(t *testing.T) {
	lf := []byte(fuenteJavaLimpio)
	crlf := []byte(strings.ReplaceAll(fuenteJavaLimpio, "\n", "\r\n"))
	// Y el caso mixto, que es el que de verdad hace fallar la comprobación byte
	// a byte: un archivo con mayoría LF donde un editor de Windows dejó una
	// línea en CRLF. La herramienta unificaría, o sea "cambiaría", sin que haya
	// nada mal formateado.
	mixto := []byte(strings.Replace(fuenteJavaLimpio, "public final class Limpio {\n",
		"public final class Limpio {\r\n", 1))

	if string(jfmtNormalizar(lf)) != string(jfmtNormalizar(crlf)) {
		t.Error("el mismo archivo en LF y en CRLF debe comparar igual")
	}
	if string(jfmtNormalizar(lf)) != string(jfmtNormalizar(mixto)) {
		t.Error("los finales de línea mezclados tampoco pueden marcar diferencia")
	}
	// Y sin salto final: que el archivo termine o no en \n lo arregla el editor.
	sinSalto := []byte(strings.TrimRight(fuenteJavaLimpio, "\n"))
	if string(jfmtNormalizar(lf)) != string(jfmtNormalizar(sinSalto)) {
		t.Error("el salto final no es formato")
	}
	// Lo que SÍ es una diferencia real tiene que seguir siéndolo, o el motor no
	// serviría para nada.
	if string(jfmtNormalizar(lf)) == string(jfmtNormalizar([]byte(fuenteJavaMalFormateado))) {
		t.Error("un archivo realmente mal formateado no puede compararse igual")
	}
}

// ── el hallazgo ─────────────────────────────────────────────────────────────

func TestJavaFmtHallazgoBloqueaYDaElComandoConcreto(t *testing.T) {
	jar := `C:\Users\dev\AppData\Local\CodeGuard\engines\google-java-format-1.36.1-all-deps.jar`
	f := jfmtHallazgo(jar, "backend", "backend/src/main/java/com/ejemplo/MalFormateado.java")

	// §7: el formato bloquea — es auto-corregible y no tiene ambigüedad.
	if f.Severity != finding.Error || !f.Blocking {
		t.Errorf("severity=%q blocking=%v; el formato es compuerta bloqueante", f.Severity, f.Blocking)
	}
	if f.Pillar != finding.Quality || !f.Verified || f.Source != finding.Deterministic {
		t.Errorf("pilar/verified/source mal puestos: %+v", f)
	}
	if f.Engine != "google-java-format" || f.RuleKey != "google-java-format" {
		t.Errorf("engine=%q rule=%q; el hallazgo debe nombrar la herramienta real", f.Engine, f.RuleKey)
	}
	if f.File != "backend/src/main/java/com/ejemplo/MalFormateado.java" || f.Line != 1 {
		t.Errorf("file=%q line=%d; el archivo entero es lo que está sin formatear", f.File, f.Line)
	}
	if f.LineContent == "" {
		// La identidad la asigna finding.AsignarHuellas (huellas v2); sin el
		// insumo, la huella saldría sobre vacío y no habría supresión posible.
		t.Error("sin LineContent no hay huella, y sin huella no hay supresión posible (§9)")
	}
	// El consejo tiene que poder pegarse en la terminal: jar real, bandera de
	// escritura y ruta relativa al proyecto, más desde dónde ejecutarlo.
	for _, quiero := range []string{jar, " -i ", "src/main/java/com/ejemplo/MalFormateado.java", "desde backend/"} {
		if !strings.Contains(f.FixHint, quiero) {
			t.Errorf("el FixHint debe contener %q, dice %q", quiero, f.FixHint)
		}
	}
}

func TestJavaFmtHallazgoEnLaRaizNoDiceDesdeDonde(t *testing.T) {
	f := jfmtHallazgo("gjf.jar", ".", "src/A.java")
	if strings.Contains(f.FixHint, "desde") {
		t.Errorf("en la raíz sobra el \"desde\": %q", f.FixHint)
	}
}

// ── Applies ─────────────────────────────────────────────────────────────────

func TestJavaFmtNoAplicaSinArchivosJava(t *testing.T) {
	raiz := t.TempDir()
	e := JavaFmt{}
	if e.Applies(engines.Input{RepoRoot: raiz, Files: archivosJava("src/App.kt", "README.md")}) {
		t.Error("sin .java tocados el motor no debe aplicar")
	}
	if !e.Applies(engines.Input{RepoRoot: raiz, Files: archivosJava("src/A.java")}) {
		t.Error("con un .java tocado el motor debe aplicar")
	}
	// Y un .java que es salida de compilación no cuenta como .java tocado.
	if e.Applies(engines.Input{RepoRoot: raiz, Files: archivosJava("target/generated-sources/A.java")}) {
		t.Error("la salida de compilación no debe activar el motor")
	}
}

// Sin herramienta instalada el motor no puede inventarse un "todo limpio": tiene
// que devolver error, y ese error tiene que ser reconocible como motor ausente.
func TestJavaFmtSinHerramientaNoDiceQueEstaLimpio(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	raiz := t.TempDir()
	escribir(t, raiz, "src/A.java", fuenteJavaLimpio)

	fs, err := JavaFmt{}.Run(context.Background(), engines.Input{RepoRoot: raiz, Files: archivosJava("src/A.java")})
	if err == nil {
		t.Fatalf("sin google-java-format instalado debe fallar, devolvió %d hallazgos", len(fs))
	}
	if len(fs) != 0 {
		t.Errorf("una degradación no puede traer hallazgos, trajo %d", len(fs))
	}
}

// ── integración con el binario real ─────────────────────────────────────────

// javaYJarInstalados salta la prueba cuando falta el JDK o la herramienta. No es
// una excusa: es que sin ellas la prueba no puede afirmar nada, y una prueba que
// pasa sin comprobar es peor que no tenerla.
func javaYJarInstalados(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("java"); err != nil {
		t.Skip("sin java en el PATH de esta máquina")
	}
	jar, _, err := herramientaJava(jarGJFPatron, jarGJFPrefijo, jarGJFSufijo)
	if err != nil {
		t.Skipf("google-java-format no está instalado en %s", dirMotores())
	}
	return jar
}

// proyectoJavaDeJuguete deja un repo con pom.xml en backend/ y los tres
// archivos: uno mal formateado, uno con problemas de PMD y uno limpio.
func proyectoJavaDeJuguete(t *testing.T) string {
	t.Helper()
	raiz := t.TempDir()
	escribir(t, raiz, "backend/pom.xml", "<project/>")
	escribir(t, raiz, "backend/src/main/java/com/ejemplo/Limpio.java", fuenteJavaLimpio)
	escribir(t, raiz, "backend/src/main/java/com/ejemplo/MalFormateado.java", fuenteJavaMalFormateado)
	escribir(t, raiz, "backend/src/main/java/com/ejemplo/ConProblemas.java", fuenteJavaConProblemas)
	return raiz
}

func TestIntegracionJavaFmtSenalaSoloElMalFormateado(t *testing.T) {
	if testing.Short() {
		t.Skip("arranca una JVM de verdad: fuera del modo corto")
	}
	javaYJarInstalados(t)
	raiz := proyectoJavaDeJuguete(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	fs, err := JavaFmt{}.Run(ctx, engines.Input{RepoRoot: raiz, Files: archivosJava(
		"backend/src/main/java/com/ejemplo/Limpio.java",
		"backend/src/main/java/com/ejemplo/MalFormateado.java",
		"backend/src/main/java/com/ejemplo/ConProblemas.java",
	)})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("esperaba exactamente 1 hallazgo (el mal formateado), obtuve %d: %+v", len(fs), fs)
	}
	if fs[0].File != "backend/src/main/java/com/ejemplo/MalFormateado.java" {
		t.Errorf("archivo señalado = %q", fs[0].File)
	}
	if !fs[0].Blocking || fs[0].Severity != finding.Error {
		t.Errorf("el formato debe bloquear: %+v", fs[0])
	}
}

// La prueba que de verdad importa en Windows: el mismo archivo limpio, escrito
// con CRLF como lo deja autocrlf al clonar. No puede bloquear un commit.
func TestIntegracionJavaFmtNoBloqueaPorCRLF(t *testing.T) {
	if testing.Short() {
		t.Skip("arranca una JVM de verdad: fuera del modo corto")
	}
	javaYJarInstalados(t)
	raiz := t.TempDir()
	escribir(t, raiz, "pom.xml", "<project/>")
	escribir(t, raiz, "src/main/java/com/ejemplo/Limpio.java",
		strings.ReplaceAll(fuenteJavaLimpio, "\n", "\r\n"))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	fs, err := JavaFmt{}.Run(ctx, engines.Input{RepoRoot: raiz,
		Files: archivosJava("src/main/java/com/ejemplo/Limpio.java")})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(fs) != 0 {
		t.Fatalf("un archivo bien formateado con CRLF no puede bloquear el commit: %+v", fs)
	}
}

// Y el archivo mal formateado CON CRLF sí tiene que seguir bloqueando: la
// tolerancia a los finales de línea no puede tragarse el formato de verdad.
func TestIntegracionJavaFmtElMalFormateadoConCRLFSigueBloqueando(t *testing.T) {
	if testing.Short() {
		t.Skip("arranca una JVM de verdad: fuera del modo corto")
	}
	javaYJarInstalados(t)
	raiz := t.TempDir()
	escribir(t, raiz, "src/main/java/com/ejemplo/MalFormateado.java",
		strings.ReplaceAll(fuenteJavaMalFormateado, "\n", "\r\n"))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	fs, err := JavaFmt{}.Run(ctx, engines.Input{RepoRoot: raiz,
		Files: archivosJava("src/main/java/com/ejemplo/MalFormateado.java")})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("esperaba 1 hallazgo, obtuve %d: %+v", len(fs), fs)
	}
}

// Un archivo que se borró entre el diff y el análisis no puede tumbar el motor:
// google-java-format sale con 1 y escribe "could not read file" por él.
func TestIntegracionJavaFmtSobreviveAUnArchivoQueYaNoEsta(t *testing.T) {
	if testing.Short() {
		t.Skip("arranca una JVM de verdad: fuera del modo corto")
	}
	javaYJarInstalados(t)
	raiz := t.TempDir()
	escribir(t, raiz, "src/main/java/com/ejemplo/Limpio.java", fuenteJavaLimpio)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	fs, err := JavaFmt{}.Run(ctx, engines.Input{RepoRoot: raiz, Files: archivosJava(
		"src/main/java/com/ejemplo/Limpio.java",
		"src/main/java/com/ejemplo/Fantasma.java",
	)})
	if err != nil {
		t.Fatalf("un archivo desaparecido no debe tumbar el motor: %v", err)
	}
	if len(fs) != 0 {
		t.Fatalf("no había nada mal formateado: %+v", fs)
	}
}

// El caché por contenido tiene que servir el mismo veredicto sin volver a
// arrancar la JVM, y con la ruta del archivo de ESTA corrida.
func TestIntegracionJavaFmtUsaElCache(t *testing.T) {
	if testing.Short() {
		t.Skip("arranca una JVM de verdad: fuera del modo corto")
	}
	javaYJarInstalados(t)
	raiz := t.TempDir()
	escribir(t, raiz, "src/A.java", fuenteJavaMalFormateado)
	escribir(t, raiz, "src/B.java", fuenteJavaMalFormateado)

	cache := &cacheDeMemoria{datos: map[string][]finding.Finding{}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	e := JavaFmt{Cache: cache}
	// Los dos archivos tienen el MISMO contenido, así que comparten entrada de
	// caché: la ruta del hallazgo tiene que reescribirse para cada uno.
	files := archivosJava("src/A.java")
	files[0].SHA256 = "mismo-contenido"
	fs, err := e.Run(ctx, engines.Input{RepoRoot: raiz, Files: files})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("esperaba 1 hallazgo, obtuve %+v", fs)
	}
	llamadas := cache.lecturas

	otros := archivosJava("src/B.java")
	otros[0].SHA256 = "mismo-contenido"
	fs2, err := e.Run(ctx, engines.Input{RepoRoot: raiz, Files: otros})
	if err != nil {
		t.Fatalf("Run con caché caliente: %v", err)
	}
	if len(fs2) != 1 {
		t.Fatalf("el acierto de caché debe reproducir el hallazgo: %+v", fs2)
	}
	if fs2[0].File != "src/B.java" {
		t.Errorf("el hallazgo servido del caché debe llevar la ruta de ESTA corrida, lleva %q", fs2[0].File)
	}
	if fs2[0].Fingerprint == fs[0].Fingerprint {
		t.Error("al cambiar la ruta hay que recalcular el fingerprint (§9 lo lleva dentro)")
	}
	if cache.lecturas <= llamadas {
		t.Error("la segunda corrida debía consultar el caché")
	}
}

// cacheDeMemoria es un engines.Cache de mentira para las pruebas: guarda en un
// mapa y cuenta las lecturas.
type cacheDeMemoria struct {
	datos    map[string][]finding.Finding
	lecturas int
}

func (c *cacheDeMemoria) Leer(claves []string) map[string][]finding.Finding {
	c.lecturas++
	out := map[string][]finding.Finding{}
	for _, k := range claves {
		if v, ok := c.datos[k]; ok {
			out[k] = v
		}
	}
	return out
}

func (c *cacheDeMemoria) Guardar(entradas []engines.Cacheable) {
	// El fake respeta la vigencia igual que la implementación real.
	for _, e := range entradas {
		if e.Vigente != nil && e.Vigente() {
			c.datos[e.Clave] = e.Findings
		}
	}
}
