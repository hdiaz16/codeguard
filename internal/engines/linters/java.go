package linters

import (
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"codeguard/internal/engines"
	"codeguard/internal/gitdiff"
	"codeguard/internal/instalacion"
	"codeguard/internal/textutil"
)

// Piezas que comparten los dos motores de Java: javafmt (google-java-format) y
// javalint (PMD).
//
// Viven juntas a propósito. Si el descubrimiento de proyectos divergiera entre
// los dos, un mismo archivo podría acabar atribuido a backend/ para el formato y
// a la raíz para el lint, y el informe mostraría DOS rutas distintas para el
// mismo código — que es exactamente lo que rompe la supresión por fingerprint
// (§9: la clave lleva la ruta normalizada dentro).

// manifiestosJava son los archivos que declaran "aquí empieza un proyecto Java".
//
// Se buscan subiendo desde cada .java tocado, como tsc.go con el tsconfig.json:
// en el monorepo corporativo típico el pom.xml vive en backend/ y la raíz no
// tiene ninguno. Mirar sólo la raíz dejaría la compuerta enrolada sin correr.
//
// settings.gradle NO está en la lista aunque marque la raíz de un build Gradle:
// lo que se busca es el MÓDULO más cercano al archivo, y en un build multi
// proyecto el settings.gradle de la raíz se tragaría los módulos de abajo.
var manifiestosJava = []string{"pom.xml", "build.gradle", "build.gradle.kts"}

// proyectoJava es un grupo de archivos tocados que cuelgan del mismo manifiesto.
type proyectoJava struct {
	dir      string // relativo a la raíz, "." si es la propia raíz
	archivos []gitdiff.ChangedFile
}

// proyectosJava agrupa los .java vivos por su manifiesto más cercano.
//
// Un repo sin ningún manifiesto NO queda fuera: cae a la raíz. Es la diferencia
// deliberada con eslint.go, que sí exige configuración —allí las reglas son del
// repo y sin config no hay reglas que aplicar—; aquí las dos herramientas traen
// las suyas y funcionan sobre cualquier .java suelto.
func proyectosJava(in engines.Input) []proyectoJava {
	idx := map[string]*proyectoJava{}
	for _, f := range filesWithExt(in, ".java") {
		if esJavaGenerado(f.Path) {
			continue
		}
		dir := proyectoJavaDe(in.RepoRoot, f.Path)
		p := idx[dir]
		if p == nil {
			p = &proyectoJava{dir: dir}
			idx[dir] = p
		}
		p.archivos = append(p.archivos, f)
	}
	out := make([]proyectoJava, 0, len(idx))
	for _, p := range idx {
		out = append(out, *p)
	}
	// Orden estable: el informe no puede cambiar de forma entre dos corridas
	// idénticas por el recorrido de un mapa.
	sort.Slice(out, func(i, j int) bool { return out[i].dir < out[j].dir })
	return out
}

// proyectoJavaDe sube desde el archivo hasta el primer directorio con
// manifiesto, sin salirse de la raíz. Sin manifiesto en ningún nivel devuelve
// "." (la raíz del repo).
func proyectoJavaDe(repoRoot, rel string) string {
	dir := path.Dir(rel)
	for {
		if hayAlguno(filepath.Join(repoRoot, filepath.FromSlash(dir)), manifiestosJava) {
			return dir
		}
		if dir == "." || dir == "/" {
			return "."
		}
		dir = path.Dir(dir)
	}
}

// esJavaGenerado descarta lo que vive en la salida de compilación: target/ es de
// Maven, build/ de Gradle, out/ de IntelliJ. Los .java que aparecen ahí los
// escribió un generador de código (JAXB, protobuf, Lombok delombok), y bloquear
// un commit porque un generador no formatea como google-java-format convertiría
// al agente en un obstáculo por algo que el dev no puede arreglar.
//
// La comprobación se detiene en el primer segmento "src": a partir de ahí todo
// es fuente y un PAQUETE llamado build o target es Java perfectamente legal
// (com.ejemplo.build.Constructor). Sin esa parada, el filtro se comería código
// de verdad, que es peor que analizar de más.
func esJavaGenerado(rel string) bool {
	for _, seg := range strings.Split(rel, "/") {
		bajo := strings.ToLower(seg)
		if bajo == "src" {
			return false
		}
		switch bajo {
		case "target", "build", "out", ".gradle":
			return true
		}
	}
	return false
}

// dirMotores es donde el instalador deja los motores descargables.
//
// gitleaks y trivy no la necesitan: son .exe y el instalador mete este
// directorio en el PATH, así que les basta exec.LookPath. Un .jar no se
// resuelve por PATH — hay que saber dónde está.
//
// La resuelve internal/instalacion y no esta función porque cmd/codeguard
// necesita la misma ruta, internal/ no puede importar cmd/, y la copia que eso
// obligaba a mantener tenía el mismo agujero de ejecución de código. Devuelve
// "" cuando no hay directorio resoluble; ver herramientaJava.
func dirMotores() string { return instalacion.DirMotores() }

// herramientaJava localiza una herramienta instalada cuyo NOMBRE lleva la
// versión dentro, y devuelve su ruta y esa versión.
//
// El nombre versionado no es cosmética: la versión entra en la clave de caché.
// google-java-format 1.36 y 1.37 pueden formatear el mismo archivo distinto, y
// PMD estrena y retira reglas en cada versión menor; servir el resultado
// guardado tras una actualización sería reportar los hallazgos de la herramienta
// anterior — el mismo fallo que eslint.go evita metiendo la huella de la config
// en la clave. Con el nombre versionado la versión se lee de la ruta, sin pagar
// un proceso extra por informe sólo para preguntarla.
//
// Si no hay ninguna, el error envuelve fs.ErrNotExist para que el orquestador lo
// etiquete "falta:" y no como análisis degradado (pipeline.isMissingBinary):
// una herramienta sin instalar es asunto de configuración, no una avería.
func herramientaJava(patron, prefijo, sufijo string) (string, string, error) {
	dir := dirMotores()
	// Sin directorio de motores NO se busca, y hay que decirlo aquí aunque
	// dirMotores ya devuelva "": filepath.Join("", patron) no da una ruta vacía,
	// deja el patrón SUELTO, y Glob lo resolvería contra el directorio de
	// trabajo — que durante un commit es el repo que se analiza. Sin esta
	// guarda, al repo hostil le bastaría con plantar el .jar en su raíz en vez
	// de en CodeGuard\engines: el mismo agujero movido un directorio.
	if dir == "" {
		return "", "", fmt.Errorf("no hay directorio de motores donde buscar %s: %w", patron, fs.ErrNotExist)
	}
	rutas, err := filepath.Glob(filepath.Join(dir, patron))
	if err != nil || len(rutas) == 0 {
		return "", "", fmt.Errorf("no hay ningún %s en %s: %w", patron, dir, fs.ErrNotExist)
	}
	mejor, mejorVer := "", ""
	for _, r := range rutas {
		v := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(r), prefijo), sufijo)
		if mejor == "" || masNuevaJava(v, mejorVer) {
			mejor, mejorVer = r, v
		}
	}
	return mejor, mejorVer, nil
}

// masNuevaJava compara dos versiones por sus segmentos NUMÉRICOS.
//
// Comparar los textos daría "1.9.0" > "1.36.1", y durante una actualización
// —cuando conviven dos versiones en el directorio de motores— eso elegiría la
// vieja. Los segmentos que no son números se comparan como texto, que es lo
// razonable para un "7.26.0-rc1".
func masNuevaJava(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		sa, sb := "", ""
		if i < len(pa) {
			sa = pa[i]
		}
		if i < len(pb) {
			sb = pb[i]
		}
		na, erra := strconv.Atoi(sa)
		nb, errb := strconv.Atoi(sb)
		if erra == nil && errb == nil {
			if na != nb {
				return na > nb
			}
			continue
		}
		if sa != sb {
			return sa > sb
		}
	}
	return false
}

// rutaRepoJava normaliza a "relativa al repo con separador /" la ruta que
// reportó la herramienta.
//
// Las dos escupen la ruta TAL COMO se la dieron pero con la barra invertida de
// Windows (medido: se les pasa src/main/... y contestan src\main\...), así que
// el caso normal es el relativo. La rama absoluta es defensiva y prueba las dos
// formas de la raíz —la cruda y la canónica— porque en Windows el directorio de
// trabajo puede venir con alias 8.3 (HECTOR~1) y la herramienta canonizarlo: es
// el mismo cuidado que dnbRelativizar, y sin él la ruta se quedaría absoluta y
// el hallazgo no casaría con ningún archivo del diff.
//
// Las barras se normalizan a mano y no con filepath para que el parseo dé el
// mismo resultado en cualquier plataforma donde se compile el repo: los payloads
// de los tests son capturas reales de Windows.
func rutaRepoJava(repoRoot, dir, p string) string {
	if p == "" {
		return ""
	}
	limpia := strings.ReplaceAll(p, `\`, "/")
	// esAbsolutaJS nació con eslint.go, pero lo que mira es la FORMA de la ruta
	// (C:/… o /…), no el lenguaje: reutilizarla evita dos copias que puedan
	// divergir.
	if esAbsolutaJS(limpia) {
		for _, base := range basesRepo(repoRoot) {
			b := strings.TrimSuffix(filepath.ToSlash(base), "/")
			if b != "" && len(limpia) > len(b)+1 && limpia[len(b)] == '/' &&
				strings.EqualFold(limpia[:len(b)], b) {
				return limpia[len(b)+1:]
			}
		}
		return limpia // fuera del repo: mejor la ruta cruda que una mentira
	}
	if dir != "." && dir != "" {
		return path.Join(dir, limpia)
	}
	return limpia
}

// basesRepo devuelve la raíz del repo tal cual y, si difiere, su forma canónica.
func basesRepo(repoRoot string) []string {
	bases := []string{repoRoot}
	if canon, err := filepath.EvalSymlinks(repoRoot); err == nil && canon != repoRoot {
		bases = append(bases, canon)
	}
	return bases
}

// jRecortar acota un texto de diagnóstico para que quepa en una línea del
// informe sin arrastrar el stack trace entero que Java adjunta a todo.
func jRecortar(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return textutil.TruncarRunas(s, n) + "…"
}

// jErrorDeJVM detecta que la máquina virtual ni llegó a ejecutar la herramienta.
//
// Existe porque los dos motores comparten una trampa medida: `java -jar` sale
// con 1 tanto cuando google-java-format encontró diferencias (resultado normal)
// como cuando el lanzador no pudo abrir el jar. Lo que los separa es el texto:
// el lanzador de Java empieza SIEMPRE sus errores con "Error: " a principio de
// línea ("Error: Unable to access jarfile", "Error: Could not find or load main
// class", "Error: Invalid or corrupt jarfile"), y los diagnósticos por archivo
// de las herramientas nunca lo hacen (google-java-format escribe
// "Roto.java:4:17: error: …", PMD escribe "[main] ERROR net.sourceforge…").
//
// Confundirlos sería anunciar "0 problemas de formato" con la herramienta sin
// arrancar, que es la mentira que este proyecto persigue.
func jErrorDeJVM(stderr []byte) string {
	for _, l := range strings.Split(string(stderr), "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "Error: ") || strings.HasPrefix(l, "Exception in thread ") {
			return l
		}
	}
	return ""
}
