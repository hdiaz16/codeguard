package linters

import (
	"context"
	"os"
	"path/filepath"

	"codeguard/internal/engines"
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
