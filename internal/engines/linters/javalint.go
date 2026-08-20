package linters

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"codeguard/internal/engines"
	"codeguard/internal/engines/proc"
	"codeguard/internal/finding"
)

// JavaLint es la compuerta de calidad de Java: el equivalente de govet y
// staticcheck para el otro lado del producto.
//
// La herramienta es PMD, y la elección es empírica, no de gusto. SpotBugs —el
// otro candidato serio— analiza BYTECODE: exige un proyecto compilado, o sea un
// `mvn compile` con red y minutos por delante, y eso no cabe en el camino de un
// commit. PMD analiza el FUENTE: construye el AST de Java de cada archivo y
// evalúa las reglas sobre él. No necesita .class, ni classpath, ni dependencias
// resueltas.
//
// El conjunto de reglas es rulesets/java/quickstart.xml, el que PMD publica
// como "las reglas que probablemente apliquen en cualquier proyecto" (124 reglas
// en 7.26.0). Es una decisión distinta a la de eslint.go, que corre la config
// DEL REPO: allí el repo tenía una y el CI la aplica: aquí casi ningún repo Java
// tiene PMD cableado, así que no hay decisión del equipo que respetar, y elegir
// el conjunto conservador del propio PMD es lo más parecido a no imponer nada.
// Un repo que sí tenga su propio ruleset necesitaría configuración, y hoy no la
// hay: queda dicho como límite conocido, no como descuido.
type JavaLint struct {
	// Cache es por ARCHIVO, no por proyecto, y esa es la diferencia con tsc y
	// dotnet-build. Los dos compilan el proyecto ENTERO, así que su unidad de
	// resultado es el proyecto y su clave tiene que resumir todos los fuentes.
	// PMD no: sin --aux-classpath cada archivo se parsea y se evalúa por su
	// cuenta, sin resolver tipos de otros archivos, así que los mismos bytes dan
	// las mismas violaciones vivan donde vivan. La clave por contenido hace que
	// tocar 1 archivo de 200 cueste 1 archivo, y que dos archivos idénticos
	// compartan entrada.
	Cache engines.Cache
}

func (JavaLint) Name() string { return "pmd" }

func (JavaLint) Applies(in engines.Input) bool { return len(proyectosJava(in)) > 0 }

const (
	// El directorio se llama pmd-bin-<version> tal como viene dentro del zip
	// publicado; la versión sale de ahí y entra en la clave de caché, porque PMD
	// estrena y retira reglas en cada versión menor.
	pmdHomePatron  = "pmd-bin-*"
	pmdHomePrefijo = "pmd-bin-"
	pmdHomeSufijo  = ""

	// pmdRuleset es la ruta DENTRO del jar pmd-java (no un archivo del disco):
	// PMD la resuelve por classpath, así que no hay nada que instalar aparte ni
	// que se pueda quedar desincronizado con la versión de la herramienta.
	pmdRuleset = "rulesets/java/quickstart.xml"

	// pmdClasePrincipal es lo que invoca el propio lanzador pmd.bat del zip.
	//
	// Se ejecuta java directamente en vez de pmd.bat por dos motivos medidos.
	// Uno: pmd.bat es un script batch y Windows lo pasa por cmd.exe, que corta la
	// línea de comandos en 8191 caracteres — la avería que ya costó un motor en
	// eslint.go ("The command line is too long"). Dos, y más grave: sin java en
	// el PATH, pmd.bat imprime "No java executable found in PATH" y sale con 2,
	// o sea un fallo NORMAL desde el punto de vista de Go; el centinela
	// exec.ErrNotFound no aparece por ningún lado y el orquestador reportaría
	// "pmd:error" en vez de "falta: pmd". Invocando java.exe, la ausencia llega
	// como el error de exec que el pipeline sabe leer.
	pmdClasePrincipal = "net.sourceforge.pmd.cli.PmdCli"
)

// Códigos de salida de PMD 7.26.0, medidos uno a uno (no leídos de la
// documentación) porque de ellos depende no anunciar "limpio" sin haber mirado:
//
//	0  analizó y no encontró violaciones
//	1  error de ejecución — y aquí está la trampa: con un archivo inexistente
//	   PMD escribe un JSON PERFECTAMENTE VÁLIDO con "files": [] y sale con 1.
//	   Tomar eso por "limpio" es exactamente la mentira de la que este repo
//	   aprendió con semgrep ("0 bloqueantes · COMPLETADO" sin haber escaneado).
//	2  error de uso (faltó -d/--file-list): tampoco hubo análisis
//	4  encontró violaciones — resultado normal, JSON completo
//	5  hubo errores recuperables (algún archivo no parseó); el JSON trae las
//	   violaciones de los DEMÁS archivos y el detalle en processingErrors
//
// O sea: sólo 0, 4 y 5 significan "PMD miró". El 4 y el 5 se combinan a favor
// del 5 (medido con un archivo roto y otro con violaciones: salió 5 y el JSON
// traía las 6 violaciones del bueno).
const (
	pmdSinViolaciones     = 0
	pmdConViolaciones     = 4
	pmdErroresRecuperados = 5
)

func (e JavaLint) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	proys := proyectosJava(in)
	if len(proys) == 0 {
		return nil, nil
	}
	// Sin PMD instalado el error envuelve fs.ErrNotExist y el orquestador lo
	// etiqueta "falta: pmd" (configuración) en vez de degradar el análisis.
	home, version, err := herramientaJava(pmdHomePatron, pmdHomePrefijo, pmdHomeSufijo)
	if err != nil {
		return nil, err
	}
	var out []finding.Finding
	for _, p := range proys {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		hallazgos, err := e.correrProyectoPMD(ctx, in.RepoRoot, p, home, version)
		if err != nil {
			// La cancelación y la falta de la herramienta son del motor ENTERO,
			// no de este proyecto: ahí abortar sigue siendo lo correcto, porque
			// el orquestador se apoya en esos centinelas (ctx.Err() y el
			// fs.ErrNotExist que se traduce a "falta: pmd").
			if ctx.Err() != nil || errors.Is(err, fs.ErrNotExist) || errors.Is(err, exec.ErrNotFound) {
				return nil, err
			}
			// Un fallo acotado a ESTE proyecto no puede tirar los hallazgos de
			// los demás ni los ya acumulados: es el mismo criterio que unas
			// líneas más abajo se aplica archivo por archivo con
			// ProcessingErrors. Queda constancia bloqueante de que el proyecto
			// no se revisó, y se sigue con el resto.
			out = append(out, falloProyectoPMD(p.dir, err))
			continue
		}
		out = append(out, hallazgos...)
	}
	return out, nil
}

// claveJavaLint compone la clave de caché de un archivo: herramienta, versión,
// conjunto de reglas y contenido.
//
// La versión y el ruleset van dentro porque son lo que decide QUÉ se busca:
// actualizar PMD o cambiar de conjunto cambia los hallazgos sin tocar una línea
// de código, y servir la entrada guardada sería reportar las reglas de ayer. Es
// la misma razón por la que la clave de eslint lleva la huella de su config.
func claveJavaLint(version, sha string) string {
	return "pmd:" + version + ":" + pmdRuleset + ":" + sha
}

func (e JavaLint) correrProyectoPMD(ctx context.Context, repoRoot string, p proyectoJava, home, version string) ([]finding.Finding, error) {
	abs := filepath.Join(repoRoot, filepath.FromSlash(p.dir))

	var pendientes []objetivoJava
	for _, f := range p.archivos {
		o := objetivoJava{rel: f.Path, enPry: enProyecto(p.dir, f.Path)}
		if e.Cache != nil && f.SHA256 != "" {
			o.clave = claveJavaLint(version, f.SHA256)
		}
		pendientes = append(pendientes, o)
	}

	// ── Aciertos de caché ──
	// Direccionada por contenido: al reproducir un acierto hay que reescribir la
	// ruta y recalcular el fingerprint para el archivo de esta corrida.
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

	// Un archivo que desapareció entre el diff y el análisis hay que quitarlo
	// ANTES de invocar: PMD sale con 1 por él ("No such file X") y ese código es
	// fallo de ejecución, así que se perdería el lote entero.
	var vivos []objetivoJava
	for _, o := range pendientes {
		st, err := os.Stat(filepath.Join(repoRoot, filepath.FromSlash(o.rel)))
		switch {
		case err == nil && !st.IsDir():
			vivos = append(vivos, o)
		case err == nil, errors.Is(err, fs.ErrNotExist):
			// Directorio, o desapareció de verdad entre el diff y el análisis:
			// se quita, como siempre.
		default:
			// El archivo está en el diff pero no se puede consultar (permisos,
			// disco, red). Quitarlo callando sería perder cobertura sin avisar
			// —la enfermedad de siempre—, y pasárselo a PMD mataría el lote
			// entero con un "código 1" que no diría la causa real. Se falla
			// nombrando el archivo: el error es información, no silencio.
			return nil, fmt.Errorf("no se pudo consultar %s antes de analizarlo: %w", o.rel, err)
		}
	}
	if len(vivos) == 0 {
		return findings, nil
	}

	rutas := make([]string, len(vivos))
	for i, o := range vivos {
		rutas[i] = o.enPry
	}
	nuevos := []finding.Finding{}
	for _, lote := range lotesDeRutas(rutas, maxLineaComandosJava) {
		fs, err := correrPMD(ctx, repoRoot, abs, p.dir, home, lote)
		if err != nil {
			return nil, err
		}
		nuevos = append(nuevos, fs...)
	}

	if e.Cache != nil {
		e.Cache.Guardar(cacheDeArchivosJava(nuevos, vivos))
	}
	return append(findings, nuevos...), nil
}

func correrPMD(ctx context.Context, repoRoot, absProyecto, dirProyecto, home string, rutas []string) ([]finding.Finding, error) {
	// El classpath es lib/* con el asterisco LITERAL: lo expande la propia JVM,
	// no el shell (aquí no hay shell). Es lo mismo que hace pmd.bat.
	args := []string{
		"-cp", filepath.Join(home, "lib", "*"), pmdClasePrincipal,
		"check", "-f", "json", "-R", pmdRuleset,
		// --no-progress: sin esto PMD avisa en stderr de que la barra de progreso
		// choca con el reporte por stdout. --no-cache: PMD trae su propio caché
		// incremental y lo pide por stderr; el caché de resultados es el nuestro
		// (§9, por contenido), y tener dos capas de caché sobre el mismo trabajo
		// sólo añade un archivo de estado que puede quedar rancio.
		"--no-progress", "--no-cache",
	}
	for _, r := range rutas {
		args = append(args, "-d", r)
	}

	cmd := exec.CommandContext(ctx, "java", args...)
	cmd.Dir = absProyecto
	cmd.Env = proc.Entorno()
	salida, runErr := proc.Correr(ctx, cmd, proc.MaxSalida)

	if salida.Recortada {
		return nil, fmt.Errorf("pmd devolvió más de %d MB en %s: el JSON llega a medias y no se puede parsear", proc.MaxSalida>>20, dirProyecto)
	}
	var exitErr *exec.ExitError
	if runErr != nil && !errors.As(runErr, &exitErr) {
		// Cancelación y plazo agotado NO son «no arrancó»: el motor está sano,
		// la corrida se interrumpió. Reportarlos como «falta: pmd» mandaría a
		// reinstalar lo que funciona — el consejo equivocado en el panel. La
		// capa sigue degradada (PMD no corrió); lo que cambia es el porqué.
		switch {
		case errors.Is(runErr, context.Canceled):
			return nil, fmt.Errorf("pmd cancelado en %s (la operación se abortó; no es un fallo del motor): %w", dirProyecto, runErr)
		case errors.Is(runErr, context.DeadlineExceeded):
			return nil, fmt.Errorf("pmd no terminó a tiempo en %s (está lento, no roto: antivirus, disco de red o un lote enorme): %w", dirProyecto, runErr)
		}
		// No arrancó: java ausente, permisos. %w conserva el
		// centinela para que el orquestador diga "falta: pmd" y no "pmd:error".
		return nil, fmt.Errorf("pmd no corrió en %s: %w", dirProyecto, runErr)
	}
	codigo := 0
	if exitErr != nil {
		codigo = exitErr.ExitCode()
	}
	if jvm := jErrorDeJVM(salida.Stderr); jvm != "" {
		return nil, fmt.Errorf("pmd no llegó a ejecutarse en %s: %s", dirProyecto, jvm)
	}
	switch codigo {
	case pmdSinViolaciones, pmdConViolaciones, pmdErroresRecuperados:
	default:
		// 1 y 2 son los códigos con los que PMD dice "no analicé". Con el 1 el
		// JSON puede venir completo y vacío, así que confiar en el JSON en vez de
		// en el código sería anunciar un proyecto limpio que nadie miró.
		return nil, fmt.Errorf("pmd falló en %s (código %d): %s", dirProyecto, codigo,
			jRecortar(colapsar(string(salida.Combinada())), 400))
	}
	out := bytes.TrimSpace(salida.Stdout)
	if len(out) == 0 {
		return nil, fmt.Errorf("pmd no dejó salida analizable en %s (código %d): %s", dirProyecto, codigo,
			jRecortar(colapsar(string(salida.Stderr)), 400))
	}
	return hallazgosPMD(repoRoot, dirProyecto, out)
}

// ── la salida JSON de PMD ────────────────────────────────────────────────────

type pmdReporte struct {
	Files []struct {
		Filename   string         `json:"filename"`
		Violations []pmdViolacion `json:"violations"`
	} `json:"files"`
	// ProcessingErrors son los archivos que PMD NO pudo analizar (no parsean, no
	// se pudieron leer). Salen con código 5 y el resto del informe es válido.
	ProcessingErrors []struct {
		Filename string `json:"filename"`
		Message  string `json:"message"`
	} `json:"processingErrors"`
	// ConfigurationErrors son problemas de las REGLAS que le pasamos, no del
	// código del usuario.
	ConfigurationErrors []struct {
		Rule    string `json:"rule"`
		Message string `json:"message"`
	} `json:"configurationErrors"`
}

type pmdViolacion struct {
	BeginLine int    `json:"beginline"`
	EndLine   int    `json:"endline"`
	Rule      string `json:"rule"`
	RuleSet   string `json:"ruleset"`
	// Priority es 1 (la más alta) a 5. PMD la fija por regla en su catálogo.
	Priority        int    `json:"priority"`
	Description     string `json:"description"`
	ExternalInfoURL string `json:"externalInfoUrl"`
}

const porQuePMD = "Es análisis del AST de Java —PMD parsea el archivo y evalúa la regla sobre el árbol—, " +
	"no un parecido textual: lo que señala está en la estructura del código, no en cómo se escribió."

func hallazgosPMD(repoRoot, dirProyecto string, raw []byte) ([]finding.Finding, error) {
	var rep pmdReporte
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, fmt.Errorf("salida de pmd ilegible en %s: %v", dirProyecto, err)
	}
	// Un error de configuración es NUESTRO, no del repo: significa que la regla
	// no llegó a evaluarse. Presentar el resto como análisis completo sería
	// prometer una cobertura que no hubo, así que la capa se declara degradada
	// entera — el mismo corte que hace biome con sus internalError.
	if len(rep.ConfigurationErrors) > 0 {
		c := rep.ConfigurationErrors[0]
		return nil, fmt.Errorf("pmd no pudo cargar sus reglas en %s (%s): %s",
			dirProyecto, c.Rule, jRecortar(colapsar(c.Message), 300))
	}

	var findings []finding.Finding
	for _, a := range rep.Files {
		file := rutaRepoJava(repoRoot, dirProyecto, a.Filename)
		for _, v := range a.Violations {
			sev, bloquea := severidadPMD(v.Priority)
			f := finding.Finding{
				Engine:   "pmd",
				RuleKey:  v.Rule,
				Pillar:   finding.Quality,
				Severity: sev,
				Blocking: bloquea,
				File:     file,
				Line:     maxLinea(v.BeginLine),
				EndLine:  v.EndLine,
				Message:  v.Description,
				Why:      porQuePMD,
				FixHint:  arregloPMD(v),
				Verified: true,
				Source:   finding.Deterministic,
				// El fingerprint (§9) no lleva número de línea para sobrevivir a
				// los desplazamientos del archivo; con la regla y la descripción
				// dentro, dos violaciones distintas de la misma regla en el mismo
				// archivo siguen siendo dos hallazgos.
				LineContent: v.Rule + " " + v.Description,
			}
			f.ComputeFingerprint()
			findings = append(findings, f)
		}
	}

	// Un archivo que no parsea NO se calla. PMD es el único motor de este
	// producto que mira la sintaxis de Java (no hay compuerta de compilación
	// para Java como tsc o dotnet build), así que ignorarlo dejaría pasar un
	// .java roto con el informe en verde. Tampoco degrada el motor entero: los
	// demás archivos SÍ se analizaron y sus hallazgos son válidos, a diferencia
	// de dotnet-build donde el fallo es del proyecto completo.
	for _, pe := range rep.ProcessingErrors {
		file := rutaRepoJava(repoRoot, dirProyecto, pe.Filename)
		// message trae la primera línea útil y luego el volcado del parser; el
		// "detail" con el stack trace entero se ignora a propósito.
		msg := jRecortar(colapsar(pe.Message), 300)
		f := finding.Finding{
			Engine:      "pmd",
			RuleKey:     "processing-error",
			Pillar:      finding.Quality,
			Severity:    finding.Error,
			Blocking:    true,
			File:        file,
			Line:        1,
			Message:     "PMD no pudo analizar este archivo: " + msg,
			Why:         "Sin AST no hay análisis: este archivo quedó SIN revisar, y decir lo contrario sería reportar limpio lo que nadie miró.",
			FixHint:     "Casi siempre es sintaxis inválida: corrige lo que señala el mensaje (trae línea y columna) y el archivo vuelve a entrar en el análisis.",
			Verified:    true,
			Source:      finding.Deterministic,
			LineContent: "processing-error " + msg,
		}
		f.ComputeFingerprint()
		findings = append(findings, f)
	}
	return findings, nil
}

// falloProyectoPMD convierte el fallo acotado de UN proyecto en un hallazgo
// bloqueante: ese proyecto quedó sin revisar y el informe tiene que decirlo, ni
// salir en verde ni tirar los proyectos que sí se analizaron. Es el equivalente
// por proyecto del processing-error por archivo.
func falloProyectoPMD(dir string, err error) finding.Finding {
	msg := jRecortar(colapsar(err.Error()), 300)
	f := finding.Finding{
		Engine:      "pmd",
		RuleKey:     "project-error",
		Pillar:      finding.Quality,
		Severity:    finding.Error,
		Blocking:    true,
		File:        dir,
		Line:        1,
		Message:     "PMD no pudo analizar este proyecto: " + msg,
		Why:         "Este proyecto quedó SIN revisar; los demás sí se analizaron y sus hallazgos son válidos.",
		FixHint:     "Corrige la causa que señala el mensaje y el proyecto vuelve a entrar en el análisis.",
		Verified:    true,
		Source:      finding.Deterministic,
		LineContent: "project-error " + msg,
	}
	f.ComputeFingerprint()
	return f
}

// severidadPMD traduce la prioridad de PMD a la política §7.
//
// 1 y 2 son las que PMD reserva para lo que casi siempre es un defecto real
// (BrokenNullCheck: el null check está escrito al revés y va a lanzar NPE;
// DoubleCheckedLocking: el patrón roto de siempre): bloquean, como el lint de
// severidad error de eslint y govet.
//
// 3, 4 y 5 avisan. Son las de criterio (ForLoopCanBeForeach,
// SimplifyBooleanReturns): tienen razón, pero en código existente hay cientos y
// convertirlas en bloqueantes haría el hook inusable el primer día — que es
// como se acaba desinstalando, la misma razón por la que dotnet-build no pasa
// -warnaserror.
func severidadPMD(prioridad int) (finding.Severity, bool) {
	if prioridad >= 1 && prioridad <= 2 {
		return finding.Error, true
	}
	return finding.Warning, false
}

// arregloPMD da la ficha de la regla cuando PMD la trae, que es casi siempre:
// la ficha explica el porqué y trae el ejemplo bueno y el malo, que es mejor
// consejo del que podríamos escribir nosotros para 124 reglas.
func arregloPMD(v pmdViolacion) string {
	if u := strings.TrimSpace(v.ExternalInfoURL); u != "" {
		return "Ficha de la regla (con ejemplo correcto e incorrecto): " + u
	}
	return "Regla " + v.Rule + " del conjunto " + v.RuleSet + " de PMD; corrige lo que señala el mensaje."
}
