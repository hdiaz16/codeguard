package daemon

import (
	"bufio"
	"context"
	"errors"
	"log"
	"os"
	"os/exec"

	"codeguard/internal/config"
	"codeguard/internal/engines/proc"
	"codeguard/internal/trivydb"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Precalentamiento (spike S5 / corrección H3): el primer commit del día no
// debe pagar el tsc frío. El daemon recuerda qué repos atiende y recalienta
// sus compiladores incrementales al arrancar, en background.

// warmListPath es dónde se apunta qué repos precalentar. Absoluta o nada, por
// el mismo motivo y con la misma forma que registry.path, store.DefaultPath y
// cmd/codeguard.dirDatos: `base == ""` deja pasar el valor en blanco y el
// relativo, y filepath.Join no falla con ellos — devuelve una ruta relativa al
// directorio de trabajo.
//
// La consecuencia aquí es menor que en los otros tres y conviene decirlo con
// precisión en vez de exagerarla: esto corre en el daemon, cuyo directorio de
// trabajo no es el repositorio que se analiza, así que el archivo no aterriza en
// el árbol del usuario sino donde se lanzara el daemon. Se arregla igual porque
// es la misma clase de bug —ya nos ha costado cuatro hallazgos— y porque "el CWD
// del daemon nunca será un repo" es exactamente el tipo de suposición que deja
// de ser cierta sin que nadie lo note.
//
// Devolver "" es seguro: los dos llamadores abren el archivo y ya tratan el
// error como "no hay lista".
func warmListPath() string {
	dir := dirDatosUsuario()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "codeguard", "warm-repos.txt")
}

// dirDatosUsuario es la base por-usuario donde CodeGuard y sus motores guardan
// datos, con el guard de arriba aplicado UNA vez. Estaba sólo dentro de
// warmListPath, así que cada sitio nuevo que resolviera la base tenía que
// acordarse de repetirlo —y WarmTrivyDB no se acordó—; siendo la única forma de
// obtenerla, el próximo llamador lo hereda sin poder olvidarlo. Devuelve "" si
// ni LOCALAPPDATA ni el temporal de respaldo dan una ruta absoluta, y cada
// llamador decide qué significa eso.
func dirDatosUsuario() string {
	dir := os.Getenv("LOCALAPPDATA")
	if !filepath.IsAbs(dir) {
		dir = os.TempDir()
	}
	if !filepath.IsAbs(dir) {
		return ""
	}
	return dir
}

var warmMu sync.Mutex

// RememberRepo apunta el repo para precalentarlo en el próximo arranque.
func RememberRepo(repoRoot string) {
	warmMu.Lock()
	defer warmMu.Unlock()
	path := warmListPath()
	existing := map[string]bool{}
	if f, err := os.Open(path); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			existing[strings.TrimSpace(sc.Text())] = true
		}
		// Si la lectura se cortó, "existing" es parcial: lo peor que pasa
		// al seguir es una línea duplicada, que podarWarmList ya limpia.
		// Pero el corte se dice, no se traga.
		if err := sc.Err(); err != nil {
			log.Printf("warmup: no se pudo leer entero %s: %v", path, err)
		}
		f.Close()
	}
	if existing[repoRoot] {
		return
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o755) // best-effort: el WriteString de abajo dará el error real
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	// Cerrar sin mirar puede tragarse un error de escritura diferido. Aquí sólo
	// significa un repo menos precalentado mañana, así que se anota y se sigue.
	_, werr := f.WriteString(repoRoot + "\n")
	if cerr := f.Close(); werr != nil || cerr != nil {
		log.Printf("no se pudo recordar %s para precalentar: %v", repoRoot, errors.Join(werr, cerr))
	}
}

// WarmTrivyDB descarga/refresca la base de vulnerabilidades fuera del camino
// del commit (corrección H10 de la auditoría). El hook siempre corre trivy con
// --skip-db-update: sin esta rutina, la primera vez falla ("cannot be specified
// on the first run") y después envejece para siempre.
func WarmTrivyDB(ctx context.Context) {
	if _, err := exec.LookPath("trivy"); err != nil {
		return // trivy no instalado: nada que refrescar
	}
	// La ruta pasa por el mismo guard que warmListPath, que aquí faltaba: con
	// LOCALAPPDATA vacío el Join daba una ruta RELATIVA al CWD del daemon, y la
	// base se descargaba donde trivy no la va a leer — el refresco no serviría
	// de nada y se repetiría en cada arranque. Sin base absoluta no se toca
	// nada, y se dice en el log en vez de tragárselo.
	base := dirDatosUsuario()
	if base == "" {
		log.Printf("trivy: ni LOCALAPPDATA ni el temporal dan una ruta absoluta: no se refresca la base")
		return
	}
	// metadata.json de la DB: si tiene menos de 24 h, no se toca
	cache := filepath.Join(base, "trivy", "db", "metadata.json")
	if st, err := os.Stat(cache); err == nil && time.Since(st.ModTime()) < 24*time.Hour {
		return
	}
	start := time.Now()
	c, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	// La baja CodeGuard, no trivy. `trivy --download-db-only` pasa por
	// oras-go, que arrastra un CVE sin corrección publicada, y esta rutina era
	// una de las dos únicas rutas donde ese código tocaba datos de la red — y
	// además corría sin la contención de los motores. Con la descarga propia
	// (internal/trivydb: digests verificados antes de abrir nada), trivy pasa
	// a correr SIEMPRE con --skip-db-update y la excepción de oras deja de
	// tener ruta viva. (Esto también deja sin objeto el entorno acotado que la
	// rama de casa le ponía al subproceso: ya no hay subproceso.)
	if err := trivydb.Actualizar(c, filepath.Join(base, "trivy")); err != nil {
		log.Printf("trivy: no se pudo refrescar la DB: %v", err)
		return
	}
	log.Printf("trivy: base de vulnerabilidades actualizada (%.0f s)", time.Since(start).Seconds())
}

// WarmSemgrep paga el arranque en frío de semgrep fuera del camino del commit.
//
// Semgrep es un CLI de Python: intérprete + imports + parseo del rulepack
// suman 4-6 s la primera vez, contra un presupuesto de hook de ~5 s. El
// resultado era que el PRIMER commit de la sesión decía "capas no revisadas:
// semgrep:error" y pasaba sin las 112 reglas de la casa — justo el commit de
// buenos días. Un análisis mínimo aquí deja caliente el intérprete, los
// módulos y las reglas en la caché de archivos del sistema.
func WarmSemgrep(ctx context.Context) {
	if _, err := exec.LookPath("semgrep"); err != nil {
		return // no instalado: nada que calentar
	}
	// El rulepack que reparte el instalador vive junto a los binarios; se usa
	// la versión más nueva presente. Calentar con las reglas REALES importa:
	// su parseo es la mitad del costo frío.
	exe, err := os.Executable()
	if err != nil {
		return
	}
	versiones := RulepacksInstalados(filepath.Dir(exe))
	if len(versiones) == 0 {
		return
	}
	rules := filepath.Join(filepath.Dir(exe), "rulepacks", versiones[0], "semgrep")
	if _, err := os.Stat(rules); err != nil {
		return
	}

	// Un objetivo mínimo de cada lenguaje del pack: suficiente para forzar la
	// carga de los parsers sin analizar nada de verdad.
	dir, err := os.MkdirTemp("", "codeguard-warm-*")
	if err != nil {
		return
	}
	defer os.RemoveAll(dir)
	for nombre, contenido := range map[string]string{
		"w.go": "package w\n", "w.py": "x = 1\n", "w.ts": "export const x = 1\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, nombre), []byte(contenido), 0o644); err != nil {
			return
		}
	}

	start := time.Now()
	wctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(wctx, "semgrep", "scan", "--config", rules,
		"--json", "--metrics=off", "--quiet", "--disable-version-check", dir)
	proc.SinVentana(cmd)
	cmd.Env = proc.Entorno("PYTHONUTF8=1", "PYTHONIOENCODING=utf-8")
	_ = cmd.Run() // el exit code no importa: sólo queremos la caché caliente
	log.Printf("precalentado semgrep (%.1f s)", time.Since(start).Seconds())
}

// WarmAll recalienta los motores fríos. Llamar en goroutine al arrancar el
// daemon; nunca está en el camino de ningún commit.
func WarmAll(ctx context.Context) {
	// Semgrep primero: es la capa que compite con el presupuesto del hook.
	// La DB de trivy puede tardar minutos y no bloquea a nadie.
	WarmSemgrep(ctx)
	WarmTrivyDB(ctx)
	// La lista es sólo una pista de lo que alguna vez se analizó; no es una
	// autorización eterna para ejecutar binarios de esos repos en cada boot.
	// Se lee bajo warmMu para no cruzarse con RememberRepo, se revalida cada
	// entrada ANTES de tocar node_modules y se poda lo que ya no está enrolado.
	warmMu.Lock()
	f, err := os.Open(warmListPath())
	if err != nil {
		warmMu.Unlock()
		return
	}
	var repos []string
	snapshot := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if r := strings.TrimSpace(sc.Text()); r != "" {
			repos = append(repos, r)
			snapshot[r] = true
		}
	}
	scanErr := sc.Err()
	f.Close()
	warmMu.Unlock()
	if scanErr != nil {
		// La lista quedó leída a medias. Precalentar sólo lo leído es
		// seguro, y la poda también: podarWarmList sólo toca entradas que
		// estaban en el snapshot, así que lo no leído nunca se borra. Se
		// sigue con lo que hay, pero el corte queda dicho.
		log.Printf("warmup: warm-repos.txt leído a medias (%v): se precalienta sólo lo leído", scanErr)
	}

	invalid := map[string]string{}
	for _, repo := range repos {
		if ctx.Err() != nil {
			return
		}
		ok, motivo := repoPrecalentable(repo)
		if !ok {
			invalid[repo] = motivo
			continue
		}
		if _, err := os.Stat(filepath.Join(repo, "tsconfig.json")); err != nil {
			continue
		}
		start := time.Now()
		wctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		// NUNCA el tsc.cmd del repo. Ese shim vive en node_modules/.bin,
		// cualquier postinstall puede reescribirlo, y esto corre en CADA arranque
		// del daemon sin usuario delante: elegir el ejecutable leyendo una ruta
		// que el repo controla es entregarle la ejecución. La revalidación de
		// repoPrecalentable no cubre este caso, porque un repo hostil que se
		// analizó una vez sigue enrolado y con su config válida.
		//
		// MEDIDO en esta máquina, porque la razón importa y la primera versión de
		// este comentario la tenía mal: `npx --no-install tsc` NO cae al
		// node_modules/.bin del cwd. npm resuelve por nombre de PAQUETE, y el
		// paquete que trae el compilador se llama `typescript`, no `tsc`; con un
		// repo que tenía typescript instalado Y el shim en .bin, npx canceló con
		// `missing packages ["tsc@2.0.4"]` sin ejecutar el binario del repo (ese
		// tsc@2.0.4 es el paquete impostor que documenta tscnoarranco_test.go).
		// O sea que el vector queda cerrado, pero por la resolución de npm, no
		// porque npx "se resuelva fuera del alcance del repo".
		//
		// Y la otra cara de esa medición: en un repo normal esto NO CALIENTA NADA,
		// porque npx cancela. El precalentamiento de tsc (spike S5) está de hecho
		// inoperante mientras se resuelva así, y recuperarlo exigiría volver a
		// ejecutar un binario que el repo controla. Es una decisión de producto
		// pendiente; lo que no se puede es seguir anunciando en el log que se
		// precalentó cuando no ocurrió.
		cmd := exec.CommandContext(wctx, "npx.cmd",
			"--no-install", "tsc", "--noEmit", "--incremental", "--pretty", "false")
		proc.SinVentana(cmd)
		cmd.Dir = repo
		// El mismo entorno con el que corre el tsc del análisis
		// (linters/exec.go:21). Calentar con un entorno distinto del real,
		// además de regalarle la clave, calentaría otra cosa.
		cmd.Env = proc.Entorno()
		salida, err := cmd.CombinedOutput()
		cancel()
		// El exit code SÍ importa para lo que se dice en el log. Un tsc real sale
		// con código distinto de cero cuando encuentra errores de tipos y aun así
		// deja el caché caliente, así que un fallo no es necesariamente «no
		// calentó»; pero afirmar «precalentado» sin distinguir es exactamente el
		// tipo de mensaje que hace perder media hora cuando el primer commit
		// sigue pagando el tsc frío y el log jura que no debería.
		if err != nil {
			log.Printf("no se pudo precalentar tsc en %s (%.1f s): %v — %s",
				filepath.Base(repo), time.Since(start).Seconds(), err, motivoCorto(salida))
			continue
		}
		log.Printf("precalentado tsc en %s (%.1f s)", filepath.Base(repo), time.Since(start).Seconds())
	}
	podarWarmList(snapshot, invalid)
}

// motivoCorto deja la primera línea con contenido de la salida de una herramienta,
// acotada. npm escupe una decena de líneas por un solo error y el log del daemon lo
// lee una persona buscando por qué su primer commit sigue tardando: la primera línea
// dice qué pasó y el resto es ruido. Se acota en runas —no en bytes— porque estos
// mensajes vienen con acentos y rutas del usuario.
func motivoCorto(salida []byte) string {
	for _, l := range strings.Split(string(salida), "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		r := []rune(l)
		if len(r) > 200 {
			return string(r[:200]) + "…"
		}
		return l
	}
	return "sin salida"
}

// repoPrecalentable decide si una entrada de warm-repos.txt todavía autoriza
// ejecutar el tsc de ese repo en un arranque sin usuario delante. Criterio
// fail-closed: cualquier duda (ruta relativa, repo ausente, config inválida o
// repo ya no enrolado) significa no ejecutar y podar la entrada.
func repoPrecalentable(repo string) (bool, string) {
	if !filepath.IsAbs(repo) {
		return false, "ruta no absoluta"
	}
	st, err := os.Stat(repo)
	if err != nil {
		return false, "el repo ya no existe: " + err.Error()
	}
	if !st.IsDir() {
		return false, "la ruta ya no es un directorio"
	}
	cfg, err := config.Load(repo)
	if err != nil {
		return false, "config CodeGuard inválida: " + err.Error()
	}
	if cfg == nil {
		return false, "repo ya no enrolado en CodeGuard"
	}
	return true, ""
}

// podarWarmList reescribe la lista quitando sólo entradas que estaban en el
// snapshot de ESTE arranque y fallaron la revalidación. Lo que RememberRepo
// haya añadido mientras corría el warmup no estaba en snapshot y se conserva.
func podarWarmList(snapshot map[string]bool, invalid map[string]string) {
	if len(invalid) == 0 {
		return
	}
	warmMu.Lock()
	defer warmMu.Unlock()
	path := warmListPath()
	f, err := os.Open(path)
	if err != nil {
		return
	}
	var kept []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		r := strings.TrimSpace(sc.Text())
		if r == "" || seen[r] {
			continue
		}
		if snapshot[r] {
			if motivo, malo := invalid[r]; malo {
				log.Printf("warmup: podado %s de warm-repos.txt (%s)", r, motivo)
				continue
			}
		}
		seen[r] = true
		kept = append(kept, r)
	}
	if err := sc.Err(); err != nil {
		// CRÍTICO: la lista se leyó a medias, así que "kept" no contiene
		// las entradas que no se llegaron a leer. Reescribir ahora el
		// archivo las BORRARÍA sin haberlas revalidado. Se aborta la poda
		// y el archivo queda intacto: ya podará el próximo arranque.
		f.Close()
		log.Printf("warmup: no se pudo leer entero warm-repos.txt (%v): se aborta la poda, el archivo queda intacto", err)
		return
	}
	f.Close()

	g, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		log.Printf("warmup: no se pudo podar warm-repos.txt: %v", err)
		return
	}
	for _, r := range kept {
		if _, err := g.WriteString(r + "\n"); err != nil {
			log.Printf("warmup: no se pudo reescribir warm-repos.txt: %v", err)
			g.Close()
			return
		}
	}
	if err := g.Close(); err != nil {
		log.Printf("warmup: no se pudo cerrar warm-repos.txt tras podar: %v", err)
	}
}
