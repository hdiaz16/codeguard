package daemon

import (
	"bufio"
	"context"
	"errors"
	"log"
	"os"
	"os/exec"

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
	dir := filepath.Join(os.Getenv("LOCALAPPDATA"), "codeguard")
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(os.TempDir(), "codeguard")
	}
	if !filepath.IsAbs(dir) {
		return ""
	}
	return filepath.Join(dir, "warm-repos.txt")
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
	// metadata.json de la DB: si tiene menos de 24 h, no se toca
	cache := filepath.Join(os.Getenv("LOCALAPPDATA"), "trivy", "db", "metadata.json")
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
	if err := trivydb.Actualizar(c, filepath.Join(os.Getenv("LOCALAPPDATA"), "trivy")); err != nil {
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
	f, err := os.Open(warmListPath())
	if err != nil {
		return
	}
	var repos []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if r := strings.TrimSpace(sc.Text()); r != "" {
			repos = append(repos, r)
		}
	}
	f.Close()

	for _, repo := range repos {
		if ctx.Err() != nil {
			return
		}
		if _, err := os.Stat(filepath.Join(repo, "tsconfig.json")); err != nil {
			continue
		}
		start := time.Now()
		wctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		bin := "npx.cmd"
		args := []string{"--no-install", "tsc", "--noEmit", "--incremental", "--pretty", "false"}
		if local := filepath.Join(repo, "node_modules", ".bin", "tsc.cmd"); fileExists(local) {
			bin, args = local, []string{"--noEmit", "--incremental", "--pretty", "false"}
		}
		cmd := exec.CommandContext(wctx, bin, args...)
		proc.SinVentana(cmd)
		cmd.Dir = repo
		// El mismo entorno con el que corre el tsc del análisis
		// (linters/exec.go:21). Calentar con un entorno distinto del real,
		// además de regalarle la clave, calentaría otra cosa.
		cmd.Env = proc.Entorno()
		_ = cmd.Run() // el exit code no importa: solo queremos el caché caliente
		cancel()
		log.Printf("precalentado tsc en %s (%.1f s)", filepath.Base(repo), time.Since(start).Seconds())
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
