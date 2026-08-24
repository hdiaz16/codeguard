package daemon

import (
	"context"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"codeguard/internal/engines/proc"
	"codeguard/internal/rulepack"
	"codeguard/internal/trivydb"
)

// Precalentamiento (spike S5 / corrección H3): el primer commit del día no
// debe pagar el tsc frío. El daemon recuerda qué repos atiende y recalienta
// sus compiladores incrementales al arrancar, en background.

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
	versiones := rulepack.RulepacksInstalados(filepath.Dir(exe))
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
	cmd.Env = proc.EntornoDePerfil(proc.PerfilPython)
	_ = cmd.Run() // el exit code no importa: sólo queremos la caché caliente
	log.Printf("precalentado semgrep (%.1f s)", time.Since(start).Seconds())
}

// WarmAll recalienta los motores fríos. Llamar en goroutine al arrancar el
