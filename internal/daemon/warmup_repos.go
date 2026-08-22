package daemon

import (
	"bufio"
	"context"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"codeguard/internal/config"
	"codeguard/internal/engines/proc"
)

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
