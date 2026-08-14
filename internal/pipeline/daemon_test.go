package pipeline_test

// Fase 5.1 — el daemon acelera; no debe cambiar el veredicto.
//
// Es la ruta menos ejercitada del producto y la que más fácil se desvía sin que
// nadie lo note: todo lo que se ha verificado hasta aquí corre por el camino
// SIN daemon —las pruebas apuntan CODEGUARD_PIPE a un pipe que no existe justo
// para no medir el daemon instalado—, así que la ruta que usa el desarrollador
// de verdad, todos los días, no la había mirado ninguna prueba.
//
// Y las dos ramas construyen sus motores por separado: el hook llama a
// daemon.Engines(cfg, false, cache) en su propio proceso, y el daemon llama a
// daemon.Engines(cfg, false, cache) en el suyo. Hoy coinciden. Que coincidan
// dentro de tres meses es lo que esta prueba defiende: basta que alguien pase
// inCI=true en una de las dos —o añada un motor a una sola— para que el orbe
// diga verde y el CI rechace, sin ningún error visible por el camino.
//
// Se comparan CONJUNTOS DE HUELLAS leídos de la base, no cuentas ni texto de
// terminal: dos rutas pueden encontrar 15 hallazgos cada una y no ser los
// mismos 15.

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
)

func TestConDaemonYSinDaemonElVeredictoEsElMismo(t *testing.T) {
	if testing.Short() {
		t.Skip("levanta el daemon de verdad y corre todos los motores")
	}
	if runtime.GOOS != "windows" {
		t.Skip("CodeGuard sólo se distribuye para Windows")
	}

	bin := construirBinario(t)
	binDaemon := construirDaemon(t)
	repo := montarRepo(t)

	// El rulepack VENDOREADO en el repo, no el instalado en la máquina.
	//
	// Las dos rutas corren con LOCALAPPDATA aislado —hace falta para que el
	// daemon de la prueba no toque la base real—, y ahí dentro no está el
	// rulepack. Sin vendorearlo, semgrep no aplica ninguna regla de la casa: las
	// dos rutas coincidían en 30 hallazgos SIN que las reglas del producto
	// participaran en la comparación. Coincidir en menos no es coincidir.
	copiarRulepack(t, repo)
	escribir(t, repo, ".codeguard/config.yaml", configCon("2026.08.2", 50000))
	git(t, repo, "add", "-A")

	// ── Ruta 1: sin daemon ────────────────────────────────────────────────
	datosSin := t.TempDir()
	prestarLaBaseDeTrivy(t, datosSin)
	calentar(t, bin, repo, datosSin, `\\.\pipe\codeguard-verificacion-sin-daemon`)
	sinDaemon, salidaSin := huellasPorElPipe(t, bin, repo, datosSin,
		`\\.\pipe\codeguard-verificacion-sin-daemon`)
	if !strings.Contains(salidaSin, "daemon:offline") {
		t.Fatalf("esta corrida NO fue sin daemon: alguien contestó por el pipe. "+
			"Comparar contra ella no demostraría nada.\n%s", salidaSin)
	}
	if len(sinDaemon) == 0 {
		t.Fatalf("la corrida sin daemon no encontró nada: no hay nada que comparar.\n%s", salidaSin)
	}

	// ── Ruta 2: con un daemon de verdad, el compilado de este árbol ───────
	//
	// Su propio pipe y su propio LOCALAPPDATA: si se colara el daemon instalado
	// en la máquina, la prueba estaría comparando contra OTRA versión del
	// producto y diría "coinciden" sin haber medido este código.
	datosCon := t.TempDir()
	pipe := `\\.\pipe\codeguard-verificacion-con-daemon`
	prestarLaBaseDeTrivy(t, datosCon)
	arrancarDaemon(t, binDaemon, datosCon, pipe)

	calentar(t, bin, repo, datosCon, pipe)
	conDaemon, salidaCon := huellasPorElPipe(t, bin, repo, datosCon, pipe)
	if strings.Contains(salidaCon, "daemon:offline") {
		t.Fatalf("el daemon no contestó y el hook analizó en su proceso: "+
			"esta prueba habría comparado la MISMA ruta consigo misma.\n%s\n%s",
			salidaCon, colaDelLog(t, datosCon))
	}

	// ── La comparación ────────────────────────────────────────────────────
	faltan := diferencia(sinDaemon, conDaemon)
	sobran := diferencia(conDaemon, sinDaemon)
	if len(faltan) == 0 && len(sobran) == 0 {
		t.Logf("  ✓ las dos rutas ven los mismos %d hallazgos", len(sinDaemon))
		t.Logf("  ✓ motores que participaron: %s", motoresDe(sinDaemon))
		// Y lo que NO se comparó, dicho en voz alta: un motor que no encuentra
		// nada en ninguna de las dos rutas no demuestra que coincidan, y contar
		// su silencio como acuerdo es exactamente cómo una compuerta apagada
		// pasa por compuerta sana.
		if ausentes := noParticiparon(sinDaemon); len(ausentes) > 0 {
			t.Logf("  SIN COMPARAR (no encontraron nada por ninguna ruta): %s",
				strings.Join(ausentes, ", "))
		}
		return
	}

	var b strings.Builder
	b.WriteString("el daemon CAMBIA el veredicto.\n")
	if len(faltan) > 0 {
		b.WriteString("\n  el daemon NO vio lo que sí ve el análisis en proceso:\n")
		b.WriteString(listar(faltan))
	}
	if len(sobran) > 0 {
		b.WriteString("\n  el daemon ve lo que el análisis en proceso NO ve:\n")
		b.WriteString(listar(sobran))
	}
	b.WriteString("\nEl daemon es una caché con ventana, no una segunda opinión: " +
		"cada diferencia es un commit cuyo veredicto depende de si el orbe estaba " +
		"arriba, y eso el desarrollador no lo puede ni ver.\n")

	// Sin saber qué capas se quedaron fuera en cada ruta, la diferencia se
	// interpreta a ojo: «lo cortó el plazo» y «ese motor no corre en el daemon»
	// se arreglan en sitios distintos.
	b.WriteString("\n  capas no revisadas sin daemon:  " + capasDe(salidaSin))
	b.WriteString("\n  capas no revisadas con daemon:  " + capasDe(salidaCon) + "\n")
	t.Error(b.String())
}

// ── andamiaje ────────────────────────────────────────────────────────────

// huellasPorElPipe corre el gancho contra un pipe concreto y devuelve las
// huellas del run que ESA corrida registró, junto con lo que imprimió.
//
// Se queda con el run NUEVO en vez de con "el más reciente" por lo de siempre:
// dos corridas seguidas comparten segundo y ordenar por fecha comparaba runs
// distintos.
func huellasPorElPipe(t *testing.T, bin, repo, datos, pipe string) (map[string]hallazgo, string) {
	t.Helper()
	rutaDB := filepath.Join(datos, "codeguard", "codeguard.db")
	previos := idsDeRuns(t, rutaDB)

	c := exec.Command(bin, "hook", "pre-commit")
	c.Dir = repo
	c.Env = entornoConPipe(t, datos, pipe)
	out, _ := c.CombinedOutput()
	salida := string(out)

	var nuevos []string
	for id := range idsDeRuns(t, rutaDB) {
		if !previos[id] {
			nuevos = append(nuevos, id)
		}
	}
	if len(nuevos) != 1 {
		t.Fatalf("esta corrida registró %d runs nuevos y se esperaba 1: "+
			"sin saber cuál es, la comparación no significa nada.\n%s", len(nuevos), salida)
	}

	// Dos formas de que una corrida parezca válida sin serlo, y las dos se han
	// pagado ya en este proyecto: sin rulepack no aplican las reglas de la casa,
	// y pasado el límite del diff el producto corre SÓLO secretos. En ambos
	// casos las dos rutas coincidirían —en nada— y la prueba diría que sí.
	if strings.Contains(salida, "rulepack-ausente") {
		t.Fatalf("el rulepack no está donde el producto lo busca: sin reglas de la casa "+
			"esta comparación no cubre el núcleo del producto.\n%s", salida)
	}
	if strings.Contains(salida, "diff_too_large") {
		t.Fatalf("la corrida se degradó a sólo-secretos: comparar dos rutas degradadas "+
			"no demuestra que coincidan cuando trabajan.\n%s", salida)
	}

	// Y la tercera, que es la que casi cuela un fallo inventado: un motor
	// cortado por PLAZO no dice nada sobre el cableado.
	//
	// La primera versión de esta prueba comparaba en frío y salía roja acusando
	// al daemon de no ver govet, staticcheck y semgrep. La causa era el
	// cronómetro: el daemon arrancaba, levantaba su ventana y atendía la
	// petición con el mismo tope de 30 s, así que cortaba tres motores que en
	// proceso sí cabían. Es comportamiento correcto —el tope existe para que el
	// commit nunca se quede colgado— y no tiene nada que ver con si las dos
	// rutas están cableadas igual.
	//
	// Por eso se compara EN RÉGIMEN, con las dos rutas calientes, que además es
	// como vive el producto: el daemon existe precisamente para estar caliente.
	if strings.Contains(salida, ":plazo") {
		// Skip y no Fatal, y la diferencia importa: esto es «no pude medir», no
		// «está mal». Pasó de verdad — la suite completa salió ROJA porque esta
		// prueba corrió mientras otro daemon actualizaba la base de trivy y
		// había tres llamadas reales al modelo en vuelo: los motores de Go
		// tardaron 29,9 s y el tope de 30 los cortó. Un rojo que significa «la
		// máquina estaba ocupada» enseña a reintentar los rojos, que es la
		// lección exactamente contraria a la de este arnés. El skip sale en el
		// resumen de la suite, así que tampoco desaparece en silencio.
		t.Skipf("a esta corrida el plazo le cortó motores (%s): compararla mediría el "+
			"cronómetro, no el cableado. Máquina saturada; reintenta en frío.\n%s",
			capasDe(salida), salida)
	}
	return hallazgosDelRun(t, rutaDB, nuevos[0]), salida
}

// calentar corre el gancho una vez y tira el resultado.
//
// La comparación se hace sobre la SEGUNDA corrida de cada ruta: la primera paga
// el arranque en frío —caché vacío, módulos de Go sin compilar, el daemon
// levantando su ventana— y bajo el tope de 30 s eso decide qué motores caben,
// que es justo lo que esta prueba no quiere medir.
func calentar(t *testing.T, bin, repo, datos, pipe string) {
	t.Helper()
	c := exec.Command(bin, "hook", "pre-commit")
	c.Dir = repo
	c.Env = entornoConPipe(t, datos, pipe)
	_, _ = c.CombinedOutput()
}

// arrancarDaemon levanta el daemon compilado de este árbol y espera a que
// ATIENDA el pipe. Lo mata al terminar la prueba.
//
// Esperar a que el proceso exista no vale: Wails tarda en construir ventanas y
// bandeja, y el hook que llegara antes recibiría "no such file or directory",
// caería a la ruta en proceso y la prueba compararía esa ruta consigo misma
// creyendo que midió el daemon. Se espera a que el pipe CONTESTE.
func arrancarDaemon(t *testing.T, binDaemon, datos, pipe string) {
	t.Helper()
	arrancarDaemonCon(t, binDaemon, datos, pipe, entornoConPipe(t, datos, pipe))
}

// arrancarDaemonCon es la misma función con el entorno explícito: la fase 5.3
// necesita añadirle la clave del proveedor falso, sin la cual llm.New devuelve
// nil y la capa LLM se apaga en silencio.
func arrancarDaemonCon(t *testing.T, binDaemon, datos, pipe string, entorno []string) {
	t.Helper()
	c := exec.Command(binDaemon)
	c.Env = entorno
	if err := c.Start(); err != nil {
		t.Fatalf("no se pudo arrancar el daemon: %v", err)
	}
	t.Cleanup(func() {
		_ = c.Process.Kill()
		_, _ = c.Process.Wait()
	})

	limite := time.Now().Add(60 * time.Second)
	for time.Now().Before(limite) {
		espera := 500 * time.Millisecond
		conn, err := winio.DialPipe(pipe, &espera)
		if err == nil {
			conn.Close()
			return
		}
		if c.ProcessState != nil {
			t.Fatalf("el daemon se murió antes de atender el pipe.\n%s", colaDelLog(t, datos))
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("el daemon no atendió %s en 60 s.\n%s", pipe, colaDelLog(t, datos))
}

func construirDaemon(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "codeguard-daemon.exe")
	c := exec.Command("go", "build", "-o", bin, "./cmd/daemon")
	c.Dir = raizDelRepo(t)
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("no se pudo construir el daemon: %v\n%s", err, out)
	}
	return bin
}

// colaDelLog devuelve el final del log del daemon aislado. Un fallo de arranque
// sin su log obliga a reproducirlo a mano para saber qué pasó.
func colaDelLog(t *testing.T, datos string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(datos, "codeguard", "daemon.log"))
	if err != nil {
		return "(el daemon no dejó log en " + datos + ")"
	}
	lineas := strings.Split(strings.TrimRight(string(b), "\r\n"), "\n")
	if len(lineas) > 25 {
		lineas = lineas[len(lineas)-25:]
	}
	return "─── final del log del daemon ───\n" + strings.Join(lineas, "\n")
}

// noParticiparon devuelve los motores esperados que no aparecieron.
//
// El alias biome→eslint no es un parche: el motor se llama "eslint" en la
// tabla del arnés porque es la casilla que ocupa, y graba en la base el nombre
// de la herramienta que de verdad corrió (biome o eslint, según lo que tenga el
// repo). Saber cuál fue es información buena; confundirla con "no corrió" no.
func noParticiparon(hs map[string]hallazgo) []string {
	alias := map[string]string{"biome": "eslint"}
	vistos := map[string]bool{}
	for _, h := range hs {
		n := h.motor
		if a, hay := alias[n]; hay {
			n = a
		}
		vistos[n] = true
	}
	var out []string
	for _, m := range todosLosMotores() {
		if !vistos[m] {
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out
}

// listar usa el mismo formato que la prueba de paridad: quien lea un fallo de
// las dos no tiene que traducir nada entre ellas.
func listar(hs map[string]hallazgo) string {
	var out []string
	for huella, h := range hs {
		out = append(out, "      "+h.describe(huella))
	}
	sort.Strings(out)
	return strings.Join(out, "\n") + "\n"
}

// capasDe extrae lo que el gancho dijo que no revisó.
func capasDe(salida string) string {
	for _, l := range strings.Split(salida, "\n") {
		if i := strings.Index(l, "capas no revisadas:"); i >= 0 {
			return strings.TrimSpace(l[i+len("capas no revisadas:"):])
		}
	}
	return "(ninguna)"
}

// prestarLaBaseDeTrivy enlaza la base de vulnerabilidades real dentro del
// LOCALAPPDATA aislado de una ruta.
//
// Sin esto la comparación era injusta y lo decía en rojo: trivy guarda su base
// bajo %LOCALAPPDATA%, el aislamiento se la quita, y con --skip-db-update la
// primera corrida falla entera ("--skip-db-update cannot be specified on the
// first run"). El daemon acababa teniéndola —se la baja en segundo plano— y el
// gancho a solas no, así que la prueba veía a trivy encontrar cuatro CVE por
// una ruta y ninguno por la otra, y acusaba al cableado de lo que era una base
// de datos ausente.
//
// Se enlaza en vez de copiarse: son 2,6 GB. Y se enlaza en vez de compartir el
// LOCALAPPDATA entero porque cada ruta tiene que llevar su propio caché de
// resultados; si lo compartieran, la segunda leería lo que dejó la primera y
// las dos coincidirían por construcción.
//
// Si la máquina no tiene la base, no se enlaza nada: trivy falla igual por las
// dos rutas y sale como SIN COMPARAR, que es honesto.
func prestarLaBaseDeTrivy(t *testing.T, datos string) {
	t.Helper()
	real := filepath.Join(os.Getenv("LOCALAPPDATA"), "trivy")
	if _, err := os.Stat(real); err != nil {
		t.Logf("  (sin base de trivy en %s: la casilla de CVE no entrará en la comparación)", real)
		return
	}
	enlace := filepath.Join(datos, "trivy")
	// Junction: no pide privilegios de administrador, a diferencia del enlace
	// simbólico de directorio.
	c := exec.Command("cmd", "/c", "mklink", "/J", enlace, real)
	if out, err := c.CombinedOutput(); err != nil {
		t.Logf("  (no se pudo enlazar la base de trivy: %v — %s)", err, strings.TrimSpace(string(out)))
	}
}
