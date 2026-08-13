package pipeline_test

// FASE 3 — El caché, que puede dar por bueno lo viejo.
//
// Un caché que no invalida cuando debe es la forma más silenciosa de todas:
// el veredicto de hoy es el de la semana pasada y nada en pantalla lo delata.
// Ya pasó en este proyecto — el arreglo del conteo de govulncheck estaba
// compilado y funcionando, y el informe seguía enseñando el número anterior
// porque venía del caché. Una corrección que no llega al usuario no existe.
//
// CÓMO SE MIDE, porque medir esto por tiempos sería adivinar: se ENVENENA la
// entrada del caché (se le mete "aquí no había nada") y se vuelve a correr.
//
//	Si el caché acierta  → sirve el veneno → 0 hallazgos.
//	Si el eje invalida   → ignora el veneno → los hallazgos reales.
//
// Cada eje se prueba con su control delante: primero se comprueba que el
// veneno SÍ se sirve cuando no se cambia nada. Sin ese paso, "los hallazgos
// reaparecieron" también sería el resultado de un caché que nunca acertó, y la
// prueba estaría certificando invalidación sin haber probado ninguna.
//
// Los cuatro ejes van por separado a propósito: tres de cuatro funcionando se
// ve exactamente igual que cuatro.

import (
	"database/sql"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// elDefecto es la violación que se persigue por los cuatro ejes. Semgrep la
// detecta con las reglas de la casa, así que también sirve para comprobar que
// el rulepack está donde debe.
const elDefecto = "import subprocess\n\n\ndef ejecutar(orden):\n" +
	"    return subprocess.run(orden, shell=True)\n"

func TestElCacheInvalidaEnSusCuatroEjes(t *testing.T) {
	// Se comparan CONJUNTOS DE HUELLAS, no cuentas.
	//
	// Contar hallazgos daba falsos rojos por dos motivos legítimos: al cambiar
	// UN archivo sólo reaparece ese —los demás siguen envenenados con razón—, y
	// al copiar un segundo rulepack entran ficheros nuevos al diff que aportan
	// hallazgos propios. El número bailaba; el conjunto no. Lo que significa
	// "invalidó" es exactamente esto: lo que estaba envenenado VUELVE.

	t.Run("contenido del archivo", func(t *testing.T) {
		bin, repo, datos := prepararCache(t)
		reales := analizarHuellas(t, bin, repo, datos)
		delArchivo := deArchivo(reales, "app/inseguro.py")
		if len(delArchivo) == 0 {
			t.Fatal("el archivo que se va a editar no produjo hallazgos: no hay nada que medir")
		}

		envenenar(t, datos)
		exigirQueElVenenoSeSirva(t, bin, repo, datos)

		// Se edita SIN tocar la línea que viola: cambia el sha del archivo y la
		// huella del hallazgo se mantiene, así que es comparable.
		escribir(t, repo, "app/inseguro.py", "# un comentario nuevo\n"+elDefecto)
		git(t, repo, "add", "-A")

		// Sólo debe volver lo de ESE archivo: el resto sigue envenenado, y eso
		// es correcto — un caché por archivo invalida por archivo.
		exigirQueVuelvan(t, delArchivo, analizarHuellas(t, bin, repo, datos),
			"al cambiar el CONTENIDO", "un archivo editado analizado con el resultado del anterior")
		t.Logf("  ✓ el contenido invalida (%d hallazgo(s) del archivo editado)", len(delArchivo))
	})

	t.Run("version del rulepack", func(t *testing.T) {
		bin, repo, datos := prepararCache(t)
		reales := analizarHuellas(t, bin, repo, datos)

		envenenar(t, datos)
		exigirQueElVenenoSeSirva(t, bin, repo, datos)

		copiarRulepackComo(t, repo, "2026.08.9")
		escribir(t, repo, ".codeguard/config.yaml", configCon("2026.08.9", 5000))
		git(t, repo, "add", "-A")

		// Aquí la invalidación es TOTAL: el rulepack entra en la clave de todas
		// las entradas, así que debe volver todo.
		exigirQueVuelvan(t, reales, analizarHuellas(t, bin, repo, datos),
			"al cambiar el RULEPACK", "actualizar las reglas sin que cambie el veredicto es una actualización que no llega")
		t.Logf("  ✓ la versión del rulepack invalida (%d hallazgo(s))", len(reales))
	})

	t.Run("config del repo", func(t *testing.T) {
		bin, repo, datos := prepararCache(t)
		reales := analizarHuellas(t, bin, repo, datos)

		envenenar(t, datos)
		exigirQueElVenenoSeSirva(t, bin, repo, datos)

		escribir(t, repo, ".codeguard/config.yaml", configCon("2026.08.2", 7000))
		git(t, repo, "add", "-A")

		exigirQueVuelvan(t, reales, analizarHuellas(t, bin, repo, datos),
			"al cambiar la CONFIG del repo", "el veredicto depende de la configuración y el caché la ignoraría")
		t.Logf("  ✓ el hash de la config invalida (%d hallazgo(s))", len(reales))
	})

	// El eje que más importa y el que más fácil se rompe sin que nadie lo note:
	// al actualizar CodeGuard cambian los motores, y el caché serviría lo que
	// produjo el binario anterior. Es el fallo que ya ocurrió con el conteo de
	// govulncheck.
	t.Run("version del binario", func(t *testing.T) {
		bin, repo, datos := prepararCache(t)
		reales := analizarHuellas(t, bin, repo, datos)

		envenenar(t, datos)
		exigirQueElVenenoSeSirva(t, bin, repo, datos)

		// El mismo código, compilado declarando otra versión. Nada más cambia:
		// si el caché acertara igual, sería porque la versión NO está en su clave.
		otro := construirBinarioConVersion(t, "9.9.9-verificacion")

		exigirQueVuelvan(t, reales, analizarHuellas(t, otro, repo, datos),
			"con OTRA VERSIÓN del binario",
			"al actualizar CodeGuard los motores cambian y el caché daría el veredicto del binario anterior: una corrección que no llega al usuario no existe")
		t.Logf("  ✓ la versión del binario invalida (%d hallazgo(s))", len(reales))
	})
}

// exigirQueVuelvan comprueba que TODO lo envenenado reaparece.
//
// Es un test de superconjunto y no de igualdad a propósito: cambiar un eje
// puede añadir archivos al diff (copiar un rulepack nuevo mete sus .yaml), y
// esos hallazgos de más son legítimos. Lo que no puede faltar es nada de lo que
// había antes — eso sería el caché sirviendo lo viejo.
func exigirQueVuelvan(t *testing.T, esperados, obtenidos map[string]hallazgo, queCambio, porQue string) {
	t.Helper()
	faltan := diferencia(esperados, obtenidos)
	if len(faltan) == 0 {
		return
	}
	var lista []string
	for h, m := range faltan {
		lista = append(lista, m.describe(h))
	}
	sort.Strings(lista)
	t.Errorf("%s, el caché siguió sirviendo lo viejo: faltan %d de %d hallazgos.\n  %s\n\n%s",
		queCambio, len(faltan), len(esperados), strings.Join(lista, "\n  "), porQue)
}

// deArchivo se queda con los hallazgos de una ruta concreta.
func deArchivo(hs map[string]hallazgo, ruta string) map[string]hallazgo {
	out := map[string]hallazgo{}
	for k, v := range hs {
		if v.archivo == ruta {
			out[k] = v
		}
	}
	return out
}

// ── 3.1 · Acierta, y al acertar devuelve LO MISMO ────────────────────────
//
// Un caché que acierta y devuelve otra cosa es peor que uno que no acierta: el
// segundo cuesta tiempo, el primero cuesta correcciones.

func TestElCacheDevuelveExactamenteLoMismo(t *testing.T) {
	bin, repo, datos := prepararCache(t)

	primera := analizarHuellas(t, bin, repo, datos)
	if len(primera) == 0 {
		t.Fatal("la primera corrida no encontró nada: no hay nada que comparar")
	}
	segunda := analizarHuellas(t, bin, repo, datos)

	if len(diferencia(primera, segunda)) > 0 || len(diferencia(segunda, primera)) > 0 {
		t.Errorf("la segunda corrida —ya con caché— devolvió hallazgos DISTINTOS: "+
			"%d vs %d, y no son los mismos", len(primera), len(segunda))
	} else {
		t.Logf("  ✓ con caché caliente devuelve los mismos %d hallazgos", len(primera))
	}

	// Y que el caché exista de verdad: si no hubiera entradas, esta prueba
	// habría comparado dos análisis completos y no habría probado el caché.
	if n := entradasDeCache(t, datos); n == 0 {
		t.Error("no se guardó ni una entrada de caché: esta prueba no ha medido el caché")
	} else {
		t.Logf("  ✓ el caché tiene %d entrada(s)", n)
	}
}

// ── andamiaje ────────────────────────────────────────────────────────────

func prepararCache(t *testing.T) (bin, repo, datos string) {
	t.Helper()
	bin, repo = prepararInvariante(t)
	datos = t.TempDir()
	copiarRulepack(t, repo)
	escribir(t, repo, ".codeguard/config.yaml", configCon("2026.08.2", 5000))
	escribir(t, repo, "app/inseguro.py", elDefecto)
	git(t, repo, "add", "-A")
	return bin, repo, datos
}

func configCon(rulepack string, maxLineas int) string {
	return "version: 1\nrulepack: \"" + rulepack + "\"\n" +
		"max_diff_lines: " + itoa(maxLineas) + "\n"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for n > 0 {
		d = append([]byte{byte('0' + n%10)}, d...)
		n /= 10
	}
	return string(d)
}

// Un apunte que vale la pena conservar de esta fase: la primera versión de
// estas pruebas contaba SÓLO los hallazgos de semgrep, porque al envenenar el
// caché quedaban 22 en pie —gofmt, govet, ruff y dotnet-format no recibían
// caché en daemon.Engines y analizaban siempre—. Acotar la medición a los
// motores que sí lo tenían habría hecho pasar la prueba escondiendo justo lo
// que no se estaba midiendo, y entre esos cuatro estaba govet, que compila
// paquetes y era el más caro de todos. Se les implementó el caché en vez de
// estrechar la prueba; por eso hoy la comparación puede ser total.

// analizarHuellas corre el GANCHO, no el informe.
//
// `codeguard report` no registra el run en la base —sólo lo hacen el gancho y
// el CI—, así que medir por ahí devolvía cero hallazgos siempre y la prueba se
// caía sin haber medido nada del caché. El gancho además es el camino real por
// el que el caché se llena y se consulta en el día a día.
func analizarHuellas(t *testing.T, bin, repo, datos string) map[string]hallazgo {
	t.Helper()
	rutaDB := filepath.Join(datos, "codeguard", "codeguard.db")

	// Qué runs había ANTES, para quedarse luego con el que nace de esta
	// corrida.
	//
	// La primera versión pedía "el run más reciente" ordenando por fecha, y dos
	// corridas seguidas comparten segundo: la comparación salió 31 contra 165
	// cuando el producto daba 176 en ambas. Estaba midiendo dos runs distintos.
	// La segunda intentó leer el id de .git/codeguard-lastrun y ese archivo no
	// estaba. Esto no depende de ningún detalle interno: se mira qué apareció.
	previos := idsDeRuns(t, rutaDB)

	salida, _ := correrCon(t, bin, repo, datos, "hook", "pre-commit")
	exigirQueLoAnaliceElBinarioDePrueba(t, salida)
	if strings.Contains(salida, "rulepack-ausente") {
		t.Fatalf("el rulepack no está donde el producto lo busca; la corrida no vale:\n%s", salida)
	}

	var nuevos []string
	for id := range idsDeRuns(t, rutaDB) {
		if !previos[id] {
			nuevos = append(nuevos, id)
		}
	}
	if len(nuevos) != 1 {
		t.Fatalf("esta corrida registró %d runs nuevos y se esperaba exactamente 1: "+
			"sin saber cuál es, la comparación no significa nada.\n%s", len(nuevos), salida)
	}
	return hallazgosDelRun(t, rutaDB, nuevos[0])
}

// idsDeRuns devuelve los runs ya registrados. Devuelve vacío si la base aún no
// existe: la primera corrida la crea.
func idsDeRuns(t *testing.T, rutaDB string) map[string]bool {
	t.Helper()
	if _, err := os.Stat(rutaDB); err != nil {
		return map[string]bool{}
	}
	db := abrirBase(t, rutaDB)
	defer db.Close()
	filas, err := db.Query(`SELECT id FROM runs`)
	if err != nil {
		t.Fatalf("no se pudieron listar los runs: %v", err)
	}
	defer filas.Close()
	out := map[string]bool{}
	for filas.Next() {
		var id string
		if err := filas.Scan(&id); err != nil {
			t.Fatalf("fila ilegible: %v", err)
		}
		out[id] = true
	}
	return out
}

func hallazgosDelRun(t *testing.T, rutaDB, runID string) map[string]hallazgo {
	t.Helper()
	db := abrirBase(t, rutaDB)
	defer db.Close()

	filas, err := db.Query(`
		SELECT f.fingerprint, f.engine, COALESCE(f.rule_id, '(sin regla)'), f.file_path, f.blocking
		  FROM findings f WHERE f.run_id = ?`, runID)
	if err != nil {
		t.Fatalf("no se pudieron leer los hallazgos del run %s: %v", runID, err)
	}
	defer filas.Close()

	out := map[string]hallazgo{}
	for filas.Next() {
		var huella string
		var h hallazgo
		if err := filas.Scan(&huella, &h.motor, &h.regla, &h.archivo, &h.bloqueante); err != nil {
			t.Fatalf("fila ilegible: %v", err)
		}
		out[huella] = h
	}
	return out
}

// envenenar sustituye TODO lo guardado en el caché por "aquí no había nada".
//
// Es la forma de distinguir un acierto de caché de un análisis nuevo sin
// depender de tiempos: si la siguiente corrida devuelve cero, sirvió el
// veneno; si devuelve los hallazgos reales, lo ignoró.
func envenenar(t *testing.T, datos string) {
	t.Helper()
	db := abrirBase(t, filepath.Join(datos, "codeguard", "codeguard.db"))
	defer db.Close()
	res, err := db.Exec(`UPDATE file_cache SET result_json = '[]'`)
	if err != nil {
		t.Fatalf("no se pudo envenenar el caché: %v", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		t.Fatal("el caché estaba vacío: no hay nada que envenenar, así que la prueba " +
			"no puede distinguir un acierto de un análisis nuevo")
	}
}

func entradasDeCache(t *testing.T, datos string) int {
	t.Helper()
	db := abrirBase(t, filepath.Join(datos, "codeguard", "codeguard.db"))
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM file_cache`).Scan(&n); err != nil {
		t.Fatalf("no se pudo contar el caché: %v", err)
	}
	return n
}

func abrirBase(t *testing.T, ruta string) *sql.DB {
	t.Helper()
	if _, err := os.Stat(ruta); err != nil {
		t.Fatalf("no se creó la base local en %s: %v", ruta, err)
	}
	db, err := sql.Open("sqlite", ruta+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("no se pudo abrir la base: %v", err)
	}
	return db
}

// copiarRulepackComo pone las REGLAS del rulepack dentro del repo de prueba.
//
// Sólo el directorio semgrep/, no el testdata/. El testdata son los fixtures
// del corpus: decenas de archivos con violaciones deliberadas en cinco
// lenguajes. Copiarlos dentro del repo metía ~160 hallazgos ajenos al análisis
// y, en el eje del rulepack —que copia una SEGUNDA versión—, duplicaba el diff
// hasta pasarse de max_diff_lines: el pipeline degradaba a sólo-secretos y la
// prueba lo leía como "el caché no invalidó". Dos fallos que no eran del
// producto sino del fixture.
//
// En tiempo también se nota: la comprobación pasó de 1508 s a menos de un
// minuto.
func copiarRulepackComo(t *testing.T, repo, version string) {
	t.Helper()
	origen := filepath.Join(raizDelRepo(t), "rulepacks", "2026.08.2", "semgrep")
	if _, err := os.Stat(origen); err != nil {
		t.Skipf("no encuentro el rulepack en el árbol: %v", err)
	}
	destino := filepath.Join(repo, "rulepacks", version, "semgrep")
	if err := os.CopyFS(destino, os.DirFS(origen)); err != nil {
		t.Fatalf("no se pudo copiar el rulepack como %s: %v", version, err)
	}
}

// construirBinarioConVersion compila EL MISMO código declarando otra versión,
// que es lo que hace `build-dist` al publicar.
func construirBinarioConVersion(t *testing.T, version string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "codeguard.exe")
	c := exec.Command("go", "build", "-ldflags", "-X main.version="+version,
		"-o", bin, "./cmd/codeguard")
	c.Dir = raizDelRepo(t)
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("no se pudo construir el binario con versión %s: %v\n%s", version, err, out)
	}
	return bin
}

// exigirQueElVenenoSeSirva comprueba que, tras envenenar, NO queda ningún
// hallazgo — y si queda, dice de qué motor.
//
// Nombrar al motor es el punto: un "esperaba 0, hubo 22" manda a leerse el
// código; un "sobrevivieron: gofmt, govet, ruff" dice exactamente qué motor no
// consulta el caché. Así fue como se encontraron los cuatro que le faltaban, y
// así se encontrará el quinto si mañana alguien añade uno sin caché.
func exigirQueElVenenoSeSirva(t *testing.T, bin, repo, datos string) {
	t.Helper()
	motores := map[string]int{}
	for _, h := range analizarHuellas(t, bin, repo, datos) {
		if noCacheablePorDiseño[h.motor] {
			continue
		}
		motores[h.motor]++
	}
	if len(motores) == 0 {
		return
	}
	var lista []string
	total := 0
	for m, n := range motores {
		lista = append(lista, m+" ("+itoa(n)+")")
		total += n
	}
	sort.Strings(lista)
	t.Fatalf("tras envenenar el caché sobrevivieron %d hallazgos de: %s.\n"+
		"Esos motores NO consultan el caché, así que re-analizan en cada commit "+
		"y quedan fuera de esta verificación de invalidación.",
		total, strings.Join(lista, ", "))
}

// noCacheablePorDiseño son los análisis que NO tienen clave de contenido, y por
// tanto no pueden ni deben cachearse.
//
// `playbook` no mira dentro de los archivos: mira la RELACIÓN entre ellos —un
// package.json sin su lockfile, un cambio demasiado grande para revisarse—. Su
// respuesta depende del conjunto de archivos del commit, no del contenido de
// ninguno, así que no hay sha por el que indexarla; cachearla por archivo daría
// respuestas falsas en cuanto cambie la combinación.
//
// Esta lista es una excepción NOMBRADA, no un atajo. Cuando la prueba encontró
// 22 hallazgos supervivientes, la salida fácil habría sido meter aquí a gofmt,
// govet, ruff y dotnet-format y seguir adelante; lo que se hizo fue
// implementarles el caché, que era el fallo de verdad. Aquí sólo entra lo que
// no puede tenerlo por cómo funciona, y el motivo se escribe.
var noCacheablePorDiseño = map[string]bool{
	"playbook": true,
}
