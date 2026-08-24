package pipeline_test

// FASE 2 — La promesa central: paridad local/CI.
//
// «Si el commit pasa aquí, pasa allá» es la frase que vende el producto, y
// hasta esta prueba nunca se había comprobado corriendo LAS DOS RUTAS sobre el
// mismo contenido. Se comparaba de oídas.
//
// La comparación es HUELLA POR HUELLA, no por número de hallazgos: dos rutas
// que encuentran 7 cosas distintas cada una suman lo mismo y no tienen nada que
// ver. El número coincide por casualidad más a menudo de lo que parece.
//
// Las diferencias legítimas están en la spec (§7) y la prueba las EXIGE en vez
// de tolerarlas: trivy, govulncheck y dotnet-vuln bloquean en CI y sólo avisan
// en local. Una prueba que aceptara "alguna diferencia" no detectaría el día
// que aparezca una que no debía estar.

import (
	"database/sql"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// ── 2.1 · Mismo contenido → mismos hallazgos por las dos rutas ───────────

func TestElGanchoYElCIVenLoMismo(t *testing.T) {
	bin, repo := prepararInvariante(t)
	datos := t.TempDir()

	// El rulepack va DENTRO del repo (rulepacks/<version>), que es el primer
	// sitio donde lo busca el producto. Sin esto, el directorio de datos
	// aislado deja a las dos rutas sin reglas de la casa y la paridad se
	// compararía con el motor más grande apagado en los dos lados: verde por
	// no mirar, que es el fallo que este proyecto persigue.
	copiarRulepack(t, repo)

	base := strings.TrimSpace(gitSalida(t, repo, "rev-parse", "HEAD"))

	// Un repo con violaciones de varios motores. Cuantos más, más superficie de
	// desacuerdo: una paridad que sólo se comprueba con un motor no dice nada
	// del resto.
	for _, v := range violaciones() {
		if v.requiere != "" {
			continue // sin JDK ni SDK esas capas no corren en ninguna de las dos
		}
		escribir(t, repo, v.archivo, v.contenido)
	}
	git(t, repo, "add", "-A")

	// Ruta 1: el gancho, sobre el índice.
	salidaHook, _ := correrCon(t, bin, repo, datos, "hook", "pre-commit")
	exigirQueLoAnaliceElBinarioDePrueba(t, salidaHook)

	// Ruta 2: el CI, sobre el mismo contenido ya commiteado.
	//
	// Con GITHUB_ACTIONS=true, que es lo que marca el run como "ci" en la base
	// —igual que en el CI de verdad—. Sin esa variable, `codeguard ci` corriendo
	// en una máquina de desarrollo se registra como "local", y la comparación
	// habría medido dos veces la misma columna sin notarlo.
	git(t, repo, "commit", "-q", "-m", "las violaciones", "--no-verify")
	sarif := filepath.Join(t.TempDir(), "ci.sarif")
	salidaCI, _ := correrComoCI(t, bin, repo, datos, "ci",
		"--base", base, "--head", "HEAD", "--out", sarif, "--shadow")

	db := filepath.Join(datos, "codeguard", "codeguard.db")
	local := hallazgosDe(t, db, "local")
	ci := hallazgosDe(t, db, "ci")

	if len(local) == 0 {
		t.Fatalf("el gancho no registró ni un hallazgo: no hay nada que comparar.\n%s", salidaHook)
	}
	if len(ci) == 0 {
		t.Fatalf("el CI no registró ni un hallazgo: no hay nada que comparar.\n%s", salidaCI)
	}
	t.Logf("  gancho: %d hallazgos · CI: %d hallazgos", len(local), len(ci))

	soloLocal := diferencia(local, ci)
	soloCI := diferencia(ci, local)

	// Lo que el CI ve de más está permitido SÓLO para los motores que la spec
	// declara "avisa en local, bloquea en CI". Cualquier otro es una grieta.
	permitidosEnCI := map[string]bool{"trivy": true, "govulncheck": true, "dotnet-vuln": true}

	// Un motor que se DEGRADÓ en una de las dos rutas no se puede comparar: no
	// corrió, así que su silencio no dice nada sobre el cableado.
	//
	// Pasó de verdad y costó entenderlo: con la suite entera en marcha —varios
	// daemons, semgrep, compilaciones de C#— staticcheck no cabía en el tope de
	// 30 s del gancho y el CI, que no tiene esa prisa, sí lo corría. La prueba
	// acusaba de romper la paridad a un desacuerdo que era el cronómetro de la
	// máquina. Aislada pasaba siempre, que es la peor clase de roja: la que
	// enseña a reintentar en vez de a mirar.
	//
	// Esto NO afloja la prueba: la degradación es explícita —el producto la
	// nombra motor por motor—, así que un motor que dejara de correr sin
	// marcarse seguiría saliendo como grieta. Y lo excluido se dice en voz alta,
	// porque una casilla que no se comparó no es una casilla verde.
	degradados := motoresDegradados(salidaHook, salidaCI)

	var grietas, sinComparar []string
	for h, m := range soloCI {
		switch {
		case degradados[m.motor] != "":
			sinComparar = append(sinComparar, m.motor+" ("+degradados[m.motor]+")")
		case !permitidosEnCI[m.motor]:
			grietas = append(grietas, m.describe(h))
		}
	}
	for h, m := range soloLocal {
		if etiqueta := degradados[m.motor]; etiqueta != "" {
			sinComparar = append(sinComparar, m.motor+" ("+etiqueta+")")
			continue
		}
		grietas = append(grietas, "sólo en local: "+m.describe(h))
	}
	// Misma huella en las dos rutas pero distinta DECISIÓN: bloquea en una y
	// sólo avisa en la otra. Hasta aquí sólo se comparaba la PRESENCIA de cada
	// huella, y la promesa del producto —«si pasa aquí, pasa allá»— es sobre la
	// decisión, no sobre la lista: un hallazgo que bloqueaba en CI y avisaba en
	// local pasaba en verde. La excepción del §7 es justo eso hecho a propósito
	// (avisa en local, bloquea en CI), así que los de permitidosEnCI quedan
	// fuera, igual que los motores que se degradaron en una de las dos rutas.
	for huella, l := range local {
		c, ok := ci[huella]
		if !ok || l.bloqueante == c.bloqueante {
			continue
		}
		if permitidosEnCI[l.motor] || degradados[l.motor] != "" {
			continue
		}
		grietas = append(grietas, "decisión distinta: local "+l.describe(huella)+
			" · CI "+c.describe(huella))
	}
	sort.Strings(grietas)
	if len(sinComparar) > 0 {
		sort.Strings(sinComparar)
		t.Logf("  SIN COMPARAR (se degradaron en una de las dos rutas): %s",
			strings.Join(unicos(sinComparar), ", "))
	}

	if len(grietas) > 0 {
		t.Errorf("las dos rutas NO ven lo mismo (%d diferencia(s)):\n  %s\n\n"+
			"«si el commit pasa aquí, pasa allá» es la promesa central del producto. "+
			"Cada diferencia es un commit que pasa en la máquina y muere en el CI, "+
			"o al revés — que es peor.", len(grietas), strings.Join(grietas, "\n  "))
	} else {
		t.Logf("  ✓ las dos rutas ven exactamente los mismos hallazgos")
	}

	// Qué motores participaron de verdad, y cuáles no.
	//
	// Sin esta línea, la prueba podría pasar con dos motores corriendo y leerse
	// como "la paridad está demostrada". Un verde que no dice sobre qué se
	// pronuncia vale menos de lo que aparenta.
	t.Logf("  motores que participaron: %s", motoresDe(local))

	// Y los que NO, uno por uno. Todos, no sólo los del §7: la paridad de un
	// motor que no corrió en ninguna de las dos rutas no está demostrada, esté
	// callado por la razón que sea.
	var ausentes []string
	for _, m := range todosLosMotores() {
		if !participo(local, m) && !participo(ci, m) {
			ausentes = append(ausentes, m)
		}
	}
	if len(ausentes) > 0 {
		t.Logf("  SIN COMPARAR (no encontraron nada en ninguna ruta): %s", strings.Join(ausentes, ", "))
	}
	for m := range permitidosEnCI {
		if !participo(local, m) && !participo(ci, m) {
			t.Logf("  ojo: la diferencia legítima del §7 no se ejercitó — %s no encontró nada, "+
				"así que esta corrida demuestra que las dos rutas coinciden, pero NO que la "+
				"excepción documentada de bloquear-en-CI funcione", m)
			break
		}
	}
}

// todosLosMotores es la lista completa que arma el daemon, para poder decir
// cuáles se quedaron fuera de la comparación.
func todosLosMotores() []string {
	set := map[string]bool{}
	for _, v := range violaciones() {
		set[v.motor] = true
	}
	for m := range sinPruebaTodavia {
		set[m] = true
	}
	var out []string
	for m := range set {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

func motoresDe(hs map[string]hallazgo) string {
	set := map[string]bool{}
	for _, h := range hs {
		set[h.motor] = true
	}
	var out []string
	for m := range set {
		out = append(out, m)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

func participo(hs map[string]hallazgo, motor string) bool {
	for _, h := range hs {
		if h.motor == motor {
			return true
		}
	}
	return false
}

// ── 2.2 · Un rulepack ausente lo dicen LAS DOS rutas ─────────────────────
//
// Si una de las dos aplicara las reglas de la casa y la otra no, la paridad se
// rompe en silencio y en la dirección peor: el commit pasa en la máquina y el
// CI lo rechaza por reglas que en local ni se ejecutaron.

func TestUnRulepackAusenteLoDicenLasDosRutas(t *testing.T) {
	bin, repo := prepararInvariante(t)
	datos := t.TempDir()

	base := strings.TrimSpace(gitSalida(t, repo, "rev-parse", "HEAD"))
	escribir(t, repo, ".codeguard/config.yaml",
		"version: 1\nrulepack: \"2099.99.9\"\nmax_diff_lines: 5000\n")
	escribir(t, repo, "app/inseguro.py",
		"import subprocess\n\n\ndef ejecutar(orden):\n    return subprocess.run(orden, shell=True)\n")
	git(t, repo, "add", "-A")

	salidaHook, _ := correrCon(t, bin, repo, datos, "hook", "pre-commit")
	if !strings.Contains(salidaHook, "rulepack") {
		t.Errorf("el gancho no avisó de que el rulepack anclado no está instalado:\n%s", salidaHook)
	} else {
		t.Log("  ✓ el gancho avisa del rulepack ausente")
	}

	git(t, repo, "commit", "-q", "-m", "sin rulepack", "--no-verify")
	// correrComoCI y no correrCon: con GITHUB_ACTIONS=true, que es lo que marca el
	// run como "ci" y hace que la política §7 aplique su cara de CI.
	salidaCI, _ := correrComoCI(t, bin, repo, datos, "ci",
		"--base", base, "--head", "HEAD", "--out", filepath.Join(t.TempDir(), "x.sarif"), "--shadow")
	// Antes de creerse lo que diga la segunda ruta, comprobar que fue de verdad
	// la ruta del CI. Ver comentario de exigirQueSeRegistraraComoCI.
	exigirQueSeRegistraraComoCI(t, filepath.Join(datos, "codeguard", "codeguard.db"), salidaCI)
	if !strings.Contains(salidaCI, "rulepack") {
		t.Errorf("el CI NO avisó de que el rulepack anclado no está instalado. "+
			"Si una ruta aplica las reglas de la casa y la otra no, la paridad se rompe "+
			"sin que nadie lo vea:\n%s", salidaCI)
	} else {
		t.Log("  ✓ el CI avisa del rulepack ausente")
	}
}

// ── andamiaje ────────────────────────────────────────────────────────────

type hallazgo struct {
	motor, regla, archivo string
	bloqueante            bool
}

func (h hallazgo) describe(huella string) string {
	b := "aviso"
	if h.bloqueante {
		b = "BLOQUEA"
	}
	// Una huella vacía o corta NO puede tumbar el mensaje: recortaba a ciegas y
	// la primera vez que la base guardó un hallazgo SIN huella —lo hacía la ruta
	// del daemon— el diagnóstico panicó en vez de enseñar el hallazgo. Un
	// mensaje de error que revienta tapa justo lo que hay que ver.
	corta := huella
	if len(corta) > 12 {
		corta = corta[:12] + "…"
	} else if corta == "" {
		corta = "SIN HUELLA"
	}
	return h.motor + "/" + h.regla + " en " + h.archivo + " (" + b + ", " + corta + ")"
}

// hallazgosDe lee de la base lo que registró una ruta, indexado por huella.
//
// Se lee la BD y no la salida por pantalla porque la huella es lo único que
// permite comparar dos hallazgos con certeza: el texto del mensaje cambia entre
// versiones y el número de línea se desplaza.
func hallazgosDe(t *testing.T, rutaDB, entorno string) map[string]hallazgo {
	t.Helper()
	if _, err := os.Stat(rutaDB); err != nil {
		t.Fatalf("no se creó la base local en %s: %v", rutaDB, err)
	}
	db, err := sql.Open("sqlite", rutaDB+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("no se pudo abrir la base: %v", err)
	}
	defer db.Close()

	// COALESCE porque rule_id llega NULL para algunos motores —los que reportan
	// sin identificador de regla, como el formateador—. No es un fallo de la
	// paridad, pero sí es un dato: un hallazgo sin regla no se puede atribuir en
	// la calibración por regla (§17), que cuenta aciertos y fallos POR regla.
	filas, err := db.Query(`
		SELECT f.fingerprint, f.engine, COALESCE(f.rule_id, '(sin regla)'), f.file_path, f.blocking
		  FROM findings f JOIN runs r ON r.id = f.run_id
		 WHERE r.environment = ?`, entorno)
	if err != nil {
		t.Fatalf("no se pudieron leer los hallazgos de %s: %v", entorno, err)
	}
	defer filas.Close()

	out := map[string]hallazgo{}
	for filas.Next() {
		var huella string
		var h hallazgo
		if err := filas.Scan(&huella, &h.motor, &h.regla, &h.archivo, &h.bloqueante); err != nil {
			t.Fatalf("fila ilegible: %v", err)
		}
		if huella == "" {
			t.Errorf("un hallazgo de %s se registró SIN huella (%s/%s en %s): "+
				"sin huella no se puede ni suprimir ni comparar", entorno, h.motor, h.regla, h.archivo)
			continue
		}
		out[huella] = h
	}
	// Sin esto, una lectura que falla a mitad de iteración —base bloqueada,
	// cursor muerto— devuelve un mapa incompleto que la comparación tomaría por
	// completo: una grieta inventada o, peor, una paridad falsa. El helper de
	// abajo ya lo comprueba; aquí faltaba.
	if err := filas.Err(); err != nil {
		t.Fatalf("lectura de hallazgos de %s incompleta: %v", entorno, err)
	}
	return out
}

// exigirQueSeRegistraraComoCI comprueba en la BASE que el run que se acaba de
// hacer quedó registrado como "ci".
//
// Existe porque una prueba de paridad que corre dos veces la misma ruta no
// prueba ninguna paridad, y por fuera no se distingue: `codeguard ci` invocado
// sin GITHUB_ACTIONS se ejecuta igual, imprime parecido y se registra como
// "local". Esta prueba llamaba a correrCon en su segunda ruta —sin la variable—
// y comparaba local contra local; si el aviso del CI hubiera estado roto, o
// cableado precisamente a esa variable, habría pasado en verde.
//
// La comprobación va contra la base y no contra la salida a propósito: el
// entorno del run es lo que decide qué cara de la política §7 se aplica (§7:
// avisa en local, bloquea en CI), así que es el dato que hay que exigir. Y se
// hace aquí, en un helper, para que la siguiente ruta de CI que alguien añada no
// pueda volver a olvidarse de la variable en silencio.
func exigirQueSeRegistraraComoCI(t *testing.T, rutaDB, salida string) {
	t.Helper()
	if _, err := os.Stat(rutaDB); err != nil {
		t.Fatalf("no se creó la base local en %s: %v\n%s", rutaDB, err, salida)
	}
	db, err := sql.Open("sqlite", rutaDB+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("no se pudo abrir la base: %v", err)
	}
	defer db.Close()

	filas, err := db.Query(`SELECT environment, COUNT(*) FROM runs GROUP BY environment`)
	if err != nil {
		t.Fatalf("no se pudieron leer los runs: %v", err)
	}
	defer filas.Close()
	porEntorno := map[string]int{}
	for filas.Next() {
		var entorno string
		var n int
		if err := filas.Scan(&entorno, &n); err != nil {
			t.Fatalf("fila ilegible: %v", err)
		}
		porEntorno[entorno] = n
	}
	if err := filas.Err(); err != nil {
		t.Fatalf("lectura de runs incompleta: %v", err)
	}
	if porEntorno["ci"] == 0 {
		t.Fatalf("la ruta que dice ser la del CI no se registró como \"ci\" (runs por entorno: %v).\n"+
			"Sin GITHUB_ACTIONS=true, `codeguard ci` se registra como \"local\": la prueba "+
			"estaría corriendo DOS VECES la ruta local y llamándolo paridad.\n%s", porEntorno, salida)
	}
}

func diferencia(a, b map[string]hallazgo) map[string]hallazgo {
	out := map[string]hallazgo{}
	for k, v := range a {
		if _, ok := b[k]; !ok {
			out[k] = v
		}
	}
	return out
}

// copiarRulepack pone el rulepack del árbol de fuentes dentro del repo de
// prueba, en rulepacks/<version>, que es el primer candidato que mira el
// producto.
func copiarRulepack(t *testing.T, repo string) {
	t.Helper()
	copiarRulepackComo(t, repo, "2026.08.2")
}

// correrComoCI ejecuta con GITHUB_ACTIONS=true, que es lo que hace que el run
// se registre como "ci" y que la política §7 aplique su cara de CI.
func correrComoCI(t *testing.T, bin, repo, datos string, args ...string) (string, int) {
	t.Helper()
	c := exec.Command(bin, args...)
	c.Dir = repo
	c.Env = append(entornoAislado(t, datos), "GITHUB_ACTIONS=true")
	out, err := c.CombinedOutput()
	codigo := 0
	if ee, ok := err.(*exec.ExitError); ok {
		codigo = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("no se pudo ejecutar %s %v: %v", bin, args, err)
	}
	return string(out), codigo
}

// motoresDegradados devuelve, de lo que imprimieron las dos rutas, qué motores
// NO llegaron a correr y por qué.
//
// Las dos lo dicen con palabras distintas —el gancho "capas no revisadas:" y el
// CI "capas degradadas:"— y las dos con etiquetas motor:motivo. Se leen las dos
// formas a propósito: quedarse con una dejaría medio problema invisible.
func motoresDegradados(salidas ...string) map[string]string {
	fuera := map[string]string{}
	for _, salida := range salidas {
		for _, l := range strings.Split(salida, "\n") {
			var lista string
			switch {
			case strings.Contains(l, "capas no revisadas:"):
				lista = l[strings.Index(l, "capas no revisadas:")+len("capas no revisadas:"):]
			case strings.Contains(l, "capas degradadas:"):
				lista = l[strings.Index(l, "capas degradadas:")+len("capas degradadas:"):]
			default:
				continue
			}
			for _, etiqueta := range strings.Split(lista, ",") {
				etiqueta = strings.TrimSpace(etiqueta)
				motor, motivo, hay := strings.Cut(etiqueta, ":")
				if !hay || motor == "" {
					continue
				}
				// daemon:offline no habla de ningún motor: dice por dónde corrió
				// el análisis, y es lo NORMAL en estas pruebas.
				if motor == "daemon" {
					continue
				}
				fuera[motor] = motivo
			}
		}
	}
	return fuera
}

func unicos(xs []string) []string {
	visto := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !visto[x] {
			visto[x] = true
			out = append(out, x)
		}
	}
	return out
}

// El parser de capas degradadas es pequeño y peligroso: si devolviera de más,
// apagaría la comparación de paridad entera sin que nadie lo notara — la prueba
// seguiría verde diciendo "las dos rutas ven lo mismo" tras haber excluido
// todo. Por eso tiene su propia prueba.
func TestLasCapasDegradadasSeLeenDeLasDosRedacciones(t *testing.T) {
	hook := "CodeGuard  secretos ✓\n" +
		"CodeGuard  capas no revisadas: staticcheck:plazo, trivy:error, daemon:offline\n"
	ci := "capas degradadas: govulncheck:plazo\n"

	fuera := motoresDegradados(hook, ci)

	for motor, motivo := range map[string]string{
		"staticcheck": "plazo", "trivy": "error", "govulncheck": "plazo",
	} {
		if fuera[motor] != motivo {
			t.Errorf("%s debía salir como degradado por %q y salió %q", motor, motivo, fuera[motor])
		}
	}
	// daemon:offline dice por dónde corrió el análisis, no qué motor faltó. Si
	// se colara, "daemon" pasaría a excluirse como si fuera un motor.
	if _, hay := fuera["daemon"]; hay {
		t.Error("daemon:offline se leyó como si fuera un motor degradado")
	}
	// Y lo más importante: NO puede inventarse motores. Un parser generoso
	// excluye motores sanos de la comparación y deja la paridad sin probar.
	if len(fuera) != 3 {
		t.Errorf("se leyeron %d motores degradados y sólo había 3: %v", len(fuera), fuera)
	}
	if len(motoresDegradados("CodeGuard  listo — commit permitido")) != 0 {
		t.Error("una corrida sin degradaciones produjo motores degradados")
	}
}
