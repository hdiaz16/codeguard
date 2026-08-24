package pipeline_test

// Fase 5.2 — prepare-commit-msg y post-commit.
//
// Los tres ganchos se instalan juntos y sólo uno estaba probado. Los otros dos
// sostienen una cadena de la que depende §7.1:
//
//	pre-commit           analiza y deja el run id en .git/codeguard-lastrun
//	prepare-commit-msg   pega  Codeguard-Run-Id: <id>  en el mensaje
//	post-commit          ¿hay trailer? commit analizado. ¿No? SALTO registrado
//
// Que el salto quede registrado es lo que convierte a --no-verify en una
// decisión visible en vez de un agujero. Y el trailer es lo que ata un commit
// del historial con el análisis que lo revisó: sin él, la telemetría no puede
// decir qué se revisó de verdad.
//
// Estas pruebas hacen `git commit` DE VERDAD, con los ganchos instalados por el
// propio producto. Es la única forma de ejercitar prepare-commit-msg: lo invoca
// git, no nosotros, y con reglas suyas —--no-verify NO lo salta, que es
// precisamente de lo que dependen las dos trampas de abajo.

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestElTrailerAtaElCommitConSuAnalisis(t *testing.T) {
	_, repo, datos := prepararGanchos(t)

	escribir(t, repo, "app/limpio.py", "def suma(a: int, b: int) -> int:\n    return a + b\n")
	gitConEntorno(t, repo, datos, "add", "-A")
	commit(t, repo, datos, "un cambio limpio")

	mensaje := ultimoMensaje(t, repo)
	id := runIDDelTrailer(mensaje)
	if id == "" {
		t.Fatalf("el commit salió sin trailer Codeguard-Run-Id: nada ata este commit "+
			"con el análisis que lo revisó.\n%s", mensaje)
	}

	// Y que el id NO sea un adorno: tiene que existir como run en la base. Un
	// trailer que apunta a un análisis inexistente es peor que no tenerlo,
	// porque post-commit lo acepta y da el commit por revisado.
	if !existeRun(t, datos, id) {
		t.Errorf("el trailer dice Codeguard-Run-Id: %s y ese run NO está en la base.\n"+
			"post-commit lo da por analizado y el salto no se registra.", id)
	} else {
		t.Logf("  ✓ el trailer apunta al run %s, que existe en la base", id)
	}

	if n := saltosRegistrados(t, datos); n != 0 {
		t.Errorf("un commit analizado quedó marcado como salto (%d): "+
			"post-commit no vio el trailer que prepare-commit-msg acababa de poner", n)
	} else {
		t.Log("  ✓ post-commit lo reconoció como analizado: ningún salto registrado")
	}

	// El run id se limpia: si se quedara, el commit siguiente heredaría un
	// trailer que no le corresponde.
	if _, err := os.Stat(filepath.Join(repo, ".git", "codeguard-lastrun")); err == nil {
		t.Error("post-commit dejó el run id en .git/codeguard-lastrun: el commit " +
			"siguiente se pegaría el trailer de éste")
	} else {
		t.Log("  ✓ post-commit limpió el run id")
	}
}

func TestElCommitConNoVerifyQuedaMarcadoComoSalto(t *testing.T) {
	_, repo, datos := prepararGanchos(t)

	escribir(t, repo, "app/limpio.py", "def resta(a: int, b: int) -> int:\n    return a - b\n")
	gitConEntorno(t, repo, datos, "add", "-A")
	commitConNoVerify(t, repo, datos, "salto deliberado")

	mensaje := ultimoMensaje(t, repo)
	if id := runIDDelTrailer(mensaje); id != "" {
		t.Errorf("un commit sin analizar salió CON trailer (%s): el historial diría "+
			"que se revisó.\n%s", id, mensaje)
	} else {
		t.Log("  ✓ sin análisis no hay trailer")
	}

	// post-commit sí corre con --no-verify: git sólo se salta pre-commit y
	// commit-msg. Ahí está la oportunidad de registrar el salto, y §7.1 dice
	// que es señal de producto, no castigo.
	if n := saltosRegistrados(t, datos); n != 1 {
		t.Errorf("se esperaba 1 salto registrado y hay %d: --no-verify sería invisible", n)
	} else {
		t.Log("  ✓ el salto quedó registrado (bypassed=1)")
	}
}

// Trampa 1: bloquear, y que el reintento con --no-verify se camufle con el
// trailer del análisis anterior.
//
// El producto lo evita borrando el run id al bloquear. Esta prueba existe para
// que ese borrado no se pierda en una refactorización: es una línea suelta cuya
// ausencia no rompe absolutamente nada visible.
func TestUnBloqueoNoDejaTrailerQueCamufleElSalto(t *testing.T) {
	_, repo, datos := prepararGanchos(t)

	// Primero un commit normal, para que exista un run id "anterior" que robar.
	escribir(t, repo, "app/limpio.py", "def suma(a: int, b: int) -> int:\n    return a + b\n")
	gitConEntorno(t, repo, datos, "add", "-A")
	commit(t, repo, datos, "un cambio limpio")

	// Ahora algo que BLOQUEA. El secreto sirve mejor que un hallazgo de reglas:
	// la compuerta de secretos es fail-closed y no depende del rulepack.
	escribir(t, repo, "config.env", elSecreto)
	gitConEntorno(t, repo, datos, "add", "-A")
	salida, codigo := intentarCommit(t, repo, datos, "esto debería bloquearse")
	if codigo == 0 {
		t.Fatalf("el commit con un secreto NO se bloqueó: no hay trampa que probar.\n%s", salida)
	}
	t.Log("  ✓ el commit con el secreto se bloqueó")

	// Y el reintento saltándose el gancho.
	commitConNoVerify(t, repo, datos, "me lo salto")

	mensaje := ultimoMensaje(t, repo)
	if id := runIDDelTrailer(mensaje); id != "" {
		t.Errorf("el commit saltado se llevó el trailer %s del análisis ANTERIOR.\n"+
			"Con trailer, post-commit lo da por revisado y el salto no se registra: "+
			"un commit con un secreto dentro entra al historial marcado como analizado.\n%s",
			id, mensaje)
	} else {
		t.Log("  ✓ el bloqueo no dejó trailer que robar")
	}
	if n := saltosRegistrados(t, datos); n != 1 {
		t.Errorf("se esperaba 1 salto registrado y hay %d", n)
	} else {
		t.Log("  ✓ el salto quedó registrado pese al bloqueo previo")
	}
}

// Trampa 2, la que sí estaba abierta: el trailer sobreviviendo a un CAMBIO DE
// CONTENIDO.
//
// pre-commit escribe el run id y sólo lo borran el bloqueo y post-commit. Si el
// commit se aborta en medio —cerrar el editor del mensaje sin guardar es el
// caso normal— el run id se queda en disco. Y prepare-commit-msg NO se salta
// con --no-verify.
//
// Medido antes del arreglo: analizar algo limpio, abortar, meter un SECRETO y
// commitear con --no-verify pegaba el trailer del análisis viejo. post-commit
// veía trailer, daba el commit por revisado y NO registraba el salto — un
// commit con un secreto dentro entraba al historial marcado como analizado por
// CodeGuard.
//
// El arreglo ata el run id al árbol analizado.
func TestUnTrailerNoSobreviveAUnCambioDeContenido(t *testing.T) {
	bin, repo, datos := prepararGanchos(t)

	escribir(t, repo, "app/limpio.py", "def suma(a: int, b: int) -> int:\n    return a + b\n")
	gitConEntorno(t, repo, datos, "add", "-A")

	// El análisis corre y deja el run id; el commit no llega a hacerse.
	salida, codigo := correrCon(t, bin, repo, datos, "hook", "pre-commit")
	if codigo != 0 {
		t.Fatalf("el análisis del cambio limpio bloqueó; no es el escenario:\n%s", salida)
	}
	if _, err := os.Stat(filepath.Join(repo, ".git", "codeguard-lastrun")); err != nil {
		t.Fatalf("el análisis no dejó run id: sin él no hay trampa que probar (%v)", err)
	}

	// Y ahora entra el secreto, DESPUÉS de que el análisis dijera que todo bien.
	escribir(t, repo, "config.env", elSecreto)
	gitConEntorno(t, repo, datos, "add", "-A")
	commitConNoVerify(t, repo, datos, "me lo salto tras abortar")

	mensaje := ultimoMensaje(t, repo)
	if id := runIDDelTrailer(mensaje); id != "" {
		t.Errorf("el commit se pegó el trailer %s de un análisis que NO cubría este contenido.\n"+
			"El secreto entró DESPUÉS del análisis, así que el historial afirma que este "+
			"commit pasó por CodeGuard; y como post-commit ve trailer, el salto tampoco "+
			"se registra.\n%s", id, mensaje)
	} else {
		t.Log("  ✓ contenido distinto al analizado: no hay trailer que robar")
	}
	if n := saltosRegistrados(t, datos); n != 1 {
		t.Errorf("se esperaba 1 salto registrado y hay %d: el salto quedaría invisible", n)
	} else {
		t.Log("  ✓ el salto quedó registrado")
	}
}

// Y la otra mitad, que es una DECISIÓN y no un descuido: con el mismo contenido
// el trailer sigue valiendo.
//
// Si lo que se commitea es exactamente lo que se analizó, el trailer dice la
// verdad —ese contenido pasó por CodeGuard— aunque el gancho se saltara en el
// segundo intento. Se prueba para que nadie lo "arregle" por error creyendo que
// es el mismo agujero de arriba.
func TestConElMismoContenidoElTrailerSigueValiendo(t *testing.T) {
	bin, repo, datos := prepararGanchos(t)

	escribir(t, repo, "app/limpio.py", "def suma(a: int, b: int) -> int:\n    return a + b\n")
	gitConEntorno(t, repo, datos, "add", "-A")

	salida, codigo := correrCon(t, bin, repo, datos, "hook", "pre-commit")
	if codigo != 0 {
		t.Fatalf("el análisis bloqueó y no debía:\n%s", salida)
	}

	// Sin tocar nada más: se commitea EXACTAMENTE lo analizado.
	commitConNoVerify(t, repo, datos, "el mismo contenido")

	id := runIDDelTrailer(ultimoMensaje(t, repo))
	if id == "" {
		t.Error("se perdió el trailer de un análisis que SÍ cubre este contenido: " +
			"el commit queda sin ligar a su análisis sin motivo")
	} else if !existeRun(t, datos, id) {
		t.Errorf("el trailer apunta al run %s y ese run no está en la base", id)
	} else {
		t.Logf("  ✓ mismo contenido, trailer válido (%s)", id)
	}
}

// ── andamiaje ────────────────────────────────────────────────────────────

// prepararGanchos deja un repo enrolado con los ganchos que instala el producto
// —no unos escritos por la prueba— apuntando al binario recién compilado.
func prepararGanchos(t *testing.T) (bin, repo, datos string) {
	t.Helper()
	if testing.Short() {
		t.Skip("hace commits de verdad con los ganchos instalados")
	}
	if runtime.GOOS != "windows" {
		t.Skip("CodeGuard sólo se distribuye para Windows")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("sin git no hay ganchos que disparar")
	}

	bin = construirBinario(t)
	repo = t.TempDir()
	datos = t.TempDir()

	for _, o := range [][]string{
		{"init", "-q"},
		{"config", "user.email", "e2e@ejemplo.local"},
		{"config", "user.name", "Verificación"},
		{"config", "commit.gpgsign", "false"},
	} {
		git(t, repo, o...)
	}
	escribir(t, repo, "LEEME.md", "repositorio de verificación de ganchos\n")
	escribir(t, repo, ".codeguard/config.yaml", configCon("2026.08.2", 50000))
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-q", "-m", "base", "--no-verify")

	// Los ganchos los instala el producto: si el shim que escribe `install`
	// dejara de resolver el binario, esta prueba tiene que enterarse.
	salida, codigo := correrCon(t, bin, repo, datos, "install")
	if codigo != 0 {
		t.Fatalf("codeguard install falló:\n%s", salida)
	}
	return bin, repo, datos
}

func commit(t *testing.T, repo, datos, mensaje string) {
	t.Helper()
	if salida, codigo := intentarCommit(t, repo, datos, mensaje); codigo != 0 {
		t.Fatalf("el commit falló y se esperaba que pasara:\n%s", salida)
	}
}

func intentarCommit(t *testing.T, repo, datos, mensaje string) (string, int) {
	t.Helper()
	return gitAislado(t, repo, datos, "commit", "-m", mensaje)
}

func commitConNoVerify(t *testing.T, repo, datos, mensaje string) {
	t.Helper()
	if salida, codigo := gitAislado(t, repo, datos, "commit", "--no-verify", "-m", mensaje); codigo != 0 {
		t.Fatalf("el commit con --no-verify falló:\n%s", salida)
	}
}

func gitConEntorno(t *testing.T, repo, datos string, args ...string) {
	t.Helper()
	if salida, codigo := gitAislado(t, repo, datos, args...); codigo != 0 {
		t.Fatalf("git %s falló:\n%s", strings.Join(args, " "), salida)
	}
}

// gitAislado corre git con el entorno de la prueba, para que los ganchos que
// git dispare hereden la base de la prueba y no la del usuario.
func gitAislado(t *testing.T, repo, datos string, args ...string) (string, int) {
	t.Helper()
	c := exec.Command("git", args...)
	c.Dir = repo
	c.Env = entornoAislado(t, datos)
	out, err := c.CombinedOutput()
	codigo := 0
	if ee, ok := err.(*exec.ExitError); ok {
		codigo = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("no se pudo ejecutar git %s: %v", strings.Join(args, " "), err)
	}
	return string(out), codigo
}

func ultimoMensaje(t *testing.T, repo string) string {
	t.Helper()
	c := exec.Command("git", "log", "-1", "--format=%B")
	c.Dir = repo
	out, err := c.Output()
	if err != nil {
		t.Fatalf("no se pudo leer el mensaje del último commit: %v", err)
	}
	return string(out)
}

func runIDDelTrailer(mensaje string) string {
	for _, l := range strings.Split(mensaje, "\n") {
		if i := strings.Index(l, "Codeguard-Run-Id:"); i >= 0 {
			return strings.TrimSpace(l[i+len("Codeguard-Run-Id:"):])
		}
	}
	return ""
}

func existeRun(t *testing.T, datos, runID string) bool {
	t.Helper()
	db := abrirBase(t, filepath.Join(datos, "codeguard", "codeguard.db"))
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM runs WHERE id = ?`, runID).Scan(&n); err != nil {
		t.Fatalf("no se pudo consultar el run %s: %v", runID, err)
	}
	return n > 0
}

func saltosRegistrados(t *testing.T, datos string) int {
	t.Helper()
	db := abrirBase(t, filepath.Join(datos, "codeguard", "codeguard.db"))
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM runs WHERE bypassed = 1`).Scan(&n); err != nil {
		t.Fatalf("no se pudieron contar los saltos: %v", err)
	}
	return n
}
