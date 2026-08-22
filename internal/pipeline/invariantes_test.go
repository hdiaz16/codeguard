package pipeline_test

// FASE 1 — Invariantes de seguridad.
//
// Lo que nunca puede pasar aunque todo lo demás funcione. Está escrito en la
// especificación y en Hardening; hasta aquí NO estaba demostrado ejecutando, y
// "está en la spec" es exactamente la clase de certeza que este proyecto lleva
// un mes descubriendo que no valía nada.
//
// Todas conducen el BINARIO REAL, por la misma razón que el arnés de motores:
// llamar al pipeline en proceso produce falsos negativos que el binario no
// tiene.

import (
	"database/sql"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// ── 1.1 · La baseline no puede suprimir un secreto ───────────────────────
//
// Es la única compuerta fail-closed del producto. Si la baseline pudiera
// taparla, bastaría un `codeguard baseline` distraído —o una línea pegada a
// mano en un archivo que se versiona— para desarmar lo único que no admite
// discusión.
//
// Hay DOS defensas y se comprueban por separado, porque una sola que funcione
// se ve igual que las dos:
//
//	a) `codeguard baseline` corre con Secrets:nil, así que un secreto no llega
//	   nunca a escribirse en baseline.txt.
//	b) El pipeline ignora las supresiones cuando el hallazgo viene de gitleaks,
//	   así que una huella METIDA A MANO tampoco surte efecto.
//
// La (b) es la que importa de verdad: baseline.txt es un archivo de texto que
// se versiona, y cualquiera puede pegar una línea.

func TestLaBaselineNoPuedeTaparUnSecreto(t *testing.T) {
	bin, repo := prepararInvariante(t)

	escribir(t, repo, "credenciales.py", elSecreto)
	git(t, repo, "add", "-A")

	// El gancho bloquea, que es el punto de partida.
	salida, codigo := correr(t, bin, repo, "hook", "pre-commit")
	if codigo == 0 {
		t.Fatalf("el gancho no bloqueó un secreto ni siquiera sin baseline:\n%s", salida)
	}

	// (a) Se intenta aceptarlo con el comando previsto para aceptar deuda.
	salida, _ = correr(t, bin, repo, "baseline")
	t.Logf("  salida de `codeguard baseline`: %s", primeraLinea(salida))

	salida, codigo = correr(t, bin, repo, "hook", "pre-commit")
	if codigo == 0 {
		t.Errorf("`codeguard baseline` DESARMÓ la compuerta de secretos.\n%s", salida)
	} else {
		t.Log("  ✓ (a) tras `codeguard baseline`, el secreto sigue bloqueando")
	}

	// (b) El ataque de verdad: la huella exacta del secreto, escrita a mano en
	// el archivo que se versiona.
	huella := huellaDelSecreto(t, bin, repo)
	if huella == "" {
		t.Fatal("no se pudo obtener la huella del secreto: sin ella esta prueba no prueba nada")
	}
	rutaBaseline := filepath.Join(repo, ".codeguard", "baseline.txt")
	previo, _ := os.ReadFile(rutaBaseline)
	if err := os.WriteFile(rutaBaseline, append(previo, []byte(huella+"\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("  huella del secreto metida a mano en baseline.txt: %s…", huella[:16])

	salida, codigo = correr(t, bin, repo, "hook", "pre-commit")
	if codigo == 0 {
		t.Errorf("una huella escrita a mano en baseline.txt DESARMÓ la compuerta de secretos.\n"+
			"baseline.txt es un archivo de texto versionado: cualquiera puede pegar una línea.\n%s", salida)
	} else {
		t.Log("  ✓ (b) con la huella del secreto en baseline.txt, sigue bloqueando")
	}
}

// La MISMA garantía por la ruta del CI, que es otra defensa distinta.
//
// Esta prueba nació de un control que salió mal, y por eso existe. Se rompió a
// propósito la exención del pipeline (`f.Engine != "gitleaks"`) esperando que
// la prueba del gancho se pusiera roja… y siguió verde. Leyendo el código
// después: en el gancho, gitleaks corre aparte y sale con os.Exit(1) ANTES de
// que el pipeline llegue a mirar las supresiones. O sea que la prueba del
// gancho no cubría esa línea en absoluto.
//
// Son dos defensas independientes y hay que verificarlas por separado:
//
//	gancho → bloquea antes de las supresiones (cmd/codeguard/hook.go)
//	CI     → el pipeline recibe Secrets Y Suppressions a la vez, y ahí la
//	         exención es lo único que separa un secreto de quedar suprimido
//
// Sin esta prueba, alguien podría borrar la exención mañana, ver toda la suite
// en verde, y dejar el CI aceptando secretos por baseline.
func TestPorLaRutaDelCIUnSecretoTampocoSeSuprime(t *testing.T) {
	bin, repo := prepararInvariante(t)

	base := strings.TrimSpace(gitSalida(t, repo, "rev-parse", "HEAD"))
	escribir(t, repo, "credenciales.py", elSecreto)
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-q", "-m", "con el secreto", "--no-verify")

	// Primero: sin baseline, el CI bloquea. Si no, la prueba no mide nada.
	sarif := filepath.Join(t.TempDir(), "a.sarif")
	salida, codigo := correr(t, bin, repo, "ci", "--base", base, "--head", "HEAD", "--out", sarif)
	if codigo == 0 {
		t.Fatalf("el CI no bloqueó un secreto ni siquiera sin baseline:\n%s", salida)
	}
	huella := huellaDeSecretoEnSarif(t, sarif)
	if huella == "" {
		t.Fatalf("el SARIF del CI no traía la huella del secreto; sin ella no hay ataque que probar:\n%s", salida)
	}

	// Y ahora el ataque: su huella, en la baseline que se versiona.
	escribir(t, repo, ".codeguard/baseline.txt", huella+"\n")
	t.Logf("  huella del secreto puesta en baseline.txt: %s…", huella[:16])

	salida, codigo = correr(t, bin, repo, "ci", "--base", base, "--head", "HEAD",
		"--out", filepath.Join(t.TempDir(), "b.sarif"))
	if codigo == 0 {
		t.Errorf("por la ruta del CI, una huella en baseline.txt SUPRIMIÓ un secreto.\n"+
			"El CI es la última compuerta antes de main: si acepta secretos por baseline, "+
			"no queda ninguna.\n%s", salida)
	} else {
		t.Log("  ✓ el CI sigue bloqueando con la huella del secreto en la baseline")
	}
}

// ── 1.2 · Suprime lo preexistente, y SÓLO lo preexistente ────────────────
//
// "Sólo lo nuevo bloquea" es lo que hace adoptable el producto sobre un repo
// con años encima. Si la huella fuera demasiado laxa, aceptar un hallazgo
// aceptaría también los que vengan después — y el equipo no se enteraría,
// porque lo que vería es un commit pasando.
//
// La huella es sha256(regla + ruta + contenido de la línea): la prueba mete el
// MISMO defecto en OTRO archivo, que es el caso que distingue una huella sana
// de una que sólo mira la regla.

func TestLaBaselineSuprimeSoloLoPreexistente(t *testing.T) {
	bin, repo := prepararInvariante(t)

	const defecto = "import subprocess\n\n\ndef ejecutar(orden):\n" +
		"    return subprocess.run(orden, shell=True)\n"

	escribir(t, repo, "viejo.py", defecto)
	git(t, repo, "add", "-A")

	salidaInicial, codigo := correr(t, bin, repo, "hook", "pre-commit")
	exigirQueLoAnaliceElBinarioDePrueba(t, salidaInicial)
	if codigo == 0 {
		t.Fatal("el defecto de partida no bloquea: la prueba no mediría nada")
	}

	salida, _ := correr(t, bin, repo, "baseline")
	if !strings.Contains(salida, "baseline escrita") {
		t.Fatalf("no se escribió la baseline:\n%s", salida)
	}

	salida, codigo = correr(t, bin, repo, "hook", "pre-commit")
	if codigo != 0 {
		t.Fatalf("tras aceptarlo en la baseline debería pasar, y no pasó:\n%s", salida)
	}
	t.Log("  ✓ lo preexistente deja de bloquear")

	// Y otra vez, que es cuando el caché está caliente.
	//
	// Esta segunda corrida no es por si acaso: el caché serializa los hallazgos
	// a JSON, y finding.Finding marca Fingerprint como `json:"-"`, así que al
	// acertar devolvía hallazgos SIN HUELLA. Una huella vacía no casa con
	// ninguna baseline, o sea que la deuda aceptada resucitaba en la segunda
	// corrida — justo cuando el desarrollador ya había dado el asunto por
	// zanjado. La primera corrida siempre pasaba, así que una prueba que sólo
	// mirara una vez habría certificado esto como correcto.
	salida, codigo = correr(t, bin, repo, "hook", "pre-commit")
	if codigo != 0 {
		t.Fatalf("en la SEGUNDA corrida —ya con el caché caliente— la deuda aceptada "+
			"volvió a bloquear. La baseline sólo funciona hasta que el caché acierta:\n%s", salida)
	}
	t.Log("  ✓ y sigue sin bloquear con el caché caliente")

	// Ahora el MISMO defecto, en OTRO archivo. Es nuevo, así que bloquea.
	escribir(t, repo, "nuevo.py", defecto)
	git(t, repo, "add", "-A")

	salida, codigo = correr(t, bin, repo, "hook", "pre-commit")
	if codigo == 0 {
		t.Errorf("el MISMO defecto en un archivo NUEVO no bloqueó: la baseline está "+
			"suprimiendo por regla y no por sitio, así que aceptar un hallazgo acepta "+
			"todos los futuros de esa regla.\n%s", salida)
	} else {
		t.Log("  ✓ el mismo defecto en otro archivo SÍ bloquea")
	}
}

// ── 1.3 · El bypass queda registrado ─────────────────────────────────────
//
// `--no-verify` no ejecuta pre-commit —eso lo decide git, no nosotros— pero SÍ
// ejecuta prepare-commit-msg. Ahí es donde el salto puede quedar anotado.
//
// Importa para la 27001 y para el equipo: un bypass que no deja rastro es
// indistinguible de un análisis limpio cuando alguien mira el historial.

func TestElBypassDejaRastro(t *testing.T) {
	bin, repo := prepararInvariante(t)

	datos := t.TempDir()

	escribir(t, repo, "credenciales.py", elSecreto)
	git(t, repo, "add", "-A")

	// Se instalan los ganchos de verdad: sin ellos, `git commit` no llama a
	// nada y la prueba mediría el vacío.
	if salida, codigo := correr(t, bin, repo, "install"); codigo != 0 {
		t.Skipf("no se pudieron instalar los ganchos en el repo de prueba: %s", salida)
	}

	c := exec.Command("git", "commit", "-q", "-m", "salto deliberado", "--no-verify")
	c.Dir = repo
	c.Env = entornoAislado(t, datos)
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("el commit con --no-verify falló: %v\n%s", err, out)
	}

	// El rastro NO está en el mensaje del commit: el trailer lo pone
	// prepare-commit-msg leyendo el run id que deja pre-commit, y con
	// --no-verify pre-commit no corrió, así que no hay run id que poner.
	//
	// Está en la base local, y lo escribe post-commit —que --no-verify NO se
	// salta— al ver un commit sin trailer. La primera versión de esta prueba
	// miraba el mensaje y la salida de `stats`, no encontraba nada, y estuvo a
	// punto de reportar como fallo del producto algo que sólo era mirar donde
	// no era.
	n := runsConBypass(t, filepath.Join(datos, "codeguard", "codeguard.db"))
	if n == 0 {
		t.Errorf("un commit con --no-verify sobre un SECRETO no quedó registrado como bypass.\n"+
			"Un salto que no deja rastro es indistinguible de un análisis limpio cuando "+
			"alguien mira el historial, y es lo primero que pide un auditor.\n"+
			"mensaje del commit: %q", strings.TrimSpace(gitSalida(t, repo, "log", "-1", "--format=%B")))
	} else {
		t.Logf("  ✓ el salto quedó registrado: %d run(s) con bypassed=1", n)
	}
}

// runsConBypass cuenta los saltos anotados en la base local.
//
// Se consulta la BD directamente porque hoy ningún comando los enseña — y eso
// es un hueco conocido y anotado (el bypass se registra, pero nadie lo revisa:
// no hay informe ni umbral). La prueba comprueba que el DATO existe; que
// alguien lo mire es otra tarea.
func runsConBypass(t *testing.T, rutaDB string) int {
	t.Helper()
	if _, err := os.Stat(rutaDB); err != nil {
		t.Fatalf("no se creó la base local en %s: %v", rutaDB, err)
	}
	db, err := sql.Open("sqlite", rutaDB+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("no se pudo abrir la base: %v", err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM runs WHERE bypassed = 1").Scan(&n); err != nil {
		t.Fatalf("no se pudo consultar los runs: %v", err)
	}
	return n
}

// entornoAislado manda la base local y los datos de CodeGuard a un directorio
// de la prueba, para no escribir en la base real de quien la corre.
//
// Los motores se siguen encontrando: se resuelven por PATH, no por
// LOCALAPPDATA.
func entornoAislado(t *testing.T, datos string) []string {
	t.Helper()
	return entornoConPipe(t, datos, `\\.\pipe\codeguard-verificacion-sin-daemon`)
}

// entornoConPipe aísla además el pipe.
//
// Es parámetro porque la fase 5 necesita las DOS rutas: casi todas las pruebas
// apuntan a un pipe que no existe —para que conteste el binario recién
// compilado y no el daemon instalado en la máquina— y la prueba del daemon
// levanta el suyo y apunta ahí.
func entornoConPipe(t *testing.T, datos, pipe string) []string {
	t.Helper()
	var out []string
	for _, e := range sinGOROOT(os.Environ()) {
		u := strings.ToUpper(e)
		if strings.HasPrefix(u, "LOCALAPPDATA=") || strings.HasPrefix(u, "CODEGUARD_PIPE=") {
			continue
		}
		// GITHUB_ACTIONS y CI fuera SIEMPRE: el producto clasifica el run como
		// "ci" al verlas, y en el runner de GitHub están en el entorno GLOBAL —
		// se colaban a la ruta del GANCHO, que registraba sus hallazgos como
		// "ci", y la paridad encontraba cero filas "local" que comparar. En una
		// máquina de desarrollo no existen y el fallo era invisible; se
		// reprodujo en local exportándolas (GITHUB_ACTIONS=true → rojo).
		// correrComoCI las vuelve a poner a propósito para SU ruta.
		if strings.HasPrefix(u, "GITHUB_ACTIONS=") || strings.HasPrefix(u, "CI=") {
			continue
		}
		out = append(out, e)
	}
	return append(out, "LOCALAPPDATA="+datos, "CODEGUARD_PIPE="+pipe)
}

// ── andamiaje ────────────────────────────────────────────────────────────

func prepararInvariante(t *testing.T) (bin, repo string) {
	t.Helper()
	if testing.Short() {
		t.Skip("compila el binario y corre motores de verdad")
	}
	if runtime.GOOS != "windows" {
		t.Skip("CodeGuard sólo se distribuye para Windows")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("sin git no hay nada que analizar")
	}
	return construirBinario(t), repoBase(t)
}

// exigirQueLoAnaliceElBinarioDePrueba comprueba que la corrida NO la contestó
// el daemon instalado en la máquina.
//
// `correr` apunta CODEGUARD_PIPE a un pipe inexistente para forzar el análisis
// en proceso, pero eso es una precaución que hay que VERIFICAR: si mañana
// alguien cambia el nombre de la variable, o el gancho encuentra el daemon por
// otro camino, las pruebas volverían a medir un binario distinto del que se
// quiere probar — y seguirían verdes.
func exigirQueLoAnaliceElBinarioDePrueba(t *testing.T, salida string) {
	t.Helper()
	if !strings.Contains(salida, "daemon:offline") && !strings.Contains(salida, "en frío") {
		t.Fatalf("esta corrida la contestó el daemon instalado, no el binario compilado: "+
			"la prueba estaría midiendo otra versión.\n%s", salida)
	}
}

// huellaDelSecreto saca la huella REAL que el producto le asigna al secreto,
// del SARIF de `codeguard ci` — que es la única ruta que corre la etapa de
// secretos y además publica las huellas.
//
// Calcularla a mano en la prueba sería reimplementar el producto y comprobar
// que mi copia coincide con mi copia.
func huellaDelSecreto(t *testing.T, bin, repo string) string {
	t.Helper()
	base := strings.TrimSpace(gitSalida(t, repo, "rev-parse", "HEAD"))

	// `ci` compara dos commits, así que hay que commitear el secreto para poder
	// preguntarle su huella… y DESHACERLO después.
	//
	// Sin el reset, la prueba se engañaba a sí misma de la peor manera: al
	// commitear, el índice queda vacío, el gancho no tiene nada que analizar y
	// pasa — y eso se leía como "una huella en baseline.txt desarmó la
	// compuerta de secretos", que habría sido un hallazgo grave y falso. El
	// reset --soft devuelve el secreto al índice, exactamente como estaba.
	git(t, repo, "commit", "-q", "-m", "con el secreto", "--no-verify")
	defer func() {
		git(t, repo, "reset", "--soft", base)
		if idx := gitSalida(t, repo, "diff", "--cached", "--name-only"); !strings.Contains(idx, "credenciales.py") {
			t.Fatalf("tras recuperar el estado, el secreto NO volvió al índice (%q): "+
				"la prueba siguiente mediría un repo vacío", strings.TrimSpace(idx))
		}
	}()

	sarif := filepath.Join(t.TempDir(), "salida.sarif")
	salida, _ := correr(t, bin, repo, "ci", "--base", base, "--head", "HEAD",
		"--out", sarif, "--shadow")

	if _, err := os.Stat(sarif); err != nil {
		t.Logf("no se pudo leer el SARIF (%v); salida del comando:\n%s", err, salida)
		return ""
	}
	return huellaDeSecretoEnSarif(t, sarif)
}

type documentoSarif struct {
	Runs []struct {
		Results []struct {
			RuleID              string            `json:"ruleId"`
			PartialFingerprints map[string]string `json:"partialFingerprints"`
		} `json:"results"`
	} `json:"runs"`
}

// huellaDeSecretoEnSarif saca la huella que el PRODUCTO le asignó al secreto.
//
// Se lee del SARIF y no se recalcula en la prueba a propósito: reimplementar
// aquí sha256(regla+ruta+línea) comprobaría que mi copia coincide con mi copia,
// no que la baseline resiste a la huella de verdad.
func huellaDeSecretoEnSarif(t *testing.T, ruta string) string {
	t.Helper()
	raw, err := os.ReadFile(ruta)
	if err != nil {
		t.Logf("SARIF ilegible: %v", err)
		return ""
	}
	var doc documentoSarif
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Logf("SARIF ilegible: %v", err)
		return ""
	}
	var vistas []string
	for _, r := range doc.Runs {
		for _, res := range r.Results {
			vistas = append(vistas, res.RuleID)
			id := strings.ToLower(res.RuleID)
			if strings.Contains(id, "gitleaks") || strings.Contains(id, "secret") {
				var claves []string
				for k := range res.PartialFingerprints {
					claves = append(claves, k)
				}
				sort.Strings(claves)
				if len(claves) > 0 {
					return res.PartialFingerprints[claves[0]]
				}
			}
		}
	}
	t.Logf("el SARIF no traía ningún hallazgo de secretos; reglas vistas: %s", strings.Join(vistas, ", "))
	return ""
}

func gitSalida(t *testing.T, repo string, args ...string) string {
	t.Helper()
	c := exec.Command("git", args...)
	c.Dir = repo
	out, err := c.Output()
	if err != nil {
		t.Fatalf("git %s: %v", strings.Join(args, " "), err)
	}
	return string(out)
}

func primeraLinea(s string) string {
	if i := strings.IndexByte(s, '\n'); i > 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}
