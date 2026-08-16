package main

import (
	"database/sql"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// N008: el bloqueo por secreto es el evento MÁS valioso del producto —"impedí
// que una credencial entrara al repo"— y era el único que no quedaba anotado en
// ninguna parte. La etapa de secretos corre en el proceso del hook y salía por
// os.Exit(1) antes de que existiera siquiera el run id, así que después de
// frenar una credencial de AWS `codeguard stats` seguía diciendo "sin hallazgos
// registrados todavía". Un commit limpio, en cambio, sí se registraba: la
// telemetría contaba los días buenos y se callaba los que importan.
//
// La prueba mira la BD y no la terminal a propósito: lo que se rompió no fue el
// mensaje —ese ya salía— sino la constancia. Si el dev no está mirando la
// terminal en ese instante, el bloqueo no existió para nadie más.
func TestUnBloqueoPorSecretoQuedaRegistrado(t *testing.T) {
	if soyElHijo() {
		hacerDeHook()
		return
	}
	if _, err := exec.LookPath("gitleaks"); err != nil {
		t.Skip("sin gitleaks no hay compuerta de secretos que pueda bloquear")
	}

	// La BD del hook cuelga de LOCALAPPDATA (dirDatos). Redirigirla mantiene la
	// del usuario fuera de esto, y da un sitio limpio donde el único run que
	// aparezca sea el de esta prueba.
	datos := t.TempDir()
	t.Setenv("LOCALAPPDATA", datos)

	repo, git := repoEnrolado(t)
	// Un id de clave de AWS: la regla aws-access-token de gitleaks lo reconoce
	// por su forma (AKIA + 16), sin depender de entropía ni de un rulepack
	// propio, así que la prueba mide la compuerta y no la suerte del detector.
	//
	// Va PARTIDO en dos literales, y no por gusto: entero, el gitleaks de ESTE
	// repo lo encuentra al commitear su propio código fuente y bloquea el commit.
	// Lo cazó la propia compuerta al preparar este archivo para subirlo, que es la
	// mejor demostración posible de que funciona. Misma convención que
	// patDePrueba en internal/pipeline. El valor que llega al fixture es idéntico.
	escribirEnRepo(t, filepath.Join(repo, "config.py"),
		"AWS_ACCESS_KEY_ID = \""+"AKIA"+"Z3XK7QW2NBVCXR4T"+"\"\n")
	git("add", ".")

	codigo, salida := correrHookEnHijo(t, repo)
	if codigo == 97 {
		t.Fatal("el hijo no pudo entrar al repo de prueba")
	}
	if codigo == 0 {
		t.Fatalf("el secreto tenía que bloquear el commit y salió 0:\n%s", salida)
	}

	ruta := filepath.Join(datos, "codeguard", "codeguard.db")
	if _, err := os.Stat(ruta); err != nil {
		t.Fatalf("SIN RASTRO: se bloqueó un commit por un secreto y la base de datos ni "+
			"siquiera llegó a crearse (%v).\nLa compuerta hizo su trabajo y no quedó "+
			"constancia en ningún sitio: `codeguard stats` seguirá diciendo que no hay "+
			"nada.\nsalida del hook:\n%s", err, salida)
	}
	db, err := sql.Open("sqlite", ruta)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var runID, verdict string
	var hallazgos int
	err = db.QueryRow(`SELECT id, verdict,
		(SELECT count(*) FROM findings WHERE findings.run_id = runs.id)
		FROM runs ORDER BY started_at DESC LIMIT 1`).Scan(&runID, &verdict, &hallazgos)
	if err == sql.ErrNoRows {
		t.Fatalf("SIN RASTRO: se bloqueó un commit por un secreto y no se registró ningún "+
			"run.\nEl único evento que demuestra que la compuerta sirve para algo es el "+
			"que no se anota.\nsalida del hook:\n%s", salida)
	}
	if err != nil {
		t.Fatalf("no se pudo consultar la BD: %v", err)
	}

	if verdict != "block" {
		t.Errorf("el run quedó como %q y el commit se bloqueó: el veredicto de la BD "+
			"tiene que decir lo mismo que la terminal", verdict)
	}
	// Sin los hallazgos dentro, el run dice "algo bloqueó" y no QUÉ: ni el panel
	// puede enseñarlo ni las métricas de reglas cuentan el secreto.
	if hallazgos == 0 {
		t.Errorf("el run %s se guardó sin ninguno de los secretos que lo bloquearon", runID)
	}
}
