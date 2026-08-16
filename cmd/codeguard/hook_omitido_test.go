package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codeguard/internal/ipc"
)

// Un análisis que no miró NADA no puede presentarse como una revisión.
//
// El hook decide el mensaje de la terminal con res.BlockingFindings y
// len(res.Degraded), y NUNCA lee res.Verdict. Así, un veredicto Skipped —que
// significa "ni siquiera empezamos"— cae en las mismas ramas que un análisis
// completo: si no hay capas degradadas sale el "✓ listo — commit permitido", y
// si las hay sale "commit permitido sobre lo que SÍ se revisó", que promete una
// revisión parcial donde no hubo ninguna. El res.Reason que explica el motivo
// existe y está relleno, pero el hook no lo imprime en ningún sitio: sólo lo
// enseña printSummary del camino de CI (main.go:161).
//
// Es la lección de H009 otra vez: la función hacía lo correcto y el usuario veía
// otra cosa.

// repoConTodoExcluido deja un repo enrolado cuya configuración excluye todo lo
// que se va a preparar. Es el único camino que hoy llega a la salida del hook
// con veredicto Skipped: git sí ve los archivos (así que el hook no sale por
// "nada preparado"), y es el pipeline el que se queda sin nada que mirar.
func repoConTodoExcluido(t *testing.T) (repo string, git func(args ...string)) {
	t.Helper()
	repo, git = repoEnrolado(t)
	escribirEnRepo(t, filepath.Join(repo, ".codeguard", "config.yaml"),
		"version: 1\nrulepack: \"2026.08.2\"\npaths:\n  exclude:\n    - \"vendor/**\"\n")
	// La config se commitea antes de preparar nada más. Si se quedara
	// preparada, ella misma sería un archivo NO excluido y el pipeline tendría
	// algo que mirar: la prueba dejaría de probar lo que dice probar.
	git("add", ".codeguard")
	git("commit", "-qm", "config de prueba")
	return repo, git
}

// sinDaemon apunta el canal a un pipe que nadie escucha, para que la prueba
// recorra siempre la misma rama. Sin esto el resultado dependería de si hay un
// daemon vivo en la máquina que corre los tests.
func sinDaemon(t *testing.T) {
	t.Helper()
	t.Setenv("CODEGUARD_PIPE", `\\.\pipe\codeguard-test-inexistente-omitido`)
}

func TestUnAnalisisOmitidoNoSePresentaComoRevision(t *testing.T) {
	if soyElHijo() {
		hacerDeHook()
		return
	}
	sinDaemon(t)

	repo, git := repoConTodoExcluido(t)
	escribirEnRepo(t, filepath.Join(repo, "vendor", "lib.go"), "package vendor\n\nfunc F() {}\n")
	git("add", "vendor")

	codigo, salida := correrHookEnHijo(t, repo)
	if codigo == 97 {
		t.Fatal("el hijo no pudo entrar al repo de prueba")
	}

	// No se bloquea: que todo esté excluido es una decisión del propio equipo,
	// no una avería. Asustar aquí sería el camino más corto a que desinstalen
	// el agente.
	if codigo != 0 {
		t.Errorf("un repo con todo excluido no puede detener el commit (exit %d)\nsalida:\n%s", codigo, salida)
	}

	// Lo que no puede decir: que revisó algo.
	if strings.Contains(salida, "listo — commit permitido") {
		t.Errorf("el hook firmó «listo — commit permitido» sin haber analizado nada:\n%s", salida)
	}
	if strings.Contains(salida, "commit permitido sobre lo que SÍ se revisó") {
		t.Errorf("el hook dijo que revisó una parte, y no revisó NADA:\n%s", salida)
	}
	if strings.Contains(salida, "formato/lint/tipos/reglas/migraciones ✓") {
		t.Errorf("el hook puso el ✓ a cinco compuertas que no llegaron a correr:\n%s", salida)
	}

	// Y lo que sí tiene que decir: que no se revisó, y por qué.
	if !strings.Contains(salida, "— SIN REVISAR") {
		t.Errorf("el hook no dijo que no había revisado:\n%s", salida)
	}
	if !strings.Contains(salida, "todos excluidos por la configuración") {
		t.Errorf("el hook no dijo POR QUÉ no se revisó nada:\n%s", salida)
	}
	// En tono NEUTRO: excluir rutas es una decisión del propio equipo y no hay
	// nada que arreglar. La línea de alarma está reservada a lo que sí es
	// avería, porque repetida en cada commit deja de leerse — y es la misma
	// línea que tiene que funcionar cuando de verdad haya algo roto.
	if strings.Contains(salida, "NO es una revisión limpia") {
		t.Errorf("gastó la línea de alarma en una decisión de configuración:\n%s", salida)
	}
}

// Y la cara opuesta del tono: cuando el motivo SÍ es una avería, la línea
// fuerte tiene que estar. Es la mitad que impide "arreglar" el ruido callando
// también lo que hay que arreglar.
//
// El caso se monta por la ruta del daemon porque es la única que lo produce: el
// hook sale antes si la config no se lee en SU proceso, y este motivo lo
// redacta el daemon cuando la config cambió entre las dos lecturas.
func TestUnOmitidoPorAveriaSiLlevaLaLineaFuerte(t *testing.T) {
	if soyElHijo() {
		hacerDeHook()
		return
	}
	pipeDePrueba(t)
	daemonDeMentira(t, ipc.Response{
		Verdict:  "skipped",
		Reason:   "no se pudo leer .codeguard/config.yaml: config.yaml no coincide con el esquema",
		Degraded: []string{},
	})

	repo, git := repoEnrolado(t)
	escribirEnRepo(t, filepath.Join(repo, "a.txt"), "contenido\n")
	git("add", ".")

	codigo, salida := correrHookEnHijo(t, repo)
	if codigo != 0 {
		t.Errorf("ni siquiera una config ilegible bloquea el commit (exit %d):\n%s", codigo, salida)
	}
	if !strings.Contains(salida, "no se analizó nada: no se pudo leer") {
		t.Errorf("no dijo cuál era la avería:\n%s", salida)
	}
	if !strings.Contains(salida, "NO es una revisión limpia") {
		t.Errorf("una avería tiene que llevar la línea fuerte; si se calla aquí, "+
			"el aviso no existe para nadie:\n%s", salida)
	}
	if strings.Contains(salida, "todos excluidos por la configuración") {
		t.Errorf("presentó una avería como una decisión del equipo:\n%s", salida)
	}
}

// La otra mitad, para no «arreglarlo» rompiendo el camino de todos los días: un
// commit normal tiene que seguir con su veredicto de siempre. La rama nueva
// mira el veredicto, así que no puede secuestrar a los que no son Skipped.
func TestUnCommitNormalConservaSuVeredicto(t *testing.T) {
	if soyElHijo() {
		hacerDeHook()
		return
	}
	sinDaemon(t)

	repo, git := repoEnrolado(t)
	escribirEnRepo(t, filepath.Join(repo, "notas.txt"), "texto sin nada que revisar\n")
	git("add", ".")

	codigo, salida := correrHookEnHijo(t, repo)
	if codigo == 97 {
		t.Fatal("el hijo no pudo entrar al repo de prueba")
	}
	if codigo != 0 {
		t.Errorf("un commit legítimo no puede detenerse (exit %d)\nsalida:\n%s", codigo, salida)
	}
	if strings.Contains(salida, "SIN REVISAR") {
		t.Errorf("un análisis que SÍ corrió se anunció como omitido:\n%s", salida)
	}
	if !strings.Contains(salida, "secretos ✓") {
		t.Errorf("la compuerta de secretos tenía que correr y firmar:\n%s", salida)
	}
	// Y el veredicto POSITIVO, afirmado y no sólo supuesto: sin esto la prueba
	// pasaba igual con un hook que no imprimiera veredicto ninguno, que es la
	// forma silenciosa de romperlo.
	//
	// Este camino va sin daemon, así que Degraded trae al menos "daemon:offline"
	// y el veredicto legítimo es PARCIAL — el ✓ limpio por la ruta del daemon lo
	// fija TestPorLaRutaDelDaemonUnVeredictoNormalNoCambia.
	if !strings.Contains(salida, "— PARCIAL") {
		t.Errorf("con el daemon caído el veredicto legítimo es PARCIAL, y no se anunció:\n%s", salida)
	}
	if !strings.Contains(salida, "commit permitido sobre lo que SÍ se revisó") {
		t.Errorf("el hook no dijo sobre qué permitió el commit:\n%s", salida)
	}
	// El motivo de omisión no puede aparecer en un análisis que sí corrió.
	if strings.Contains(salida, "no se analizó nada") ||
		strings.Contains(salida, "sin archivos que revisar") {
		t.Errorf("un análisis que corrió trajo el mensaje del omitido:\n%s", salida)
	}
}

// Un repo no enrolado sigue saliendo callado: el hook vuelve en la etapa 0, muy
// antes del veredicto, y ese silencio es deliberado — el hook se instala en
// máquinas con repos ajenos y no puede ponerse a hablar en cada uno.
func TestUnRepoNoEnroladoSigueSaliendoCallado(t *testing.T) {
	if soyElHijo() {
		hacerDeHook()
		return
	}
	sinDaemon(t)

	repo, git := repoEnrolado(t)
	if err := os.Remove(filepath.Join(repo, ".codeguard", "config.yaml")); err != nil {
		t.Fatal(err)
	}
	escribirEnRepo(t, filepath.Join(repo, "a.txt"), "x\n")
	git("add", ".")

	codigo, salida := correrHookEnHijo(t, repo)
	if codigo != 0 {
		t.Errorf("un repo no enrolado no puede detener el commit (exit %d)\nsalida:\n%s", codigo, salida)
	}
	if strings.Contains(salida, "CodeGuard") {
		t.Errorf("un repo no enrolado tiene que salir en silencio, y habló:\n%s", salida)
	}
}
