package main

// La ruta del daemon es la que miente, y por eso es la que hay que probar.
//
// Con el daemon CAÍDO, res.Degraded siempre trae "daemon:offline", así que un
// análisis omitido caía en la rama PARCIAL. Con el daemon VIVO y sin capas
// caídas, Degraded llega vacío y caía en el `else` final: el "✓ listo — commit
// permitido" sobre cinco compuertas que no corrieron. O sea que el fallo sólo
// se manifestaba por el camino del commit de todos los días, que es justo el
// que no cubre una prueba sin daemon.
//
// El daemon de aquí es de mentira a propósito: lo que se está probando es cómo
// PRESENTA el hook la respuesta, no si el daemon la calcula bien —de eso se
// ocupa internal/daemon/motivo_test.go contra el Analyze de verdad—. Y siendo
// de mentira se puede fijar la respuesta exacta, incluido el Degraded vacío que
// destapa la rama del ✓.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codeguard/internal/ipc"
	"codeguard/internal/pipeline"
)

// daemonDeMentira atiende UNA consulta en el pipe de prueba y contesta lo que
// se le pase. Se levanta en el proceso del test; el hook corre en otro y le
// pregunta por el pipe, igual que en producción.
func daemonDeMentira(t *testing.T, resp ipc.Response) {
	t.Helper()
	ln, err := ipc.Listen()
	if err != nil {
		t.Fatalf("no se pudo levantar el daemon de mentira: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if _, err := ipc.ReadRequest(conn); err != nil {
			return
		}
		copia := resp
		_ = ipc.WriteResponse(conn, &copia)
	}()
}

// pipeDePrueba da un nombre único por prueba y proceso: dos corridas a la vez
// sobre el mismo nombre se robarían la conexión.
func pipeDePrueba(t *testing.T) {
	t.Helper()
	t.Setenv("CODEGUARD_PIPE", fmt.Sprintf(`\\.\pipe\codeguard-test-%s-%d`, t.Name(), os.Getpid()))
}

func TestPorLaRutaDelDaemonElMotivoLlegaALaTerminal(t *testing.T) {
	if soyElHijo() {
		hacerDeHook()
		return
	}
	pipeDePrueba(t)

	// La constante del pipeline, no una copia: el hook la reconoce por igualdad
	// exacta para elegir el tono, así que la prueba tiene que mandar por el pipe
	// lo mismo que manda el daemon de verdad.
	motivo := pipeline.MotivoTodoExcluido
	// Degraded VACÍO: es la condición exacta que llevaba al "✓ listo".
	daemonDeMentira(t, ipc.Response{Verdict: "skipped", Reason: motivo, Degraded: []string{}})

	repo, git := repoEnrolado(t)
	escribirEnRepo(t, filepath.Join(repo, "a.txt"), "contenido\n")
	git("add", ".")

	codigo, salida := correrHookEnHijo(t, repo)
	if codigo == 97 {
		t.Fatal("el hijo no pudo entrar al repo de prueba")
	}
	if codigo != 0 {
		t.Errorf("un análisis omitido no puede detener el commit (exit %d)\nsalida:\n%s", codigo, salida)
	}

	// La regresión del hallazgo original, sobre la rama que lo producía.
	if strings.Contains(salida, "formato/lint/tipos/reglas/migraciones ✓") {
		t.Errorf("el ✓ falso volvió por la ruta del daemon:\n%s", salida)
	}
	if strings.Contains(salida, "listo — commit permitido") {
		t.Errorf("el hook firmó «listo» sobre un análisis que no ocurrió:\n%s", salida)
	}

	// Y lo que añade esta pieza: el motivo cruza el pipe y se ve en la terminal.
	//
	// No se busca el literal de la constante. El hook REFORMULA el motivo de
	// exclusión a propósito —"todos los archivos tocados están excluidos" pasa a
	// "sin archivos que revisar: todos excluidos por la configuración"— porque
	// esa rama es una decisión del propio equipo y no una avería, y el tono
	// tiene que distinguirlas: un aviso que se aprende a ignorar arrastra
	// consigo al aviso serio. Atar el test al literal convertiría esa mejora de
	// redacción en un rojo, que es cómo un test acaba desactivado en vez de
	// arreglado.
	//
	// Lo que sí es contrato es que el motivo LLEGUE: la señal de que no llegó es
	// exactamente el texto de respaldo que el hook imprime cuando el campo viene
	// vacío, así que se comprueba su ausencia y que se nombra la causa concreta.
	if strings.Contains(salida, "el motivo no llegó hasta aquí") {
		t.Errorf("el motivo no cruzó el pipe: el daemon lo manda en Response.Reason y el hook\n"+
			"no lo copia al construir su pipeline.Result, así que se pierde en el último salto.\n"+
			"salida:\n%s", salida)
	}
	if !strings.Contains(salida, "excluid") {
		t.Errorf("el hook dijo que no se analizó nada pero no dijo POR QUÉ; se esperaba que\n"+
			"nombrara la exclusión (motivo del daemon: %q).\nsalida:\n%s", motivo, salida)
	}
	// El motivo tiene que llegar ENTERO, y esto lo comprueba sin fijar una sola
	// palabra de la redacción.
	//
	// El hook elige el tono comparando por igualdad exacta contra
	// pipeline.MotivoTodoExcluido, así que un motivo que llegue mutilado —un
	// truncado, un espacio de más, la redacción de otra versión— no se reconoce
	// y sale por la rama de avería, con su línea de alarma. Ausencia de alarma
	// significa entonces "llegó idéntico", que es la propiedad que interesa; y
	// como es una comprobación NEGATIVA, la frase neutra se puede reescribir
	// entera sin tocar esta prueba.
	//
	// De paso fija la mitad de producto: excluir rutas es una decisión del
	// propio equipo y no puede gastar la línea que hace falta para las averías.
	if strings.Contains(salida, "NO es una revisión limpia") {
		t.Errorf("el motivo no llegó tal cual (%q) o se trató una decisión de configuración\n"+
			"como si fuera una avería:\n%s", motivo, salida)
	}
}

// Un veredicto normal por la ruta del daemon no puede contagiarse de nada de
// esto: sigue diciendo lo de siempre.
func TestPorLaRutaDelDaemonUnVeredictoNormalNoCambia(t *testing.T) {
	if soyElHijo() {
		hacerDeHook()
		return
	}
	pipeDePrueba(t)
	daemonDeMentira(t, ipc.Response{Verdict: "pass", Degraded: []string{}})

	repo, git := repoEnrolado(t)
	escribirEnRepo(t, filepath.Join(repo, "a.txt"), "contenido\n")
	git("add", ".")

	codigo, salida := correrHookEnHijo(t, repo)
	if codigo != 0 {
		t.Errorf("un análisis limpio no puede detener el commit (exit %d)\nsalida:\n%s", codigo, salida)
	}
	if !strings.Contains(salida, "listo — commit permitido") {
		t.Errorf("un análisis que SÍ corrió y salió limpio tiene que decirlo:\n%s", salida)
	}
	if strings.Contains(salida, "SIN REVISAR") {
		t.Errorf("un análisis completo se anunció como omitido:\n%s", salida)
	}
}

// [13] del plan: un daemon que rechaza por protocolo incompatible no deja al
// dev sin análisis NI le pinta media revisión — el hook cae a la ruta local
// (la misma honesta de daemon:offline) con su propia etiqueta, que es
// política deliberada: el remedio es actualizar, no una cobertura rota.
func TestUnDaemonIncompatibleCaeALocalYNoPintaParcial(t *testing.T) {
	if soyElHijo() {
		hacerDeHook()
		return
	}
	pipeDePrueba(t)
	daemonDeMentira(t, ipc.Response{Verdict: "error",
		Reason: "protocolo incompatible: tu binario habla [2,3] y este daemon [1,1] — actualiza el que quedó atrás"})

	repo, git := repoEnrolado(t)
	escribirEnRepo(t, filepath.Join(repo, "notas.txt"), "texto sin nada que revisar\n")
	git("add", ".")

	codigo, salida := correrHookEnHijo(t, repo)
	if codigo != 0 {
		t.Errorf("el rechazo del daemon no puede costarle el commit al dev (exit %d):\n%s", codigo, salida)
	}
	if !strings.Contains(salida, "el agente rechazó la conexión") {
		t.Errorf("el rechazo estructurado no se dijo:\n%s", salida)
	}
	if !strings.Contains(salida, "listo — commit permitido") {
		t.Errorf("el análisis local completo merece su veredicto positivo:\n%s", salida)
	}
	if strings.Contains(salida, "— PARCIAL") {
		t.Errorf("despliegue mixto no es cobertura rota: PARCIAL aquí es mentira:\n%s", salida)
	}
}
