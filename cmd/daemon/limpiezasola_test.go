package main

import (
	"os"
	"path/filepath"
	"testing"

	"codeguard/internal/ipc"
	"codeguard/internal/registry"
)

// Abrir el panel tiene que recalcular la lista de proyectos.
//
// Esto salió de usar el producto, no de leerlo: tras borrar del disco 25 repos
// de prueba, el panel seguía listándolos, y la única forma de limpiarlo fue
// parar el agente, editar repos.json a mano y volver a arrancarlo. Ningún
// desarrollador va a hacer eso, ni tiene por qué saber que ese archivo existe.
//
// La limpieza YA existía —listaProyectosLocked comprueba el disco y da de baja
// lo que no está—, pero abrir el panel no la ejecutaba: con un contexto activo
// ya guardado se devolvía esa copia tal cual. Así que la lista sólo se
// refrescaba al analizar o al cambiar de proyecto, y un repo borrado seguía en
// pantalla toda la vida del agente.
func TestAbrirElPanelDaDeBajaLoQueYaNoEstaEnDisco(t *testing.T) {
	vivo := repoEnDisco(t, "vivo")
	muerto := repoEnDisco(t, "muerto")

	e, olvidados := escritorioDePrueba([]registry.Repo{vivo, muerto})
	e.tray = &trayState{}
	var publicados []*panelPayload
	e.emitir = func(_ string, datos any) {
		if p, ok := datos.(*panelPayload); ok {
			publicados = append(publicados, p)
		}
	}
	// Un análisis previo deja contexto activo: es el caso en el que el atajo
	// devolvía la foto vieja, o sea el único que importa.
	e.alComandoDeLaCLI("repo-enrolado", &ipc.Request{RepoRoot: filepath.FromSlash(vivo.Root)})
	if p := e.activoActual(); p == nil || len(p.OtrosRepos) != 2 {
		t.Fatalf("de partida deben verse los dos proyectos: %+v", p)
	}

	// El usuario borra la carpeta por fuera. El agente sigue corriendo.
	if err := os.RemoveAll(filepath.FromSlash(muerto.Root)); err != nil {
		t.Fatal(err)
	}

	// Abre el panel. Sin reiniciar nada, sin commitear nada.
	p := e.sembrarDesdeRegistro()
	if p == nil {
		t.Fatal("el panel se quedó sin contexto tras la limpieza")
	}
	for _, r := range p.OtrosRepos {
		if r.Nombre == "muerto" {
			t.Errorf("el repo borrado sigue en el panel al abrirlo: %+v\n"+
				"La única salida sería reiniciar el agente a mano, que es lo que "+
				"esta prueba existe para impedir.", p.OtrosRepos)
		}
	}
	if len(p.OtrosRepos) != 1 {
		t.Errorf("debe quedar sólo el vivo, quedaron %+v", p.OtrosRepos)
	}
	// Y se olvida también del REGISTRO: si sólo saliera de la memoria,
	// volvería a aparecer en cuanto el agente se reiniciara.
	if len(*olvidados) == 0 {
		t.Error("el repo borrado no se dio de baja del registro: reaparecería al reiniciar")
	}
}

// El caso peor del mismo camino: el que desaparece es el proyecto ACTIVO.
// Ahí no basta con quitarlo de la lista — hay que soltar el contexto y mostrar
// otro, porque enseñar el estado de una carpeta que ya no existe es peor que
// no enseñar nada.
func TestSiDesapareceElProyectoActivoElPanelPasaAOtro(t *testing.T) {
	activo := repoEnDisco(t, "activo")
	otro := repoEnDisco(t, "otro")

	e, _ := escritorioDePrueba([]registry.Repo{activo, otro})
	e.tray = &trayState{}
	e.emitir = func(string, any) {}
	e.alComandoDeLaCLI("repo-enrolado", &ipc.Request{RepoRoot: filepath.FromSlash(activo.Root)})

	if err := os.RemoveAll(filepath.FromSlash(activo.Root)); err != nil {
		t.Fatal(err)
	}

	p := e.sembrarDesdeRegistro()
	if p == nil {
		t.Fatal("quedaba otro proyecto: el panel no puede quedarse vacío")
	}
	if p.Repo == "activo" {
		t.Errorf("el panel sigue mostrando el proyecto borrado: %+v", p)
	}
	if p.Repo != "otro" {
		t.Errorf("debía pasar al proyecto que sí existe, mostró %q", p.Repo)
	}
}
