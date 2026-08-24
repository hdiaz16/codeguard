package main

import (
	"path/filepath"
	"sync"
	"testing"

	"codeguard/internal/ipc"
	"codeguard/internal/registry"
)

// El fallo de la 1.9.3: `codeguard init` enrolaba el repo, escribía repos.json y
// decía LISTO, pero el panel no lo mostraba nunca —ni cerrándolo y abriéndolo—
// porque init no le hablaba al daemon y el único camino que relee el registro
// (sembrarDesdeRegistro, al abrirse el panel) se rinde en cuanto YA hay un
// contexto activo, que es el caso de cualquiera que no acabe de instalar.
//
// Por eso la prueba parte de un proyecto ya en pantalla: con el escritorio
// recién arrancado pasaría por el sembrado y no probaría nada.
func TestComandoRepoEnroladoActivaElRecienEnroladoAunqueYaHubieraOtroEnPantalla(t *testing.T) {
	viejo := repoEnDisco(t, "alfa")
	nuevo := repoEnDisco(t, "portal-cliente")
	e, _ := escritorioDePrueba([]registry.Repo{viejo})
	e.tray = &trayState{} // sin bandeja ni burbuja: aquí sólo se observa lo que se publica
	var mu sync.Mutex
	var publicados []*panelPayload
	e.emitir = func(nombre string, datos any) {
		if nombre != "analysis" {
			return
		}
		p, ok := datos.(*panelPayload)
		if !ok {
			t.Errorf("el panel espera un panelPayload en analysis, llegó %T", datos)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		publicados = append(publicados, p)
	}

	// Ya hay un proyecto al frente.
	e.cambiarDeProyecto(viejo.Root)
	if e.activo == nil || e.activo.RepoRoot != viejo.Root {
		t.Fatalf("la prueba necesita un contexto activo previo, quedó %+v", e.activo)
	}

	// `codeguard init` ya escribió repos.json y avisa por el pipe. La ruta llega
	// como la da Windows: si el despacho no la normaliza, la búsqueda en
	// porProyecto falla y el comando se vuelve un no-op silencioso.
	e.cargarRepos = func() []registry.Repo { return []registry.Repo{viejo, nuevo} }
	e.alComandoDeLaCLI("repo-enrolado", &ipc.Request{RepoRoot: filepath.FromSlash(nuevo.Root)})

	if e.activo == nil || e.activo.RepoRoot != nuevo.Root {
		t.Fatalf("el repo recién enrolado debe quedar como contexto activo, quedó %+v", e.activo)
	}
	mu.Lock()
	nPub := len(publicados)
	var ultimo *panelPayload
	if nPub >= 2 {
		ultimo = publicados[1]
	}
	mu.Unlock()

	if nPub != 2 {
		t.Fatalf("el panel debe recibir el contexto nuevo sin esperar a que lo reabran, recibió %d eventos", nPub)
	}
	if ultimo == nil || ultimo.RepoRoot != nuevo.Root || ultimo.Repo != "portal-cliente" {
		t.Errorf("lo publicado debe ser el repo enrolado, llegó %+v", ultimo)
	}
	// Y sale en la lista del panel, que es donde se cambia de contexto.
	var enLista bool
	for _, entrada := range ultimo.OtrosRepos {
		if entrada.Ruta == nuevo.Root {
			enLista = true
		}
	}
	if !enLista {
		t.Errorf("el repo enrolado debe aparecer en la lista de proyectos: %v", ultimo.OtrosRepos)
	}
}
