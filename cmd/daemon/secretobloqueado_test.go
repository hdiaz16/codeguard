package main

import (
	"slices"
	"strings"
	"testing"

	"codeguard/internal/ipc"
	"codeguard/internal/registry"
)

// FRENAR UNA CREDENCIAL ES EL EVENTO QUE JUSTIFICA EL PRODUCTO, Y ERA EL ÚNICO
// QUE LA INTERFAZ NO CONTABA.
//
// La etapa 1 corre DENTRO del proceso del gancho —tiene que ser así: es
// fail-closed y no puede depender de que el daemon esté vivo— y salía por
// os.Exit(1) mucho antes de la primera llamada al daemon. Consecuencia medida
// con una llave privada y una clave de Stripe: el commit se bloqueaba, la
// terminal lo decía… y el orbe seguía en verde y el panel no se abría.
//
// Héctor lo dijo mirando la pantalla: "no vi que se bloqueara con los secretos".
// Estaba bloqueado. Lo que no estaba era dicho donde él miraba, y en un producto
// cuya promesa es "no te enteras de que está hasta que te salva", el momento en
// que te salva es justo el que no se puede callar.
//
// Lo que NO viaja por este aviso, y es deliberado: el VALOR del secreto. Sería
// absurdo abrir un camino nuevo por el que salga justo lo que estamos
// protegiendo. Viajan el repo, la rama y CUÁNTOS; el detalle ya está en la base
// —el gancho lo persiste antes de salir— y se lee en la pestaña Historial.
func TestUnBloqueoPorSecretoLlegaAlOrbeYAlPanel(t *testing.T) {
	repo := repoEnDisco(t, "demo-checkout")
	e, _ := escritorioDePrueba([]registry.Repo{repo})
	var climaDelOrbe string
	e.tray = &trayState{emit: func(estado, _ string) { climaDelOrbe = estado }}
	var publicados []*panelPayload
	e.emitir = func(nombre string, datos any) {
		if nombre != "analysis" {
			return
		}
		if p, ok := datos.(*panelPayload); ok {
			publicados = append(publicados, p)
		}
	}

	e.alComandoDeLaCLI("secreto-bloqueado", &ipc.Request{
		RepoRoot: repo.Root, Branch: "master", SecretosBloqueados: 2,
		SecretosEn: []string{"internal/pago/llave.go:3", ".env:1"},
	})

	if len(publicados) == 0 {
		t.Fatal("el bloqueo por secreto no publicó nada: el orbe se queda en verde y el panel " +
			"mudo justo cuando el producto acaba de frenar una credencial")
	}
	p := publicados[len(publicados)-1]
	if p.Verdict != "block" {
		t.Errorf("el veredicto tiene que ser un bloqueo, llegó %q", p.Verdict)
	}
	if p.Blocking != 2 {
		t.Errorf("tienen que contarse los 2 secretos, llegó %d", p.Blocking)
	}
	if p.RepoRoot != repo.Root {
		t.Errorf("el bloqueo tiene que hablar del repo que lo produjo, llegó %q", p.RepoRoot)
	}
	// El texto tiene que decir QUÉ pasó. Un "block" a secas con cero hallazgos
	// en la lista se lee como una avería del agente, que es lo contrario de lo
	// que acaba de ocurrir.
	if !strings.Contains(strings.ToLower(p.Reason), "secreto") {
		t.Errorf("el motivo tiene que nombrar el secreto para que no parezca una avería: %q", p.Reason)
	}
	// Y el orbe cambia de clima: es lo que se ve sin abrir nada, y era todo el
	// problema — el commit frenado y el orbe en verde.
	if climaDelOrbe != "blocked" {
		t.Errorf("el orbe tiene que ponerse en bloqueado, quedó %q", climaDelOrbe)
	}
	// EL DÓNDE. Héctor lo dijo con el orbe ya en rojo: "veo el orbe de color
	// rojo pero no el porqué del bloqueo ni en dónde". Un rojo sin sitio al que
	// ir obliga a volver a la terminal, y si commiteaste desde un editor que se
	// traga esa salida, no hay terminal a la que volver.
	if !slices.Equal(p.SecretosEn, []string{"internal/pago/llave.go:3", ".env:1"}) {
		t.Errorf("el panel tiene que decir en qué archivo y línea está cada secreto, llegó %v", p.SecretosEn)
	}
}

// El valor del secreto NO puede viajar en el aviso. Es la única regla dura de
// este camino: el producto existe para que esa cadena no salga del disco.
func TestElAvisoDeSecretoNoLlevaElSecreto(t *testing.T) {
	repo := repoEnDisco(t, "demo-checkout")
	e, _ := escritorioDePrueba([]registry.Repo{repo})
	e.tray = &trayState{}
	var publicados []*panelPayload
	e.emitir = func(nombre string, datos any) {
		if p, ok := datos.(*panelPayload); ok && nombre == "analysis" {
			publicados = append(publicados, p)
		}
	}

	e.alComandoDeLaCLI("secreto-bloqueado", &ipc.Request{
		RepoRoot: repo.Root, Branch: "master", SecretosBloqueados: 1,
		SecretosEn: []string{"internal/pago/llave.go:3"},
	})

	if len(publicados) == 0 {
		t.Fatal("no se publicó nada")
	}
	// Los hallazgos se construyen AQUÍ, en el daemon, para que el panel los
	// pinte con su tarjeta de siempre — pero ninguno puede llevar el fragmento
	// de código, que es donde está la credencial. El fragmento se arma leyendo
	// el archivo, y el panel se comparte por pantalla.
	p := publicados[len(publicados)-1]
	if len(p.Findings) != 1 {
		t.Fatalf("esperaba 1 hallazgo para que el panel lo pinte, llegaron %d", len(p.Findings))
	}
	if p.Findings[0].Snippet != nil {
		t.Errorf("el hallazgo de un secreto NO puede llevar fragmento de código: "+
			"pintaría la credencial en una ventana que se comparte por pantalla. Llegó %v",
			p.Findings[0].Snippet)
	}
	if p.Findings[0].LineContent != "" {
		t.Errorf("el contenido de la línea ES la credencial y no puede viajar: %q", p.Findings[0].LineContent)
	}
}

// Un aviso sin repo no puede tumbar el daemon ni publicar un bloqueo huérfano
// que se pinte sobre el proyecto equivocado.
func TestUnAvisoDeSecretoSinRepoNoHaceNada(t *testing.T) {
	e, _ := escritorioDePrueba(nil)
	e.tray = &trayState{}
	publicados := 0
	e.emitir = func(string, any) { publicados++ }

	e.alComandoDeLaCLI("secreto-bloqueado", &ipc.Request{SecretosBloqueados: 1})
	e.alComandoDeLaCLI("secreto-bloqueado", nil)

	if publicados != 0 {
		t.Errorf("un aviso sin repo publicó %d eventos: se pintaría un bloqueo sobre otro proyecto", publicados)
	}
}
