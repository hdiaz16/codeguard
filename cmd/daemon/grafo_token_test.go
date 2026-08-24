package main

import (
	"strings"
	"testing"
)

// [17] del plan: una construcción VIEJA del grafo jamás reemplaza a una NUEVA.
//
// grafoMu hace atómico el par «publicar + abrir ventana», pero no lo ORDENA:
// las goroutines de abrirGrafo adquieren el candado en el orden que el
// runtime quiera (sync.Mutex no es FIFO), así que el pedido viejo podía ganar
// al final y la única ventana del explorador quedaba enseñando el repo
// equivocado — con tres puertas concurrentes reales (CLI open-graph, bus del
// panel, ventana). El token de generación se toma en el ORDEN de los pedidos;
// aquí se ejercita el guard directamente, sin dormir contra el planificador.
func TestUnPedidoViejoDelGrafoNoPisaAlNuevo(t *testing.T) {
	e, _ := escritorioDePrueba(nil)
	repoA, repoB := t.TempDir(), t.TempDir()

	genVieja := e.grafoGen.Add(1) // pedido A
	genNueva := e.grafoGen.Add(1) // pedido B lo supera antes de que A publique

	// B publica primero (es el vigente).
	if !e.publicarGrafoSiVigente(genNueva, contextoGrafo{raiz: repoB, repoRoot: repoB, nombre: "beta"}) {
		t.Fatal("el pedido vigente tiene que publicar")
	}
	servido, _ := e.grafoJSON.Load().([]byte)
	if len(servido) == 0 {
		t.Fatal("el vigente no dejó nada servido en /graph.json")
	}

	// A llega tarde al candado: NO publica y lo servido no cambia ni un byte.
	if e.publicarGrafoSiVigente(genVieja, contextoGrafo{raiz: repoA, repoRoot: repoA, nombre: "alfa"}) {
		t.Error("un pedido superado publicó: la ventana enseñaría el repo equivocado")
	}
	despues, _ := e.grafoJSON.Load().([]byte)
	if string(despues) != string(servido) {
		t.Errorf("el pedido viejo tocó /graph.json:\nantes:   %.80s\ndespués: %.80s", servido, despues)
	}
	if strings.Contains(string(despues), "alfa") {
		t.Error("el grafo servido menciona al proyecto del pedido viejo")
	}
}
