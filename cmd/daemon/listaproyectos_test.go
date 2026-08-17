package main

import (
	"testing"

	"codeguard/internal/registry"
)

// La lista de proyectos existe para responder "¿dónde tengo un problema?" de un
// vistazo. Con sólo el semáforo no lo respondía: un repo con un bloqueante y
// otro con nueve se pintaban idénticos, y un repo que lleva semanas sin
// analizarse se veía tan verde como el de hace un minuto.
func TestLaListaDiceCuantoYCuandoYNoSoloElColor(t *testing.T) {
	roto := repoEnDisco(t, "alfa")
	limpio := repoEnDisco(t, "beta")
	sinEstrenar := repoEnDisco(t, "gama")

	e, _ := escritorioDePrueba([]registry.Repo{roto, limpio, sinEstrenar})
	e.porProyecto[roto.Root] = &panelPayload{
		Repo: "alfa", RepoRoot: roto.Root, Verdict: "block",
		Blocking: 3, Advisory: 2, At: "11:42:03",
	}
	e.porProyecto[limpio.Root] = &panelPayload{
		Repo: "beta", RepoRoot: limpio.Root, Verdict: "pass", At: "10:15:00",
	}

	porNombre := map[string]proyectoEnLista{}
	for _, p := range e.listaProyectos(limpio.Root) {
		porNombre[p.Nombre] = p
	}
	if len(porNombre) != 3 {
		t.Fatalf("deben salir los tres proyectos: %+v", porNombre)
	}

	if a := porNombre["alfa"]; a.Blocking != 3 || a.Advisory != 2 || a.Marca != "⛔" {
		t.Errorf("el repo bloqueado tiene que llevar sus conteos: %+v", a)
	}
	if b := porNombre["beta"]; !b.Activo || b.Marca != "✓" {
		t.Errorf("el activo tiene que venir marcado como tal: %+v", b)
	}
	if a := porNombre["alfa"]; a.Activo {
		t.Errorf("sólo uno puede estar activo: %+v", a)
	}

	// El que nunca se analizó es el caso que más se presta a mentir: no tiene
	// cero hallazgos, no tiene ninguno porque nadie ha mirado.
	g := porNombre["gama"]
	if g.Verdict == "pass" || g.Blocking != 0 || g.Marca != "○" {
		t.Errorf("un repo sin estrenar no puede parecer limpio: %+v", g)
	}
	if g.Cuando == "" {
		t.Errorf("la lista tiene que decir que gama no se ha analizado nunca: %+v", g)
	}
}
