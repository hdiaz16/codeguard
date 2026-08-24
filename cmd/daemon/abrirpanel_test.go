package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codeguard/internal/ipc"
	"codeguard/internal/registry"
)

// Enrolar un repo abre el panel, PERO no si el equipo dijo que no se abriera
// solo.
//
// Las dos mitades importan y por motivos distintos. Que abra es lo que pedía el
// usuario: `codeguard init` decía LISTO y el agente se quedaba callado, sin
// forma de saber si había funcionado. Que respete `never` es lo contrario —
// quien pone eso en su config está diciendo que el panel no se abre solo, y
// "acabas de enrolar" no es una excusa para desobedecerlo.
//
// La primera versión de esto emitía "panel-show" a secas, que no abre nada (el
// panel nace oculto y sólo lo muestra panel.Show) y encima dejaba el orbe MUDO:
// el JS de la burbuja marca panelAbierto al recibir ese evento, y con esa
// bandera el susurro y el tooltip dejan de responder hasta que alguien abre y
// cierra el panel a mano.
func TestEnrolarAbrePanelSalvoQueLaConfigDigaNever(t *testing.T) {
	for _, c := range []struct {
		nombre    string
		autoOpen  string
		debeAbrir bool
	}{
		{"sin config: se abre con el valor por defecto", "", true},
		{"on_block: se abre", "on_block", true},
		{"never: NO se abre", "never", false},
	} {
		t.Run(c.nombre, func(t *testing.T) {
			viejo := repoEnDisco(t, "alfa")
			nuevo := repoEnDisco(t, "portal-cliente")
			if c.autoOpen != "" {
				escribirConfigUI(t, nuevo.Root, c.autoOpen)
			}

			e, _ := escritorioDePrueba([]registry.Repo{viejo, nuevo})
			e.tray = &trayState{}
			e.emitir = func(string, any) {}
			abierto := false
			e.abrirPanel = func() { abierto = true }

			e.alComandoDeLaCLI("repo-enrolado", &ipc.Request{RepoRoot: filepath.FromSlash(nuevo.Root)})

			if abierto != c.debeAbrir {
				t.Errorf("auto_open_panel=%q: abrió=%v, se esperaba %v", c.autoOpen, abierto, c.debeAbrir)
			}
			// En los tres casos el repo enrolado tiene que quedar al frente: la
			// decisión sobre la ventana no puede cambiar cuál es el contexto.
			if p := e.activoActual(); p == nil || p.Repo != nuevo.Nombre {
				t.Errorf("el repo enrolado debe quedar activo pase lo que pase con el panel; quedó %+v", p)
			}
		})
	}
}

// Un repo recién enrolado no tiene "0 hallazgos": no tiene ninguno porque nadie
// ha mirado. Decir "sin observaciones" ahí es la misma mentira por omisión que
// el ✓ verde sobre un análisis que no ocurrió.
func TestElTooltipDeUnRepoSinAnalizarNoFingeQueSeRevisó(t *testing.T) {
	p := &panelPayload{Repo: "portal-cliente", Verdict: "—"}
	got := tooltipDelOrbe(p)
	if got == "" {
		t.Fatal("sin tooltip")
	}
	for _, prohibido := range []string{"sin observaciones", "0 hallazgo"} {
		if contiene(got, prohibido) {
			t.Errorf("el tooltip de un repo nunca analizado dice %q: %s", prohibido, got)
		}
	}
	if !contiene(got, "sin análisis") {
		t.Errorf("el tooltip debe decir que no hay análisis todavía; dijo: %s", got)
	}
}

func contiene(s, sub string) bool { return strings.Contains(s, sub) }

func escribirConfigUI(t *testing.T, raiz, autoOpen string) {
	t.Helper()
	dir := filepath.Join(filepath.FromSlash(raiz), ".codeguard")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	yaml := "version: 1\nrulepack: \"2026.08.2\"\nui:\n  auto_open_panel: " + autoOpen + "\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
}
