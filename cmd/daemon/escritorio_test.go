package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codeguard/internal/config"
	"codeguard/internal/finding"
	"codeguard/internal/ipc"
	"codeguard/internal/registry"
)

// Estas pruebas existen porque dos fallos del daemon llegaron a producción sin
// que nada los atrapara: el panel salía vacío tras reiniciar y la lista de
// proyectos no se refrescaba. Todo lo que se prueba aquí vive fuera de Wails a
// propósito — ninguna prueba abre una ventana ni arranca la aplicación.

// escritorioDePrueba arma un escritorio sin aplicación: sólo el estado y el
// registro simulado. El campo app queda nil y ningún método de aquí lo toca.
func escritorioDePrueba(repos []registry.Repo) (*escritorio, *[]string) {
	var olvidados []string
	e := &escritorio{
		porProyecto: map[string]*panelPayload{},
		cargarRepos: func() []registry.Repo { return repos },
	}
	// En producción es `go registry.Remove(raiz)`; aquí, síncrono, para poder
	// afirmar sobre lo que se olvidó sin carreras.
	e.olvidarRepo = func(raiz string) { olvidados = append(olvidados, raiz) }
	return e, &olvidados
}

// repoEnDisco crea una carpeta de verdad: listaProyectos comprueba con os.Stat
// que el proyecto siga existiendo, y esa comprobación es parte de lo probado.
func repoEnDisco(t *testing.T, nombre string) registry.Repo {
	t.Helper()
	dir := filepath.Join(t.TempDir(), nombre)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return registry.Repo{Root: filepath.ToSlash(dir), Nombre: nombre}
}

// campos parte una entrada "marca|nombre|ruta|activo".
func campos(t *testing.T, entrada string) []string {
	t.Helper()
	partes := strings.Split(entrada, "|")
	if len(partes) != 4 {
		t.Fatalf("la entrada debe ser marca|nombre|ruta|activo, llegó %q", entrada)
	}
	return partes
}

func TestListaProyectosSiembraLosEnroladosAunqueNoHayanCommiteado(t *testing.T) {
	// La lección de bds.portal: `codeguard init` escribe en repos.json, pero
	// el daemon ya estaba corriendo con su copia en memoria. El registro se
	// relee en cada lista, no sólo al arrancar.
	nuevo := repoEnDisco(t, "bds-portal")
	e, _ := escritorioDePrueba(nil)
	if lista := e.listaProyectos(""); len(lista) != 0 {
		t.Fatalf("sin proyectos la lista debe venir vacía, llegó %v", lista)
	}

	e.cargarRepos = func() []registry.Repo { return []registry.Repo{nuevo} }
	lista := e.listaProyectos("")
	if len(lista) != 1 {
		t.Fatalf("el proyecto recién enrolado debe aparecer sin esperar al primer commit: %v", lista)
	}
	c := campos(t, lista[0])
	if c[0] != "○" || c[1] != "bds-portal" || c[3] != "0" {
		t.Errorf("un proyecto sin análisis va con marca ○ y sin activar: %q", lista[0])
	}
	if p := e.porProyecto[nuevo.Root]; p == nil || p.Verdict != "—" || p.At != "sin análisis" {
		t.Errorf("el proyecto sembrado debe quedar con su estado placeholder: %+v", p)
	}
}

func TestListaProyectosMarcaElEstadoDeCadaUnoYOrdenaPorNombre(t *testing.T) {
	// El orbe habla del proyecto activo, pero el panel muestra a todos con su
	// propio estado: un bloqueo en uno no secuestra el verde de los demás.
	uno := repoEnDisco(t, "alfa")
	dos := repoEnDisco(t, "beta")
	tres := repoEnDisco(t, "gama")
	e, _ := escritorioDePrueba([]registry.Repo{tres, uno, dos})
	e.porProyecto[uno.Root] = &panelPayload{Repo: "alfa", RepoRoot: uno.Root, Verdict: "block"}
	e.porProyecto[dos.Root] = &panelPayload{Repo: "beta", RepoRoot: dos.Root, Verdict: "pass"}

	lista := e.listaProyectos(dos.Root)
	if len(lista) != 3 {
		t.Fatalf("deben salir los tres proyectos: %v", lista)
	}
	quiero := []struct{ marca, nombre, activo string }{
		{"⛔", "alfa", "0"},
		{"✓", "beta", "1"},
		{"○", "gama", "0"},
	}
	for i, q := range quiero {
		c := campos(t, lista[i])
		if c[0] != q.marca || c[1] != q.nombre || c[3] != q.activo {
			t.Errorf("entrada %d: quería %v, llegó %q", i, q, lista[i])
		}
	}
}

func TestListaProyectosOlvidaElProyectoBorradoDelDisco(t *testing.T) {
	// Un proyecto cuya carpeta ya no existe no es un proyecto: antes seguía
	// en el panel hasta reiniciar el agente.
	vivo := repoEnDisco(t, "vivo")
	muerto := filepath.ToSlash(filepath.Join(t.TempDir(), "borrado")) // nunca se crea
	e, olvidados := escritorioDePrueba([]registry.Repo{vivo})
	e.porProyecto[muerto] = &panelPayload{Repo: "borrado", RepoRoot: muerto, Verdict: "pass"}

	lista := e.listaProyectos("")
	if len(lista) != 1 || campos(t, lista[0])[1] != "vivo" {
		t.Fatalf("sólo debe quedar el proyecto vivo: %v", lista)
	}
	if _, sigue := e.porProyecto[muerto]; sigue {
		t.Error("el proyecto borrado debe salir también del estado en memoria")
	}
	if len(*olvidados) != 1 || (*olvidados)[0] != muerto {
		t.Errorf("debe olvidarse también del registro, se olvidó %v", *olvidados)
	}
}

func TestSembrarDesdeRegistroLlenaElPanelTrasReiniciarElDaemon(t *testing.T) {
	// El fallo de la 1.2.0: daemon recién arrancado, sin análisis en memoria.
	// El panel salía vacío y se leía como "se perdieron mis repos".
	uno := repoEnDisco(t, "alfa")
	dos := repoEnDisco(t, "beta")
	e, _ := escritorioDePrueba([]registry.Repo{uno, dos})

	e.sembrarDesdeRegistro()

	if e.activo == nil {
		t.Fatal("con proyectos enrolados el panel nunca debe quedarse sin contexto")
	}
	if e.activo.Repo != "alfa" || e.activo.RepoRoot != uno.Root {
		t.Errorf("se muestra el primero del registro, llegó %+v", e.activo)
	}
	if e.activo.Verdict != "—" || e.activo.At != "sin análisis" {
		t.Errorf("sin análisis todavía, el estado es placeholder: %+v", e.activo)
	}
	if len(e.activo.OtrosRepos) != 2 {
		t.Fatalf("el panel debe listar los dos proyectos: %v", e.activo.OtrosRepos)
	}
	if c := campos(t, e.activo.OtrosRepos[0]); c[3] != "1" {
		t.Errorf("el sembrado debe quedar marcado como activo: %q", e.activo.OtrosRepos[0])
	}
}

func TestSembrarDesdeRegistroNoPisaElAnalisisEnCurso(t *testing.T) {
	// Sembrar es sólo para el arranque en frío: si ya hubo un análisis, el
	// contexto activo manda.
	uno := repoEnDisco(t, "alfa")
	e, _ := escritorioDePrueba([]registry.Repo{uno})
	analizado := &panelPayload{Repo: "beta", RepoRoot: "c:/repos/beta", Verdict: "block"}
	e.activo = analizado

	e.sembrarDesdeRegistro()

	if e.activo != analizado {
		t.Errorf("el contexto activo no se toca, quedó %+v", e.activo)
	}
}

func TestSembrarDesdeRegistroSinProyectosEnrolados(t *testing.T) {
	// Máquina sin ningún repo enrolado: no hay nada que mostrar y tampoco
	// nada que reventar.
	e, _ := escritorioDePrueba(nil)

	e.sembrarDesdeRegistro()

	if e.activo != nil {
		t.Errorf("sin proyectos no debe inventarse un contexto: %+v", e.activo)
	}
}

func TestRegistrarAnalisisGuardaElContextoYLoVuelveActivo(t *testing.T) {
	uno := repoEnDisco(t, "alfa")
	dos := repoEnDisco(t, "beta")
	e, _ := escritorioDePrueba([]registry.Repo{uno, dos})
	e.sembrarDesdeRegistro() // arranque en frío: el activo es alfa

	analisis := &panelPayload{Repo: "beta", RepoRoot: dos.Root, Verdict: "block", Blocking: 2}
	e.registrarAnalisis(analisis)

	if e.activo != analisis {
		t.Fatalf("el proyecto recién analizado pasa a ser el activo: %+v", e.activo)
	}
	if e.porProyecto[dos.Root] != analisis {
		t.Error("el análisis debe quedar guardado en el contexto de su proyecto")
	}
	if raiz, _ := e.raizConfig.Load().(string); raiz != dos.Root {
		t.Errorf("la config del modelo se lee desde el último proyecto analizado, quedó %q", raiz)
	}
	// El otro proyecto conserva su estado: cambiar de contexto no altera a nadie.
	if p := e.porProyecto[uno.Root]; p == nil || p.Verdict != "—" {
		t.Errorf("alfa no debe verse afectado por un bloqueo en beta: %+v", p)
	}
	if len(analisis.OtrosRepos) != 2 {
		t.Fatalf("el panel viaja con la lista completa: %v", analisis.OtrosRepos)
	}
	if c := campos(t, analisis.OtrosRepos[1]); c[1] != "beta" || c[0] != "⛔" || c[3] != "1" {
		t.Errorf("beta debe salir bloqueado y activo: %q", analisis.OtrosRepos[1])
	}
}

func TestOrbStateFor(t *testing.T) {
	// El clima del orbe: un bloqueo manda sobre todo lo demás, y una
	// sugerencia no es motivo para pintar de verde ni de rojo.
	casos := []struct {
		nombre  string
		payload *panelPayload
		quiero  string
	}{
		{"bloqueado", &panelPayload{Verdict: "block"}, "blocked"},
		{"bloqueado con avisos", &panelPayload{Verdict: "block", Advisory: 3}, "blocked"},
		{"limpio", &panelPayload{Verdict: "pass"}, "pass"},
		{"sólo sugerencias", &panelPayload{Verdict: "pass", Advisory: 1}, "idle"},
		{"sin análisis", &panelPayload{Verdict: "—"}, "pass"},
	}
	for _, c := range casos {
		if got := orbStateFor(c.payload); got != c.quiero {
			t.Errorf("%s: quería %q, llegó %q", c.nombre, c.quiero, got)
		}
	}
}

func TestResumenHallazgos(t *testing.T) {
	// "0 bloqueantes, 1 avisos" obliga a descifrar dos números y encima está
	// mal escrito. Los plurales son el punto de esta función.
	casos := []struct {
		bloqueantes, avisos int
		quiero              string
	}{
		{0, 0, "sin observaciones"},
		{0, 1, "1 sugerencia"},
		{0, 4, "4 sugerencias"},
		{1, 0, "1 problema por resolver"},
		{3, 0, "3 problemas por resolver"},
		{1, 1, "1 problema por resolver y 1 sugerencia"},
		{2, 3, "2 problemas por resolver y 3 sugerencias"},
	}
	for _, c := range casos {
		if got := resumenHallazgos(c.bloqueantes, c.avisos); got != c.quiero {
			t.Errorf("(%d,%d): quería %q, llegó %q", c.bloqueantes, c.avisos, c.quiero, got)
		}
	}
}

func TestMarcaProyecto(t *testing.T) {
	casos := map[string]string{
		"block":   "⛔",
		"pass":    "✓",
		"skipped": "✓",
		"—":       "○",
		"":        "○",
	}
	for veredicto, quiero := range casos {
		if got := marcaProyecto(veredicto); got != quiero {
			t.Errorf("veredicto %q: quería %q, llegó %q", veredicto, quiero, got)
		}
	}
}

func TestOpcionesUI(t *testing.T) {
	maxShow, autoOpen := opcionesUI(nil)
	if maxShow != 7 || autoOpen != "on_block" {
		t.Errorf("sin configuración legible mandan los valores de §12: %d %q", maxShow, autoOpen)
	}

	cfg := &config.Config{}
	cfg.UI.MaxVisibleFindings = 3
	cfg.UI.AutoOpenPanel = "never"
	if maxShow, autoOpen = opcionesUI(cfg); maxShow != 3 || autoOpen != "never" {
		t.Errorf("el proyecto manda sobre el default: %d %q", maxShow, autoOpen)
	}

	// Un cero o un vacío no son una elección: se quedan los defaults.
	if maxShow, autoOpen = opcionesUI(&config.Config{}); maxShow != 7 || autoOpen != "on_block" {
		t.Errorf("los campos sin poner conservan el default: %d %q", maxShow, autoOpen)
	}
}

func TestConstruirPayloadLlevaElCodigoSenalado(t *testing.T) {
	repo := t.TempDir()
	archivo := filepath.Join(repo, "main.go")
	if err := os.WriteFile(archivo, []byte("uno\ndos\ntres\ncuatro\ncinco\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	req := &ipc.Request{RepoRoot: repo, Branch: "main", AIGenerated: true}
	resp := &ipc.Response{
		Verdict: "block", BlockingFindings: 1, AdvisoryFindings: 2, ElapsedMs: 42,
		Findings: []finding.Finding{
			{File: "main.go", Line: 3, Source: finding.Deterministic},
		},
	}

	payload := construirPayload(req, resp, 5)

	if payload.Repo != filepath.Base(repo) || payload.Branch != "main" || !payload.AIGenerated {
		t.Errorf("el encabezado del panel sale de la petición: %+v", payload)
	}
	if payload.RepoRoot != filepath.ToSlash(repo) {
		t.Errorf("la raíz viaja con separadores / (es la llave del contexto): %q", payload.RepoRoot)
	}
	if payload.MaxShow != 5 || payload.Verdict != "block" || payload.Blocking != 1 || payload.Advisory != 2 {
		t.Errorf("el veredicto y los contadores salen de la respuesta: %+v", payload)
	}
	if len(payload.Findings) != 1 {
		t.Fatalf("debe viajar el hallazgo: %+v", payload.Findings)
	}
	f := payload.Findings[0]
	if !f.IsFact {
		t.Error("un hallazgo determinista se enuncia como hecho (§12.2)")
	}
	if len(f.Snippet) != 5 {
		t.Fatalf("el snippet lleva la línea señalada y tres a cada lado: %+v", f.Snippet)
	}
	if f.Snippet[2].Text != "tres" || !f.Snippet[2].Culprit {
		t.Errorf("la línea culpable debe venir marcada: %+v", f.Snippet[2])
	}
}

// Un proyecto sembrado del registro NO puede afirmar que la paridad con el CI
// está rota: nadie la ha comprobado todavía.
//
// El panel enseña el aviso amarillo cuando ci_parity es false, y false es el
// cero de Go. Al sembrar el placeholder sin fijar el campo, bds.portal —un repo
// sano, con su rulepack instalado y resuelto— aparecía acusando "tu rulepack no
// coincide, no puedo garantizar que pase el CI". El arreglo del panel vacío
// (1.3.0) trajo puesto este otro fallo.
func TestElProyectoSembradoNoAcusaFaltaDeParidad(t *testing.T) {
	uno := repoEnDisco(t, "portal")
	e, _ := escritorioDePrueba([]registry.Repo{uno})

	e.sembrarDesdeRegistro()

	if e.activo == nil {
		t.Fatal("el sembrado debia dejar un contexto activo")
	}
	if !e.activo.CIParity {
		t.Error("sin analisis no hay paridad rota que reportar: el panel ensenaria un aviso inventado")
	}
	if e.activo.Verdict != "—" || e.activo.At != "sin analisis" && e.activo.At != "sin análisis" {
		t.Errorf("el placeholder debe verse como lo que es: %+v", e.activo)
	}
}
