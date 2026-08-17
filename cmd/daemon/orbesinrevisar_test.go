package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"codeguard/internal/daemon"
	"codeguard/internal/gitdiff"
	"codeguard/internal/ipc"
	"codeguard/internal/pipeline"
)

// El ✓ falso en la otra pantalla.
//
// El hook ya dejó de firmar "listo — commit permitido" sobre un análisis que no
// miró nada: tiene una rama propia para Skipped que dice "SIN REVISAR". La UI se
// quedó fuera de esa mudanza y seguía cometiendo el mismo pecado por tres sitios
// a la vez —el orbe, su tooltip y el semáforo de la lista de proyectos—, que son
// justo las tres superficies que un desarrollador mira DESPUÉS de commitear.
//
// Lo que estas pruebas fijan no es un color: es que ninguna de las tres afirme
// "revisado y limpio" cuando el embudo se paró en la etapa 0.

// motivosDeDecisionDelEquipo son los saltos que el propio equipo eligió. Un
// merge se salta porque así se acordó, y unos archivos excluidos lo están porque
// alguien los excluyó en la config. Pasan todos los días y NO son una avería.
var motivosDeDecisionDelEquipo = []string{
	pipeline.MotivoMergeORevert,
	pipeline.MotivoTodoExcluido,
}

// motivosDeAveria son los saltos que delatan algo roto. Aquí el análisis no
// corrió porque NO PUDO, y eso el usuario tiene que verlo y arreglarlo.
var motivosDeAveria = []string{
	pipeline.MotivoNoEnrolado,
	pipeline.MotivoSinDiff,
	"no se pudo leer .codeguard/config.yaml: yaml: line 3: mapping values are not allowed",
}

func TestElOrbeNuncaPintaVerdeUnAnalisisQueNoMiroNada(t *testing.T) {
	// El verde es la única afirmación fuerte que hace el orbe: "lo revisé y está
	// limpio". Sobre un embudo que se paró antes de la primera compuerta esa
	// frase es falsa por cualquiera de los motivos, así que la prueba es una
	// sola y cubre todos.
	todos := append(append([]string{}, motivosDeDecisionDelEquipo...), motivosDeAveria...)
	todos = append(todos, "") // un motivo que no llegó tampoco autoriza el verde
	for _, motivo := range todos {
		p := &panelPayload{Verdict: "skipped", Reason: motivo}
		if got := orbStateFor(p); got == "pass" {
			t.Errorf("motivo %q: el orbe pintó «pass» sobre un análisis omitido.\n"+
				"El verde afirma «lo revisé y está limpio», y aquí no se revisó nada", motivo)
		}
	}
	// Y el proyecto que todavía no se ha analizado nunca: tampoco es un verde.
	// Se llega aquí al abrir el panel con el daemon recién reiniciado, que es
	// cuando MENOS hay que afirmar nada.
	if got := orbStateFor(&panelPayload{Verdict: "—"}); got == "pass" {
		t.Error("un proyecto enrolado y sin analizar todavía pintó «pass»: " +
			"el orbe afirma una revisión limpia que no ha ocurrido")
	}
}

func TestElOrbeDistingueLaDecisionDelEquipoDeLaAveria(t *testing.T) {
	// El matiz que ya se aplicó en el hook. Un merge se salta todos los días por
	// acuerdo del equipo: pintarlo de naranja convertiría el naranja en ruido y
	// entonces no serviría el día que haya una degradación de verdad. Una config
	// ilegible es lo contrario: hay algo roto y hay que ir a arreglarlo.
	for _, motivo := range motivosDeDecisionDelEquipo {
		p := &panelPayload{Verdict: "skipped", Reason: motivo}
		if got := orbStateFor(p); got != "idle" {
			t.Errorf("motivo %q: quería «idle» y llegó %q.\n"+
				"Es una decisión del equipo, no una avería: no debe alarmar", motivo, got)
		}
	}
	for _, motivo := range motivosDeAveria {
		p := &panelPayload{Verdict: "skipped", Reason: motivo}
		if got := orbStateFor(p); got != "degraded" {
			t.Errorf("motivo %q: quería «degraded» y llegó %q.\n"+
				"Aquí el análisis no corrió porque no pudo, y eso hay que verlo", motivo, got)
		}
	}
}

// El orbe y el hook tienen que clasificar IGUAL, y por eso ninguno de los dos
// tiene criterio propio.
//
// Los dos describen el MISMO commit: el tono del mensaje en la terminal y el
// color del orbe. Cuando cada lado llevaba su copia del criterio —dos switch
// sobre las mismas dos constantes— coincidían por casualidad, y el día que se
// añadiera un motivo nuevo tocando sólo uno, el mismo commit habría salido en
// neutro por la terminal y en naranja de avería en el orbe. Un producto que se
// contradice sobre un solo commit es peor que cualquiera de las dos conductas.
//
// Esta prueba NO repite la lista de motivos rutinarios: la pregunta a
// pipeline.EsDecisionDelEquipo, que es la única que la sabe. Así, añadir un
// motivo allí llega hasta aquí solo, y si alguien vuelve a bifurcar el criterio
// dentro del daemon, esto se pone rojo. La otra mitad —que el hook use esa misma
// función— la fija TestElTonoSeDecidePorElMotivoExacto en cmd/codeguard.
func TestElOrbeNoTieneCriterioPropioSobreQuienDecidioElSalto(t *testing.T) {
	motivos := []string{
		pipeline.MotivoMergeORevert,
		pipeline.MotivoTodoExcluido,
		pipeline.MotivoNoEnrolado,
		pipeline.MotivoSinDiff,
		"no se pudo leer .codeguard/config.yaml: yaml: line 3: mapping values are not allowed",
		"un motivo que todavía no existe",
		"",
		// Una variante parecida no es la constante: el acento importa.
		"todos los archivos tocados estan excluidos",
	}
	for _, m := range motivos {
		quiero := "degraded"
		if pipeline.EsDecisionDelEquipo(m) {
			quiero = "idle"
		}
		p := &panelPayload{Verdict: "skipped", Reason: m}
		if got := orbStateFor(p); got != quiero {
			t.Errorf("motivo %q: pipeline.EsDecisionDelEquipo dice %v y el orbe pintó %q "+
				"(se esperaba %q).\nEl orbe se ha vuelto a inventar un criterio propio, y el "+
				"hook seguirá usando el del pipeline: el mismo commit saldría distinto en "+
				"cada superficie", m, pipeline.EsDecisionDelEquipo(m), got, quiero)
		}
	}
}

// Lo anterior ata el orbe al criterio canónico; esto ata el criterio canónico a
// lo que el producto quiere. Sin este par, "arreglarlo" haciendo que
// EsDecisionDelEquipo devuelva siempre lo mismo pasaría desapercibido.
func TestElCriterioCanonicoSigueDiciendoLoQueElProductoQuiere(t *testing.T) {
	if !pipeline.EsDecisionDelEquipo(pipeline.MotivoMergeORevert) {
		t.Error("un merge dejó de ser decisión del equipo: el orbe se pondría de color " +
			"piedra en cada merge y el naranja se convertiría en ruido")
	}
	if !pipeline.EsDecisionDelEquipo(pipeline.MotivoTodoExcluido) {
		t.Error("excluir archivos dejó de ser decisión del equipo: alarmar por una " +
			"configuración que el propio equipo eligió es la avería lenta de este producto")
	}
	if pipeline.EsDecisionDelEquipo(pipeline.MotivoNoEnrolado) {
		t.Error("un repo sin enrolar pasó a contarse como rutina: es una avería y el " +
			"usuario tiene que verla")
	}
	if pipeline.EsDecisionDelEquipo("") {
		t.Error("un motivo vacío pasó a contarse como rutina: sin motivo no se puede " +
			"saber si fue decisión o avería, y hay que asumir lo segundo")
	}
}

func TestUnMotivoDesconocidoSeTrataComoAveriaYNoComoRutina(t *testing.T) {
	// La dirección en la que se falla importa. Un daemon de otra versión puede
	// mandar un motivo que este binario no conoce; ante la duda, la señal
	// prudente es la que pide mirar, no la que tranquiliza.
	p := &panelPayload{Verdict: "skipped", Reason: "un motivo que todavía no existe"}
	if got := orbStateFor(p); got != "degraded" {
		t.Errorf("un motivo desconocido dio %q; se espera «degraded»: "+
			"ante un motivo que no sabemos clasificar, hay que pedir que se mire", got)
	}
}

// Las dos rutas del orbe tienen que decir lo mismo del mismo payload.
//
// Había dos caminos y no coincidían: actualizarOrbe (tras un análisis) sí miraba
// las capas degradadas, y orbStateFor (al cambiar de proyecto desde el panel) no
// las miraba en absoluto. El mismo commit se veía naranja al terminar y VERDE al
// volver a ese proyecto un minuto después. Un semáforo que cambia de color según
// por dónde lo mires no es un semáforo.
func TestLasDosRutasDelOrbeNoSeContradicen(t *testing.T) {
	casos := []*panelPayload{
		{Verdict: "block"},
		{Verdict: "block", Advisory: 2},
		{Verdict: "pass"},
		{Verdict: "pass", Advisory: 3},
		{Verdict: "pass", Degraded: []string{"semgrep:error"}},
		{Verdict: "pass", Degraded: []string{"falta:trivy"}},
		{Verdict: "pass", Advisory: 1, Degraded: []string{"tsc:plazo"}},
		{Verdict: "skipped", Reason: pipeline.MotivoTodoExcluido},
		{Verdict: "skipped", Reason: pipeline.MotivoMergeORevert},
		{Verdict: "skipped", Reason: pipeline.MotivoNoEnrolado, Degraded: []string{"config:unreadable"}},
		{Verdict: "—"},
	}
	for _, p := range casos {
		quiere := orbStateFor(p)
		e := &escritorio{}
		tray, g := bandejaDePrueba(20 * time.Millisecond)
		e.tray = tray
		e.actualizarOrbe(p)
		if got := g.ultima(t).estado; got != quiere {
			t.Errorf("veredicto %q motivo %q degradadas %v:\n"+
				"  orbStateFor (cambiar de proyecto) dice %q\n"+
				"  actualizarOrbe (tras el análisis)  dice %q\n"+
				"El mismo estado no puede tener dos colores según por dónde se mire",
				p.Verdict, p.Reason, p.Degraded, quiere, got)
		}
	}
}

func TestElTooltipDeUnAnalisisOmitidoNoDiceSinObservaciones(t *testing.T) {
	// "sin observaciones" describe un análisis que corrió y no encontró nada.
	// Sobre uno que no miró nada es literalmente falso, y es la frase que el
	// usuario lee al pasar el ratón por encima del orbe.
	for _, motivo := range append(append([]string{}, motivosDeDecisionDelEquipo...), motivosDeAveria...) {
		e := &escritorio{}
		tray, g := bandejaDePrueba(20 * time.Millisecond)
		e.tray = tray
		e.actualizarOrbe(&panelPayload{
			Repo: "portal", Branch: "master", Verdict: "skipped", Reason: motivo,
		})
		tooltip := g.ultima(t).tooltip
		if strings.Contains(tooltip, "sin observaciones") {
			t.Errorf("motivo %q: el tooltip dice «sin observaciones» sobre un análisis "+
				"que no observó nada:\n  %s", motivo, tooltip)
		}
		if !strings.Contains(tooltip, motivo) {
			t.Errorf("motivo %q: el tooltip no lo menciona, así que no hay forma de "+
				"saber por qué no se revisó:\n  %s", motivo, tooltip)
		}
	}
}

// El motivo tiene que LLEGAR a la UI para que la UI pueda decirlo.
//
// Es la causa raíz de que las tres superficies tuvieran que adivinar: el pipe ya
// traía ipc.Response.Reason —el daemon lo rellena y el hook lo usa— pero
// construirPayload lo tiraba al armar lo que ve el panel. El panel acabó
// enumerando de memoria "fue un merge, un revert, o todos los archivos están
// excluidos", que es una conjetura escrita a mano sobre un dato que ya existía.
func TestConstruirPayloadNoPierdeElMotivoDelSalto(t *testing.T) {
	p := construirPayload(
		&ipc.Request{RepoRoot: "C:/repo", Branch: "master"},
		&ipc.Response{Verdict: "skipped", Reason: pipeline.MotivoTodoExcluido},
		nil,
		7,
	)
	if p.Reason != pipeline.MotivoTodoExcluido {
		t.Errorf("el motivo se perdió al armar el payload: %q.\n"+
			"Sin él la UI no puede explicar por qué no se revisó, y acaba adivinando",
			p.Reason)
	}
}

// Y lo que de verdad manda el daemon, no lo que yo supuse que manda.
//
// Las pruebas de arriba clasifican motivos escritos a mano. Ésta los pide al
// productor real —daemon.Analyze sobre repos de verdad— y los pasa por la misma
// tubería que la UI (construirPayload → orbStateFor), para que la clasificación
// no se quede colgando de una cadena que alguien retoque en el otro extremo.
func TestLoQueElDaemonEmiteDeVerdadSeClasificaComoAveria(t *testing.T) {
	casos := []struct {
		nombre string
		monta  func(t *testing.T) string
	}{
		{"repo sin enrolar", func(t *testing.T) string { return t.TempDir() }},
		{"config ilegible", func(t *testing.T) string {
			raiz := t.TempDir()
			dir := filepath.Join(raiz, ".codeguard")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			// YAML roto de verdad: una lista donde se espera un mapa.
			if err := os.WriteFile(filepath.Join(dir, "config.yaml"),
				[]byte("rulepack: [esto\n  no: cierra\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			return raiz
		}},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			raiz := c.monta(t)
			req := &ipc.Request{RepoRoot: raiz, Branch: "master"}
			resp := (&daemon.Server{}).Analyze(context.Background(), req)

			if resp.Verdict != "skipped" {
				t.Fatalf("el daemon devolvió %q; esta prueba sólo tiene sentido sobre un salto", resp.Verdict)
			}
			p := construirPayload(req, resp, nil, 7)
			if p.Reason == "" {
				t.Error("el motivo no llegó al payload: la UI se queda sin poder explicarse")
			}
			if got := orbStateFor(p); got != "degraded" {
				t.Errorf("motivo real %q (degradadas %v): el orbe pintó %q y se esperaba «degraded».\n"+
					"El análisis no corrió porque NO PUDO, y eso el usuario tiene que verlo",
					p.Reason, p.Degraded, got)
			}
			if strings.Contains(tooltipDelOrbe(p), "sin observaciones") {
				t.Errorf("el tooltip dice «sin observaciones» sobre un análisis que no corrió: %s",
					tooltipDelOrbe(p))
			}
		})
	}
}

// La otra mitad, y es la que importa para el ruido: el salto RUTINARIO tal como
// lo emite el daemon de verdad.
//
// El de arriba ata el lado de la avería. Éste ata el de la decisión del equipo,
// que es el que se dispara todos los días: si el texto que el daemon pone en
// Reason dejara de coincidir con la constante, la clasificación caería al lado
// prudente —«degraded»— y el orbe se pondría de color piedra en CADA merge y en
// cada commit que sólo toca archivos excluidos. Se degrada sin mentir, pero
// convierte la señal en ruido, que es la avería lenta que este repo ya ha
// pagado dos veces. Mejor que salte una prueba.
func TestUnSaltoRutinarioDelDaemonRealNoAlarma(t *testing.T) {
	raiz := t.TempDir()
	dir := filepath.Join(raiz, ".codeguard")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Una config válida que excluye absolutamente todo: el embudo llega a la
	// etapa 0, filtra los archivos y se queda sin nada que mirar.
	cfg := "version: 1\nrulepack: \"2026.08.2\"\nlanguages: [go]\npaths:\n  exclude: [\"**\"]\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	req := &ipc.Request{
		RepoRoot:    raiz,
		Branch:      "master",
		StagedFiles: []gitdiff.ChangedFile{{Path: "main.go", Status: "M"}},
	}
	resp := (&daemon.Server{}).Analyze(context.Background(), req)
	if resp.Verdict != "skipped" {
		t.Fatalf("el daemon devolvió %q con todo excluido; esta prueba sólo tiene sentido sobre un salto", resp.Verdict)
	}
	if resp.Reason != pipeline.MotivoTodoExcluido {
		t.Fatalf("el daemon puso en Reason %q y la UI clasifica contra %q.\n"+
			"El motivo es un contrato entre los dos: si cambia de un lado, cambia del otro",
			resp.Reason, pipeline.MotivoTodoExcluido)
	}
	p := construirPayload(req, resp, nil, 7)
	if got := orbStateFor(p); got != "idle" {
		t.Errorf("un salto rutinario del daemon real pintó %q y se esperaba «idle».\n"+
			"Excluir archivos lo decidió el equipo: alarmar por ello convierte la señal en ruido", got)
	}
}

func TestLaListaDeProyectosNoPoneVistoBuenoAUnAnalisisOmitido(t *testing.T) {
	// El ✓ de la lista es el mismo pecado en pequeño: junto al nombre del repo
	// dice "limpio — el último commit pasó todas las compuertas", que sobre un
	// análisis omitido no pasó ninguna.
	for _, motivo := range append(append([]string{}, motivosDeDecisionDelEquipo...), motivosDeAveria...) {
		p := &panelPayload{Verdict: "skipped", Reason: motivo}
		if got := marcaProyecto(p); got == "✓" {
			t.Errorf("motivo %q: la lista marca el proyecto con ✓, que el panel "+
				"rotula «limpio — el último commit pasó todas las compuertas»", motivo)
		}
	}
	// Y lo que sí es un pass sigue llevando su ✓: sin esto, "arreglarlo"
	// quitando el ✓ de todas partes pasaría.
	if got := marcaProyecto(&panelPayload{Verdict: "pass"}); got != "✓" {
		t.Errorf("un pass de verdad perdió su ✓: llegó %q", got)
	}
	if got := marcaProyecto(&panelPayload{Verdict: "block"}); got != "⛔" {
		t.Errorf("un bloqueo perdió su ⛔: llegó %q", got)
	}
}
