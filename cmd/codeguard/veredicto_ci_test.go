package main

import (
	"strings"
	"testing"

	"codeguard/internal/finding"
	"codeguard/internal/pipeline"
)

// El render del CI contra el outcome derivado, no contra un Result crudo:
// estos tests fijan el CONTRATO de la primera línea del log. La mentira que
// entierran estaba medida (cabecera de garantia.go y bitácora 2026-08-22):
// printSummary imprimía «OK — 0 bloqueantes» y el bloque de garantía, que
// corría después y aparte, imprimía «NO PUEDO GARANTIZAR» con exit 1 — el
// mismo log diciendo las dos cosas, en ese orden.

func renderCI(t *testing.T, o pipeline.AnalysisOutcome, fs []finding.Finding) string {
	t.Helper()
	var b strings.Builder
	printSummary(&b, o, fs)
	return b.String()
}

func TestUnAnalisisSinGarantiaYaNoAbreConOK(t *testing.T) {
	res := &pipeline.Result{Verdict: pipeline.Pass, AdvisoryFindings: 2,
		Degraded: []string{"rulepack-ausente:2026.08.2"}}
	salida := renderCI(t, pipeline.Finalizar(res, "", nil), nil)

	if strings.Contains(salida, "OK —") {
		t.Errorf("la garantía está rota y el log volvió a abrir con OK:\n%s", salida)
	}
	if !strings.Contains(salida, "SIN GARANTÍA") {
		t.Errorf("la primera línea tiene que decir la verdad del veredicto:\n%s", salida)
	}
	if !strings.Contains(salida, "NO PUEDO GARANTIZAR ESTE COMMIT — rulepack-ausente:2026.08.2") {
		t.Errorf("la capa rota concreta tiene que nombrarse:\n%s", salida)
	}
}

// El invariante de render del consejo (turno 67): bloqueado Y garantía rota se
// dicen los DOS. Sin esto, el dev arregla el bloqueante, commitea otra vez, y
// la compuerta que no miró le llega como sorpresa en el segundo intento.
func TestBloqueadoConGarantiaRotaMuestraAmbos(t *testing.T) {
	res := &pipeline.Result{Verdict: pipeline.Block, BlockingFindings: 1,
		Degraded: []string{"semgrep:error", "daemon:offline"}}
	salida := renderCI(t, pipeline.Finalizar(res, "", nil), nil)

	if !strings.Contains(salida, "BLOQUEADO") {
		t.Errorf("el estado es Bloqueado y no se dijo:\n%s", salida)
	}
	if !strings.Contains(salida, "NO PUEDO GARANTIZAR ESTE COMMIT — semgrep:error") {
		t.Errorf("la garantía rota se calló porque «ya estaba bloqueado»:\n%s", salida)
	}
	if strings.Contains(salida, "GARANTIZAR ESTE COMMIT — semgrep:error, daemon:offline") {
		t.Errorf("una política deliberada (daemon:offline) se presentó como garantía rota:\n%s", salida)
	}
}

func TestSoloLimpioYConAvisosPuedenDecirOK(t *testing.T) {
	limpio := renderCI(t, pipeline.Finalizar(&pipeline.Result{Verdict: pipeline.Pass}, "", nil), nil)
	if !strings.Contains(limpio, "OK — 0 bloqueantes, 0 aviso(s)") {
		t.Errorf("un análisis completo y limpio tiene derecho a su OK:\n%s", limpio)
	}
	// Y una política deliberada no le roba el OK: diff_too_large está anunciada.
	deliberada := renderCI(t, pipeline.Finalizar(&pipeline.Result{Verdict: pipeline.Pass,
		Degraded: []string{"deterministic:diff_too_large"}}, "", nil), nil)
	if !strings.Contains(deliberada, "OK —") {
		t.Errorf("una política deliberada no es garantía rota y no puede tumbar el OK:\n%s", deliberada)
	}
	if !strings.Contains(deliberada, "capas degradadas: deterministic:diff_too_large") {
		t.Errorf("la política anunciada igual se lista, como siempre:\n%s", deliberada)
	}
}

func TestElPlazoAgotadoTraeSuRemedio(t *testing.T) {
	res := &pipeline.Result{Verdict: pipeline.Pass, Degraded: []string{"semgrep:plazo"}}
	salida := renderCI(t, pipeline.Finalizar(res, "", nil), nil)
	if !strings.Contains(salida, "REINTENTA EL JOB") {
		t.Errorf("un :plazo sin su remedio manda a buscar bugs donde hubo una máquina ocupada:\n%s", salida)
	}
}

func TestElRenderDeCINoInventaEstados(t *testing.T) {
	omitido := renderCI(t, pipeline.Finalizar(&pipeline.Result{Verdict: pipeline.Skipped,
		Reason: pipeline.MotivoSinDiff}, "", nil), nil)
	if !strings.Contains(omitido, "análisis omitido — "+pipeline.MotivoSinDiff) {
		t.Errorf("el omitido perdió su motivo:\n%s", omitido)
	}
	fallido := renderCI(t, pipeline.Finalizar(nil, pipeline.FalloPipeline,
		errTest("git no respondió")), nil)
	if !strings.Contains(fallido, "el análisis FALLÓ (pipeline) — git no respondió") {
		t.Errorf("un fallo tiene que decir fase y causa, no disfrazarse:\n%s", fallido)
	}
}

type errTest string

func (e errTest) Error() string { return string(e) }
