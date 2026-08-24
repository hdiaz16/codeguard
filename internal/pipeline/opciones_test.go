package pipeline

import (
	"context"
	"strings"
	"testing"

	"codeguard/internal/config"
	"codeguard/internal/gitdiff"
)

// Run tolera Config nil con un veredicto controlado, pero daba por hecho que el
// diff siempre venía: la etapa 0 lo desreferenciaba sin comprobarlo. Un cambio
// sin archivos que mirar no es un fallo del sistema, es un análisis que se
// salta.
//
// Se comprueba el MOTIVO y no sólo el veredicto porque desde que el hook lee
// res.Verdict, un Skipped se imprime en la terminal acompañado de su Reason: si
// el motivo viniera vacío o fuera el de otra cosa, el usuario leería "no se
// analizó nada" seguido de una explicación que no corresponde. Y porque sin
// mirarlo, esta prueba daría por bueno un Skipped por CUALQUIER causa.
func TestRunSinDiffSeSalta(t *testing.T) {
	cfg := &config.Config{Rulepack: "test", RepoRoot: t.TempDir(), MaxDiffLines: 2000}

	res, err := Run(context.Background(), Options{Config: cfg, Diff: nil})
	if err != nil {
		t.Fatalf("no esperaba error: %v", err)
	}
	if res.Verdict != Skipped {
		t.Errorf("esperaba veredicto %q, hubo %q", Skipped, res.Verdict)
	}
	if res.Reason == "" {
		t.Error("un análisis omitido sin motivo llega al hook como «no se analizó nada» a secas: " +
			"el usuario no puede saber si es un merge, una exclusión o una llamada mal armada")
	}
	if !strings.Contains(res.Reason, "diff") {
		t.Errorf("el motivo debe hablar del diff que falta, y dijo %q", res.Reason)
	}
	// Y no puede confundirse con el otro Skipped temprano, que es el que ya
	// existía: dos causas distintas no pueden contar la misma historia.
	sinConfig, err := Run(context.Background(), Options{Config: nil, Diff: nil})
	if err != nil {
		t.Fatalf("no esperaba error: %v", err)
	}
	if sinConfig.Reason == res.Reason {
		t.Errorf("el diff ausente y el repo no enrolado dan el mismo motivo (%q): "+
			"el hook enseñaría una causa por otra", res.Reason)
	}
}

// El control positivo, sin el cual lo de arriba no prueba nada: un Run que
// devolviera Skipped SIEMPRE pasaría la prueba anterior con nota. Con un diff de
// verdad, la etapa 0 tiene que dejar pasar el análisis.
func TestConDiffDeVerdadRunNoSeSalta(t *testing.T) {
	cfg := &config.Config{Rulepack: "test", RepoRoot: t.TempDir(), MaxDiffLines: 2000}
	diff := &gitdiff.Diff{
		Files: []gitdiff.ChangedFile{{Path: "a.go", Status: "M"}},
		Lines: 1,
	}

	res, err := Run(context.Background(), Options{Config: cfg, Diff: diff})
	if err != nil {
		t.Fatalf("no esperaba error: %v", err)
	}
	if res.Verdict == Skipped {
		t.Fatalf("con un archivo que mirar el análisis no puede omitirse (motivo: %q).\n"+
			"Sin esta comprobación, «devolver Skipped siempre» pasaría por arreglo y la "+
			"herramienta dejaría de analizar sin que ninguna prueba se pusiera roja", res.Reason)
	}
	if res.Reason != "" {
		t.Errorf("un análisis que SÍ corrió no puede traer motivo de omisión: %q", res.Reason)
	}
}
