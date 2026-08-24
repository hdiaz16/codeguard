package ipc

import (
	"encoding/json"
	"testing"

	"codeguard/internal/pipeline"
)

// El contrato del veredicto en el cable: lo derivado viaja tal cual (ida y
// vuelta por JSON incluida, que es como viaja de verdad) y lo desconocido
// NUNCA cae hacia «pasó» (turno 67). Un hook que malinterprete en silencio la
// versión siguiente del formato es como nacen los veredictos que mienten.

func TestElOutcomeCruzaElCableEntero(t *testing.T) {
	res := &pipeline.Result{
		Verdict:          pipeline.Block,
		BlockingFindings: 2,
		AdvisoryFindings: 1,
		Suppressed:       3,
		Degraded:         []string{"semgrep:error", "daemon:offline"},
	}
	resp := &Response{
		BlockingFindings: 2, AdvisoryFindings: 1, Suppressed: 3,
		Degraded: res.Degraded,
		Outcome:  DeOutcome(pipeline.Finalizar(res, "", nil)),
	}
	crudo, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	var llegado Response
	if err := json.Unmarshal(crudo, &llegado); err != nil {
		t.Fatal(err)
	}
	if llegado.Outcome == nil {
		t.Fatal("el outcome no sobrevivió al viaje por JSON")
	}
	o := llegado.Outcome.AOutcome(&llegado)
	if o.Estado != pipeline.Bloqueado {
		t.Errorf("Estado = %q tras el viaje", o.Estado)
	}
	if len(o.GarantiaRota) != 1 || o.GarantiaRota[0] != "semgrep:error" {
		t.Errorf("GarantiaRota = %v: la derivación del daemon se perdió o se re-hizo", o.GarantiaRota)
	}
	if o.Bloqueantes != 2 || o.Avisos != 1 || o.Suprimidos != 3 {
		t.Errorf("los contadores del Response no se ensamblaron: %+v", o)
	}
	if !o.Bloquea() {
		t.Error("un Bloqueado que no bloquea")
	}
}

func TestUnaVersionDesconocidaDelCableNoSeFingeEntendida(t *testing.T) {
	w := &WireOutcome{Version: WireOutcomeVersion + 1, State: "clean"}
	o := w.AOutcome(&Response{})
	if o.Estado != pipeline.Fallido || o.FalloEn != pipeline.FalloDesconocido {
		t.Errorf("una versión futura del formato se leyó como %q: el desconocido "+
			"jamás cae hacia «pasó»", o.Estado)
	}
}

func TestUnEstadoDesconocidoDelCableNoSeFingeEntendido(t *testing.T) {
	w := &WireOutcome{Version: WireOutcomeVersion, State: "estupendo"}
	o := w.AOutcome(&Response{})
	if o.Estado != pipeline.Fallido || o.FalloEn != pipeline.FalloDesconocido {
		t.Errorf("un estado inventado se aceptó como %q", o.Estado)
	}
}

// El fallo tipado cruza con su fase: es lo que le permite al hook distinguir
// «arregla tu YAML» de «reporta un bug» sin parsear textos (turno 67).
func TestElFalloCruzaConSuFase(t *testing.T) {
	resp := &Response{Outcome: DeOutcome(pipeline.Finalizar(nil, pipeline.FalloConfig, errCable("yaml roto")))}
	crudo, _ := json.Marshal(resp)
	var llegado Response
	if err := json.Unmarshal(crudo, &llegado); err != nil {
		t.Fatal(err)
	}
	o := llegado.Outcome.AOutcome(&llegado)
	if o.Estado != pipeline.Fallido || o.FalloEn != pipeline.FalloConfig || o.Fallo != "yaml roto" {
		t.Errorf("el fallo llegó desfigurado: %+v", o)
	}
	if o.Bloquea() {
		t.Error("un fallo de config no es fail-closed: el commit pasa con aviso")
	}
}

type errCable string

func (e errCable) Error() string { return string(e) }
