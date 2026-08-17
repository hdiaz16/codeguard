package main

import (
	"testing"

	"codeguard/internal/capas"
	"codeguard/internal/config"
	"codeguard/internal/ipc"
)

// La cabecera del panel tiene que decirle al dev DOS cosas que hasta ahora no
// salían por ninguna parte: qué stack detectó CodeGuard en su repo, y qué
// motores le están vigilando.
//
// Las dos las pidió él con esas palabras: "no le decimos al dev qué stack tiene
// su repo" y "deben saber qué motores se eligieron para su repo". El dato ya
// existía en los dos casos —`languages:` en el config, el estado por capa en el
// análisis— y moría antes de llegar a la pantalla.
func TestElPayloadLlevaElStackYLosMotores(t *testing.T) {
	cfg := &config.Config{Languages: []string{"go", "python", "sql", "typescript"}}
	req := &ipc.Request{RepoRoot: t.TempDir(), Branch: "master"}
	resp := &ipc.Response{
		Verdict: "pass",
		Capas: []capas.Capa{
			{Motor: "gitleaks", Estado: capas.Corrio, Ms: 120},
			{Motor: "squawk", Estado: capas.NoAplica, Detalle: "sin migraciones en el cambio"},
			{Motor: "trivy", Estado: capas.Ausente, Detalle: "no está instalado en esta máquina"},
		},
	}

	payload := construirPayload(req, resp, cfg, 7)

	if len(payload.Languages) != 4 || payload.Languages[0] != "go" {
		t.Errorf("el stack detectado tiene que viajar al panel; llegó %v", payload.Languages)
	}
	if len(payload.Capas) != 3 {
		t.Fatalf("las capas tienen que viajar completas, incluidas las que no corrieron; llegó %+v", payload.Capas)
	}
	// La que NO corrió es justo la que no puede perderse: una lista que sólo
	// enseña los motores que corrieron le dice al dev que trivy no existe.
	var vistas []string
	for _, c := range payload.Capas {
		vistas = append(vistas, c.Motor)
		if c.Cayo() && c.Detalle == "" {
			t.Errorf("%s cayó sin motivo: en la cabecera saldría un aviso que no se puede accionar", c.Motor)
		}
	}
	for _, quiero := range []string{"gitleaks", "squawk", "trivy"} {
		if !contiene(joinComa(vistas), quiero) {
			t.Errorf("falta %s en la cabecera: %v", quiero, vistas)
		}
	}
}

// Sin config no se inventa un stack. Un repo cuyo config no se pudo leer no
// tiene "ningún lenguaje": tiene un problema, y el panel no debe presentar lo
// segundo como lo primero.
func TestSinConfigNoSeInventaStack(t *testing.T) {
	payload := construirPayload(&ipc.Request{RepoRoot: t.TempDir()}, &ipc.Response{Verdict: "skipped"}, nil, 7)
	if len(payload.Languages) != 0 {
		t.Errorf("sin config el stack va vacío, no adivinado: %v", payload.Languages)
	}
}

func joinComa(s []string) string {
	out := ""
	for _, x := range s {
		out += x + ","
	}
	return out
}
