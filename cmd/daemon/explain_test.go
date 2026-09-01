package main

import (
	"os"
	"strings"
	"testing"
)

func TestExplicacionesSoloAceptanIDsSolicitadosYUnaVez(t *testing.T) {
	got, err := parsearExplicaciones(`{"explanations":[
		{"id":"pedido","text":"  explicación útil  "},
		{"id":"ajeno","text":"inyectada"},
		{"id":"pedido","text":"duplicada"}]}`, map[string]string{"pedido": "clave"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "pedido" || got[0].Text != "explicación útil" {
		t.Fatalf("aduana de explicaciones = %+v", got)
	}
}

func TestExplicacionTieneTopeYLaCacheIncluyeContexto(t *testing.T) {
	larga := strings.Repeat("x", maxRunasExplicacion+50)
	got, err := parsearExplicaciones(`{"explanations":[{"id":"f","text":"`+larga+`"}]}`,
		map[string]string{"f": "clave"})
	if err != nil {
		t.Fatal(err)
	}
	if len([]rune(got[0].Text)) != maxRunasExplicacion+1 || !strings.HasSuffix(got[0].Text, "…") {
		t.Fatalf("la explicación no se acotó: %d runas", len([]rune(got[0].Text)))
	}
	base := claveExplicacion("fp", "mensaje", "impacto", "arreglo", "código A")
	if base == claveExplicacion("fp", "mensaje", "impacto", "arreglo", "código B") {
		t.Error("la caché reutilizaría una explicación sobre otro contexto")
	}
}

func TestPanelIdentificaLaExplicacionComoIA(t *testing.T) {
	raw, err := os.ReadFile("frontend/index.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "Sugerencia contextual de IA · verifica antes de aplicar") {
		t.Error("el panel mezcla la sugerencia del modelo con el hallazgo verificado")
	}
}
