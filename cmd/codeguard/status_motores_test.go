package main

import (
	"strings"
	"testing"

	"codeguard/internal/config"
	"codeguard/internal/engines/identidad"
)

func TestEstadoMotoresDelRepoNoDeclaraSanoUnMotorAplicableQueNoArranca(t *testing.T) {
	cfg := &config.Config{Languages: []string{"go", "java"}}
	got := estadoMotoresDelRepo(cfg, []identidad.Resultado{
		{Motor: "gitleaks", Critico: true, Estado: identidad.Verificado},
		{Motor: "google-java-format", Estado: identidad.NoArranca, Detalle: "requiere Java 21"},
	})
	if got.ok || !strings.Contains(got.detalle, "google-java-format") {
		t.Fatalf("se esperaba degradación explícita, got=%+v", got)
	}
}

func TestEstadoMotoresDelRepoIgnoraJavaCuandoNoAplica(t *testing.T) {
	cfg := &config.Config{Languages: []string{"go"}}
	got := estadoMotoresDelRepo(cfg, []identidad.Resultado{
		{Motor: "gitleaks", Critico: true, Estado: identidad.Verificado},
		{Motor: "google-java-format", Estado: identidad.NoArranca, Detalle: "requiere Java 21"},
	})
	if !got.ok {
		t.Fatalf("un motor no aplicable no debe degradar el repo: %+v", got)
	}
}
