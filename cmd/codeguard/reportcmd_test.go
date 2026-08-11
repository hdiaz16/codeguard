package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// El informe instruye al agente: "anota los falsos positivos en Discrepancias
// y un humano decide despues". Y cada `codeguard report` reconstruia el
// archivo y borraba la anotacion antes de que ningun humano la viera. Las dos
// mitades del contrato se contradecian; estas pruebas fijan la reparacion.

func escribirInforme(t *testing.T, contenido string) string {
	t.Helper()
	ruta := filepath.Join(t.TempDir(), "HALLAZGOS.md")
	if err := os.WriteFile(ruta, []byte(contenido), 0o644); err != nil {
		t.Fatal(err)
	}
	return ruta
}

func TestDiscrepanciasAnotadasSobreviven(t *testing.T) {
	ruta := escribirInforme(t, `# Hallazgos de CodeGuard

## ⛔ Bloqueantes (1)

### 1. `+"`go-dinero-float`"+` — internal/config/config.go:107
<!-- fp:aaaa -->

---

## Discrepancias

<!-- El agente anota aquí lo que considere falso positivo, con su razón.
     Un humano decide después: corregir la regla o aceptar el hallazgo. -->

- go-dinero-float sobre PriceInPerMTok: son TARIFAS que escribe un humano,
  no dinero acumulado. Propongo baseline permanente.

---

## Contexto
`)
	got := leerDiscrepanciasPrevias(ruta)
	if !strings.Contains(got, "TARIFAS que escribe un humano") {
		t.Errorf("la anotación del agente se perdió:\n%q", got)
	}
	// El comentario-guía no es una anotación: no debe acumularse en cada
	// regeneración como copia de sí mismo.
	if strings.Contains(got, "<!--") {
		t.Errorf("el comentario de plantilla no debe conservarse como contenido:\n%q", got)
	}
}

func TestDiscrepanciasVaciasNoInventanContenido(t *testing.T) {
	ruta := escribirInforme(t, `# Hallazgos de CodeGuard

---

## Discrepancias

<!-- El agente anota aquí lo que considere falso positivo, con su razón.
     Un humano decide después: corregir la regla o aceptar el hallazgo. -->

---

## Contexto
`)
	if got := leerDiscrepanciasPrevias(ruta); got != "" {
		t.Errorf("sólo había plantilla; se devolvió: %q", got)
	}

	// Sin archivo previo (primer report del repo) tampoco hay nada.
	if got := leerDiscrepanciasPrevias(filepath.Join(t.TempDir(), "no-existe.md")); got != "" {
		t.Errorf("sin informe previo debía ser vacío: %q", got)
	}

	// Y un informe viejo sin la sección (formatos anteriores) no revienta.
	sinSeccion := escribirInforme(t, "# Hallazgos de CodeGuard\n\n## Contexto\n")
	if got := leerDiscrepanciasPrevias(sinSeccion); got != "" {
		t.Errorf("sin sección Discrepancias debía ser vacío: %q", got)
	}
}
