package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codeguard/internal/config"
	"codeguard/internal/finding"
	"codeguard/internal/pipeline"
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

// encabezado devuelve solo la cabecera del informe, hasta las instrucciones.
//
// Hace falta porque el bloque de instrucciones NOMBRA los dos veredictos para
// explicarselos al agente ("cuando ... dira COMPLETADO", "si dice PARCIAL"), y
// un Contains sobre el archivo entero encuentra las dos palabras siempre. La
// primera version de estas pruebas fallo justo por eso: media el texto que
// habla del veredicto en vez del veredicto.
func encabezado(informe string) string {
	if i := strings.Index(informe, "## Instrucciones"); i > 0 {
		return informe[:i]
	}
	return informe
}

// Un informe no puede declarar COMPLETADO lo que no reviso.
//
// Es el fallo que motivo este cambio, y era el peor de su familia: con el
// rulepack sin instalar, el encabezado decia "✅ COMPLETADO — no quedan
// hallazgos bloqueantes" con las reglas de la casa SIN EJECUTAR. Y unas lineas
// mas abajo, el mismo archivo le dice al agente de codigo que ese encabezado
// "es el criterio de terminado, no tu impresion de haber terminado". Una
// maquina leyendo eso da el trabajo por bueno con la compuerta apagada.
func TestNoDiceCompletadoSiUnaCapaNoCorrio(t *testing.T) {
	cfg := &config.Config{Rulepack: "2026.08.2"}
	res := &pipeline.Result{Degraded: []string{"rulepack-ausente:2099.99.9"}}

	informe := encabezado(construirInforme(cfg, res, nil, nil, nil, nil, false, false, ""))

	if strings.Contains(informe, "COMPLETADO") {
		t.Error("declara COMPLETADO sin haber aplicado las reglas de la casa")
	}
	if !strings.Contains(informe, "PARCIAL") {
		t.Error("no avisa de que el analisis esta incompleto")
	}
	// El aviso tiene que decir QUE falto y QUE hacer, no la etiqueta cruda.
	if !strings.Contains(informe, "reglas de la casa NO se aplicaron") {
		t.Error("no explica que se dejo de revisar")
	}
	if !strings.Contains(informe, "codeguard repair") {
		t.Error("no dice como arreglarlo")
	}
}

// Y el reverso, que es lo que impide que el aviso se vuelva ruido de fondo: si
// todo corrio y no hay bloqueantes, COMPLETADO sigue significando completado.
// Un aviso permanente se aprende a ignorar, y entonces no sirve el dia que
// importa.
func TestSinCapasCaidasSigueDiciendoCompletado(t *testing.T) {
	cfg := &config.Config{Rulepack: "2026.08.2"}
	res := &pipeline.Result{}

	informe := encabezado(construirInforme(cfg, res, nil, nil, nil, nil, false, false, ""))

	if !strings.Contains(informe, "COMPLETADO") {
		t.Error("con todo revisado y sin bloqueantes deberia decir COMPLETADO")
	}
	if strings.Contains(informe, "PARCIAL") {
		t.Error("avisa de un analisis incompleto que si estaba completo")
	}
}

// Con bloqueantes Y capas caidas hay que decir las dos cosas: arreglar lo que
// se ve no significa que ya no quede nada.
func TestConBloqueantesTambienAvisaDeLoQueNoCorrio(t *testing.T) {
	cfg := &config.Config{Rulepack: "2026.08.2"}
	res := &pipeline.Result{Degraded: []string{"semgrep:error"}}
	bloq := []finding.Finding{{RuleKey: "x", File: "a.go", Line: 1, Message: "m"}}

	informe := encabezado(construirInforme(cfg, res, bloq, nil, nil, nil, false, false, ""))

	if !strings.Contains(informe, "1 bloqueante") {
		t.Error("no reporta el bloqueante")
	}
	if !strings.Contains(informe, "INCOMPLETO") {
		t.Error("con un motor caido, arreglar lo visible no basta y hay que decirlo")
	}
}

// Las etiquetas se escribieron para el log. Si llegan crudas al informe, el
// aviso solo lo entiende quien escribio el codigo.
func TestLasEtiquetasSeTraducen(t *testing.T) {
	casos := map[string]string{
		"daemon:offline": "en frío",
		"trivy:plazo":    "no cupo en el plazo",
		"falta:mypy":     "no está instalado",
		"eslint:error":   "falló y no revisó nada",
	}
	for etiqueta, esperado := range casos {
		got := explicarCapas([]string{etiqueta})
		if len(got) != 1 {
			t.Fatalf("%s: esperaba una explicacion, hubo %d", etiqueta, len(got))
		}
		if !strings.Contains(got[0], esperado) {
			t.Errorf("%s se explico como %q, esperaba que mencionara %q", etiqueta, got[0], esperado)
		}
	}
	if len(explicarCapas(nil)) != 0 {
		t.Error("sin capas caidas no debe inventar avisos")
	}
}
