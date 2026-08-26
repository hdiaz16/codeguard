package daemon

import (
	"testing"

	"codeguard/internal/config"
	"codeguard/internal/engines/politicared"
)

// Toda capa del pipeline tiene su política de red DECLARADA en el registro
// (W4, Q4). El fail-closed silencioso —lo no declarado corre frenado— es la
// red de seguridad, no la licencia para no declarar: un motor nuevo tiene que
// PENSAR su política antes de escribir una línea.
//
// La versión anterior de este test decía exigir eso y no podía: preguntaba por
// el valor de RedDe(nombre), que jamás devuelve nada fuera de los tres estados
// porque lo desconocido cae en denegado. Su rama `default` era inalcanzable y
// el test pasaba con cualquier registro, incluso vacío. Se descubrió al
// cablear la política el 2026-08-25: actionlint, psscriptanalyzer y shellcheck
// llevaban desde W7 sin declarar y nadie se enteró. Ahora se pregunta por la
// PRESENCIA con Declarada(), que es la pregunta que el test creía hacer.
func TestTodaCapaDeclaraSuRed(t *testing.T) {
	cfg := &config.Config{}
	declarados := 0
	for _, eng := range Engines(cfg, false, nil) {
		nombre := eng.Name()
		if !politicared.Declarada(nombre) {
			t.Errorf("el motor %s no declara su política de red: añádelo al registro de politicared "+
				"(correrá frenado por fail-closed, pero eso es la red, no la decisión)", nombre)
			continue
		}
		declarados++
	}
	// gitleaks corre en la etapa 1 (no está en Engines) pero también declara.
	if !politicared.Declarada("gitleaks") {
		t.Error("gitleaks debía declarar su política de red")
	}
	if politicared.De("gitleaks") != politicared.RedDenegada {
		t.Error("gitleaks debía declarar red denegada")
	}
	if declarados < 15 {
		t.Fatalf("solo %d motores pasaron por el registro: la lista del pipeline cambió y este test ya no la cubre", declarados)
	}
}

// Los DOS únicos motores con red durante el análisis, fijados por nombre.
//
// Es la contraparte del test de arriba: aquel exige que todos declaren, este
// exige que casi ninguno pida red. Un tercer motor con red no es
// necesariamente un error, pero sí una decisión que alguien tiene que tomar a
// conciencia y actualizar aquí — no algo que se cuele en una revisión.
func TestSoloDosMotoresPidenRed(t *testing.T) {
	conRed := map[string]bool{}
	cfg := &config.Config{}
	for _, eng := range Engines(cfg, false, nil) {
		if politicared.RequiereRedDuranteAnalisis(eng.Name()) {
			conRed[eng.Name()] = true
		}
	}
	esperados := map[string]bool{"govulncheck": true, "dotnet-vuln": true}
	for n := range conRed {
		if !esperados[n] {
			t.Errorf("%s pide red durante el análisis y no estaba previsto: si es correcto, dilo aquí y en el threat model", n)
		}
	}
	for n := range esperados {
		if !conRed[n] {
			t.Errorf("%s ya no pide red: si dejó de necesitarla, su declaración debe bajar a denegada", n)
		}
	}
	// trivy es el caso que justifica el tri-estado: su red existe, pero ocurre
	// fuera del motor (internal/trivydb baja la BD) y durante el análisis corre
	// frenado como cualquier otro.
	if politicared.De("trivy") != politicared.RedSoloActualizar {
		t.Errorf("trivy debía declarar update-only, declara %q", politicared.De("trivy"))
	}
	if politicared.RequiereRedDuranteAnalisis("trivy") {
		t.Error("update-only NO puede conceder red durante el análisis: la proyección se escribió como «todo lo que no sea denegado»")
	}
}
