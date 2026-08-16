package identidad

import (
	"os"
	"path/filepath"
	"testing"
)

// N003 — la compuerta de identidad firmando una instalación que no existe.
//
// `DirMotores()` devuelve "" cuando no puede resolver una ruta absoluta (ese fue
// el arreglo de N001). Pero Verificar no comprobaba ese caso, y
// `filepath.Join("", rel)` no da una ruta vacía: deja la ruta RELATIVA, que se
// resuelve contra el directorio de trabajo — durante un commit, el repo que se
// está analizando.
//
// El resultado medido con el binario, en un repo que traía copias auténticas de
// gitleaks.exe y trivy.exe en su raíz:
//
//	LOCALAPPDATA= codeguard engines  → "no se pudo resolver %LOCALAPPDATA%"   (guardado)
//	LOCALAPPDATA= codeguard repair   → "ok  gitleaks v8.30.0 (binario publicado)"
//
// No hay ejecución de por medio, y por eso es menos grave que N001. Pero es la
// compuerta de identidad —el comando que existe para responder "¿son estos los
// motores que publicaron sus autores?"— contestando que sí sobre binarios que
// puso el repositorio. Una tranquilidad falsa sobre justo lo que se viene a
// comprobar.
//
// La guarda va en Verificar y no en sus dos llamadores porque el invariante es
// suyo: "sin directorio no se verifica nada". Es la lección de N001 —arreglar un
// llamador deja el agujero en el siguiente— y aquí el siguiente ya existía:
// `codeguard engines` estaba guardado y `codeguard repair` no.
func TestSinDirectorioDeMotoresNoSeVerificaNada(t *testing.T) {
	// Un directorio de trabajo con un señuelo, para que la prueba distinga
	// "no encontró nada" de "no miró": si Verificar resolviera contra el CWD,
	// aquí tendría algo que encontrar.
	trabajo := t.TempDir()
	for _, n := range []string{"gitleaks.exe", "trivy.exe"} {
		if err := os.WriteFile(filepath.Join(trabajo, n), []byte("señuelo del repo"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(trabajo)

	res := Verificar("")
	if len(res) == 0 {
		t.Fatal("Verificar no devolvió ningún motor: la prueba no distinguiría nada")
	}
	for _, r := range res {
		if r.Estado != NoEvaluable {
			t.Errorf("%s: sin directorio de motores el estado debe ser %q y fue %q (ruta %q). "+
				"Cualquier otro veredicto es una afirmación sobre un archivo que no sabemos de dónde salió",
				r.Motor, NoEvaluable, r.Estado, r.Ruta)
		}
	}
}

// La contraparte: con un directorio legítimo, Verificar sigue haciendo su
// trabajo. Sin esto, "arreglarlo" devolviendo siempre NoEvaluable pasaría.
func TestConDirectorioValidoSeSigueVerificando(t *testing.T) {
	res := Verificar(t.TempDir())
	if len(res) == 0 {
		t.Fatal("Verificar no devolvió ningún motor")
	}
	for _, r := range res {
		if r.Estado == NoEvaluable {
			t.Errorf("%s: con un directorio válido (aunque vacío) el estado debe ser %q, no %q",
				r.Motor, Ausente, r.Estado)
		}
	}
}
