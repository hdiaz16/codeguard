package daemon

import (
	"os/exec"
	"slices"
	"testing"
)

// LA GUARDA QUE HACE SEGURA LA TABLA.
//
// `requisitos` es un mapa escrito a mano, y un mapa escrito a mano se queda
// viejo: el día que alguien añada un motor a Engines() nadie se acordará de
// tocarlo, y ese motor pasaría a contarse como "puede correr" sin que nadie lo
// haya comprobado nunca. Eso es sobre-declarar cobertura, que es el fallo caro
// —el que no se nota— y es justo el que este trabajo entero viene a arreglar.
//
// Con esta prueba, añadir un motor sin decidir qué necesita pone el paquete en
// rojo. La decisión puede ser "no se comprueba"; lo que no puede es no tomarse.
func TestCadaMotorDeclaraQueNecesitaParaCorrer(t *testing.T) {
	for _, motor := range Engines(nil, false, nil) {
		if _, ok := requisitos[motor.Name()]; !ok {
			t.Errorf("el motor %q no dice qué necesita para correr.\n"+
				"Sin una entrada en `requisitos` se contaría como disponible sin haberlo "+
				"comprobado, y el panel prometería una capa que quizá no arranca. Añádelo, "+
				"aunque sea con requisito \"\" (no se comprueba).", motor.Name())
		}
	}
	// Y al revés: una entrada de un motor que ya no existe es ruido que hace
	// creer que algo está cubierto cuando no hay nada que cubrir.
	vivos := make(map[string]bool)
	for _, motor := range Engines(nil, false, nil) {
		vivos[motor.Name()] = true
	}
	for nombre := range requisitos {
		if !vivos[nombre] {
			t.Errorf("`requisitos` menciona %q, que ya no está en Engines()", nombre)
		}
	}
}

// El requisito de cada motor tiene que ser el ejecutable que ESE motor invoca
// de verdad, no uno parecido. Si aquí pusiéramos "node" donde el motor llama a
// "npx", tendríamos otra vez dos criterios para la misma pregunta.
//
// No puedo comprobar automáticamente que el mapa case con el código de cada
// motor —eso es leer 16 archivos—, así que lo que fija esta prueba es el
// resultado de haberlos leído: si alguien cambia un requisito, tiene que venir
// aquí y justificar el cambio.
func TestLosRequisitosSonLosEjecutablesQueLosMotoresInvocan(t *testing.T) {
	quiero := map[string]string{
		"semgrep":     "semgrep",     // semgrep.go: bin = "semgrep"
		"squawk":      "squawk",      // squawk.go: bin = "squawk"
		"trivy":       "trivy",       // trivy.go: bin = "trivy"
		"govulncheck": "govulncheck", // govulncheck.go: bin = "govulncheck"
		"staticcheck": "staticcheck", // staticcheck.go: bin = "staticcheck"
		"ruff":        "ruff",        // ruff.go: bin = "ruff"
		"mypy":        "mypy",        // mypy.go: exec.CommandContext(ctx, "mypy", …)
		"govet":       "go",          // govet.go: runTool(…, "go", …)
		"gofmt":       "",            // no lanza nada: formatea en proceso
		// Vacíos A PROPÓSITO, y este es el sitio donde queda constancia de por
		// qué. Su binario sale del node_modules DEL PROYECTO y sólo cae a
		// `npx --no-install` si no está. Comprobar "npx" diría "puede correr"
		// cuando no puede: medido, en esta máquina npx existe y aun así
		// `--no-install` falla sin el paquete en el repo. Entre callar y
		// prometer de más, se calla — lo corto se nota y se corrige, lo falso no
		// se nota nunca.
		"tsc":                "",
		"eslint":             "",
		"dotnet-format":      "dotnet", // dotnetformat.go: LookPath("dotnet")
		"dotnet-build":       "dotnet", // dotnetbuild.go: LookPath("dotnet")
		"dotnet-vuln":        "dotnet", // dotnetvuln.go: LookPath("dotnet")
		"google-java-format": "java",   // javafmt.go: exec.CommandContext(ctx, "java", …)
		"pmd":                "java",   // javalint.go: exec.CommandContext(ctx, "java", …)
	}
	for motor, esperado := range quiero {
		if got := requisitos[motor]; got != esperado {
			t.Errorf("%s necesita %q y la tabla dice %q", motor, esperado, got)
		}
	}
	// Y al revés, que es el sentido que faltaba: la otra prueba sólo exige que
	// `requisitos` case con Engines(), así que nada obligaba a pasar por aquí. Un
	// motor añadido a la tabla sin justificación nunca se contrastaba con el
	// ejecutable que invoca DE VERDAD, y la tabla volvía a ser el mapa escrito a
	// mano que se queda viejo — justo lo que este archivo existe para impedir.
	for motor := range requisitos {
		if _, ok := quiero[motor]; !ok {
			t.Errorf("%q está en `requisitos` pero no tiene justificación en esta prueba. "+
				"Añádelo a `quiero` con el ejecutable que el motor invoca de verdad —o \"\" si "+
				"no se comprueba— y di por qué, como se hizo con tsc y eslint.", motor)
		}
	}
}

// gofmt no puede salir nunca como "no disponible": no lanza ningún proceso,
// formatea dentro del propio codeguard. Decir que no puede correr sería
// imposible de arreglar para quien lo lea.
func TestGofmtNuncaSaleComoNoDisponible(t *testing.T) {
	d := Disponibilidad([]string{"gofmt"})
	if len(d) != 0 {
		t.Errorf("gofmt corre dentro del proceso y salió como no disponible: %v", d)
	}
}

// cambiaRequisito apunta un motor a otro ejecutable durante una prueba y lo
// devuelve a su sitio al terminar, pase lo que pase dentro.
//
// Muta el mapa global `requisitos`, y por eso las pruebas de este archivo son
// INCOMPATIBLES con t.Parallel(): dos en paralelo se pisarían el valor y
// Disponibilidad leería la tabla a medio cambiar, con fallos intermitentes que
// nadie sabría de dónde salen. Hoy ninguna lo usa. Si algún día hiciera falta,
// el arreglo es que Disponibilidad reciba la tabla por parámetro, no poner
// candados alrededor de un global.
func cambiaRequisito(t *testing.T, motor, ejecutable string) {
	t.Helper()
	original := requisitos[motor]
	requisitos[motor] = ejecutable
	t.Cleanup(func() { requisitos[motor] = original })
}

// Un motor que esta máquina NO tiene sale nombrado, con su motivo. Se usa un
// requisito imposible para no depender de qué haya instalado hoy en el disco de
// nadie: una prueba que dependa de eso pasa aquí y falla en otra máquina.
func TestUnMotorSinSuEjecutableSaleNombradoConMotivo(t *testing.T) {
	cambiaRequisito(t, "semgrep", "no-existe-este-ejecutable-cg")

	d := Disponibilidad([]string{"semgrep", "gofmt"})
	if len(d) != 1 || d[0].Motor != "semgrep" {
		t.Fatalf("esperaba sólo semgrep como no disponible: %v", d)
	}
	if d[0].Motivo == "" {
		t.Error("un motor caído sin motivo no le sirve a nadie: hay que decir qué falta")
	}
	if !slices.Contains([]string{"no-existe-este-ejecutable-cg"}, d[0].Falta) {
		t.Errorf("el motivo tiene que nombrar el ejecutable que falta: %+v", d[0])
	}
}

// Sólo se pregunta por las capas que se le pasan. Preguntar por las 16 cuando
// el repo tiene 3 haría que el panel avisara de un tsc ausente a alguien que no
// escribe TypeScript — ruido sobre una capa que no le afecta.
func TestSoloSePreguntaPorLasCapasDelRepo(t *testing.T) {
	cambiaRequisito(t, "mypy", "no-existe-este-ejecutable-cg")

	if d := Disponibilidad([]string{"semgrep", "gofmt"}); len(d) != 0 {
		t.Errorf("nadie preguntó por mypy y salió igual: %v", d)
	}
	if d := Disponibilidad([]string{"mypy"}); len(d) != 1 {
		t.Errorf("se preguntó por mypy, que falta, y no salió: %v", d)
	}
}

// El control que impide que todo lo de arriba pase por la razón equivocada: un
// ejecutable que SÍ existe en cualquier máquina donde se compile esto no puede
// salir como ausente.
func TestUnEjecutableQueSiEstaNoSaleComoAusente(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("sin go en el PATH no hay control que hacer")
	}
	if d := Disponibilidad([]string{"govet"}); len(d) != 0 {
		t.Errorf("go está en el PATH y govet salió como no disponible: %v", d)
	}
}
