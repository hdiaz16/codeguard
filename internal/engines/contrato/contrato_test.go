package contrato

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// La sonda de identidad se lanza cuando el motor acaba de terminar sin encontrar
// nada, o sea con el presupuesto del gancho casi gastado. Así que agotar el plazo
// aquí no es raro: es el caso normal de una primera corrida en frío.
//
// Y el orquestador distingue las dos cosas con errors.Is: `context.DeadlineExceeded`
// se etiqueta "motor:plazo" («no terminó a tiempo», se arregla solo en la corrida
// siguiente) y cualquier otro error se etiqueta "motor:error", que manda al
// desarrollador a buscar una avería que no existe. Si el centinela viaja como
// texto dentro del mensaje, errors.Is no lo ve.
func TestUnPlazoAgotadoLlegaComoPlazoYNoComoAveria(t *testing.T) {
	OlvidarTodo()
	ctx, cancelar := context.WithTimeout(context.Background(), 0)
	defer cancelar()

	err := Identidad(ctx, Version("prueba", nombreDeGo(t), "version",
		regexp.MustCompile(`go\d`), "irrelevante"))
	if err == nil {
		t.Fatal("con el plazo agotado no se puede dar la identidad por buena")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("el centinela del plazo no sobrevive al envoltorio, así que el orquestador "+
			"etiquetará «error» en vez de «plazo» y mandará a buscar una avería inexistente: %v", err)
	}
}

// Y el control: con plazo de sobra, la herramienta de verdad se identifica y no
// hay error. Sin esto, la prueba de arriba pasaría con una función que devolviera
// error siempre.
func TestConTiempoLaHerramientaDeVerdadSeIdentifica(t *testing.T) {
	OlvidarTodo()
	if err := Identidad(context.Background(), Version("prueba", nombreDeGo(t), "version",
		regexp.MustCompile(`go\d`), "irrelevante")); err != nil {
		t.Fatalf("`go version` dice quién es: %v", err)
	}
}

// La respuesta que no se reconoce tiene que llegar con el texto dentro, porque es
// lo único que le queda a quien luego lo diagnostique desde el log.
func TestUnaRespuestaAjenaLoDiceConElTexto(t *testing.T) {
	OlvidarTodo()
	err := Identidad(context.Background(), Version("prueba", nombreDeGo(t), "version",
		regexp.MustCompile(`ESTO-NO-LO-DICE-NADIE`), "haz esto otro"))
	if err == nil {
		t.Fatal("una respuesta que no casa no puede pasar por buena")
	}
	if !strings.Contains(err.Error(), "go version") {
		t.Errorf("el error tiene que traer lo que contestó: %v", err)
	}
	if !strings.Contains(err.Error(), "haz esto otro") {
		t.Errorf("el error tiene que traer la pista de qué hacer: %v", err)
	}
}

// El veredicto se memoriza por binario, y tiene que hacerlo: el daemon vive días
// y no va a preguntar la versión en cada commit. Lo que NO puede es sobrevivir a
// que la herramienta cambie.
func TestLaMemoriaCaducaCuandoLaHerramientaCambia(t *testing.T) {
	OlvidarTodo()
	dir := t.TempDir()
	// Un ejecutable propio, para poder cambiarlo por debajo.
	falso := filepath.Join(dir, "herramienta.exe")
	fuente := filepath.Join(dir, "main.go")
	compilar := func(cuerpo string) {
		t.Helper()
		if err := os.WriteFile(fuente, []byte(cuerpo), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module falsa\n\ngo 1.21\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		c := exec.Command("go", "build", "-o", falso, ".")
		c.Dir = dir
		if out, err := c.CombinedOutput(); err != nil {
			t.Skipf("no se pudo compilar la herramienta de prueba: %v\n%s", err, out)
		}
	}
	compilar("package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(\"soy-la-buena 1.0\") }\n")

	prueba := Version("prueba", falso, "--version", regexp.MustCompile(`soy-la-buena`), "pista")
	if err := Identidad(context.Background(), prueba); err != nil {
		t.Fatalf("la herramienta buena se identifica: %v", err)
	}
	// Ahora se sustituye por otra que NO se identifica. Si la memoria no caducara,
	// el veredicto viejo la absolvería — y eso es exactamente el fallo que todo
	// este trabajo retira, con un caché en medio.
	compilar("package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(\"soy otra cosa\") }\n")
	if err := Identidad(context.Background(), prueba); err == nil {
		t.Error("la herramienta cambió y el veredicto memorizado la sigue absolviendo: " +
			"la clave tiene que llevar tamaño y fecha del binario")
	}
}

// nombreDeGo devuelve el ejecutable de Go, que es la herramienta de verdad más a
// mano para probar el mecanismo sin depender de ningún motor.
func nombreDeGo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("sin toolchain de Go no hay a quién preguntar")
	}
	return "go"
}
