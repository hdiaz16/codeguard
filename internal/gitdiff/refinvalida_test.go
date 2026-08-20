package gitdiff

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// H021 — la mitad del agujero que el arreglo de H009 dejó abierta, y la que
// convertía ese arreglo en una falsa sensación de seguridad.
//
// H009 puso la validación de refs DENTRO del motor de gitleaks. Pero `codeguard
// ci` no empieza por el motor: empieza por aquí (main.go llama a Range antes de
// montar el pipeline), y Range recibía el MISMO --base sin mirarlo y se lo daba
// a git. Con --base "--output=/ruta", git deja de ver un rango y ve una opción:
//
//   - el diff sale con CERO archivos,
//   - el pipeline corta en la etapa 0 con "todos los archivos tocados están
//     excluidos" y devuelve Skipped,
//   - la etapa de secretos NO LLEGA A CORRER,
//   - y el proceso termina con EXIT 0.
//
// Con el fix de H009 puesto y todo en verde: exit 0 y el secreto sin detectar.
// La compuerta no se saltaba forzándola, se saltaba haciendo que no hubiera
// nada que analizar — que es el modo de fallo más caro de este repo y el que ya
// nos costó los 28 hallazgos del episodio de los acentos.
//
// Y no es sólo lectura: git ACEPTA ese --output y CREA el archivo en disco, así
// que el valor de --base elige dónde escribir.
func TestRangeNoLeDaARefSinValidarAGit(t *testing.T) {
	repo := repoDePrueba(t)

	// Directorio propio y vacío: así la comprobación no depende de adivinar el
	// nombre exacto que git derive. Range concatena base+".."+head, de modo que
	// el archivo que git crea se llama "pwned..HEAD", no "pwned". Comprobar sólo
	// el nombre "pwned" daría verde con el archivo escrito al lado.
	trampas := t.TempDir()
	pwned := filepath.Join(trampas, "pwned")

	d, err := Range(repo, "--output="+pwned, "HEAD")

	if err == nil {
		archivos := 0
		if d != nil {
			archivos = len(d.Files)
		}
		t.Fatalf("una ref inválida debe fallar de forma ruidosa; devolvió un diff con %d archivo(s) y ningún error", archivos)
	}
	if err != nil && !strings.Contains(err.Error(), "--base") {
		t.Errorf("el error debe decir qué flag venía mal para que se pueda arreglar: %v", err)
	}

	entradas, lerr := os.ReadDir(trampas)
	if lerr != nil {
		t.Fatal(lerr)
	}
	if len(entradas) != 0 {
		var nombres []string
		for _, e := range entradas {
			nombres = append(nombres, e.Name())
		}
		t.Errorf("el valor de --base escribió en disco: %v", nombres)
	}

	// Lo que de verdad dolía: un diff vacío SIN error es indistinguible de "no
	// cambió nada", y el pipeline lo trata como tal. Si esto vuelve a pasar, la
	// compuerta de secretos se salta entera y en verde.
	if err == nil && len(d.Files) == 0 {
		t.Error("diff vacío y sin error: el pipeline lo leerá como 'nada que analizar' y se saltará la etapa de secretos")
	}
}

// El head es la otra mitad de la puerta.
func TestRangeTampocoSeFiaDelHead(t *testing.T) {
	repo := repoDePrueba(t)
	if _, err := Range(repo, "HEAD~1", "HEAD --all"); err == nil {
		t.Error("un head con espacios y opciones debe rechazarse antes de llegar a git")
	} else if !strings.Contains(err.Error(), "--head") {
		t.Errorf("el error debe nombrar el flag culpable: %v", err)
	}
}

// La contraparte imprescindible: sin esto, un Range que rechazara TODO dejaría
// pasar las dos pruebas de arriba sin leer un solo diff. Y la rama va con
// acento a propósito — es la regresión por la que el primer arreglo se rechazó.
func TestRangeSigueLeyendoElDiffDeVerdad(t *testing.T) {
	repo := repoDePrueba(t)
	escribir(t, repo, "nuevo.go", "package p\n\nfunc Nuevo() {}\n")
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-q", "-m", "segundo")
	git(t, repo, "branch", "corrección-h009")

	for _, head := range []string{"HEAD", "corrección-h009"} {
		d, err := Range(repo, "HEAD~1", head)
		if err != nil {
			t.Fatalf("el rango legítimo HEAD~1..%s debió leerse: %v", head, err)
		}
		if len(d.Files) != 1 || d.Files[0].Path != "nuevo.go" {
			t.Errorf("HEAD~1..%s: se esperaba nuevo.go, se obtuvo %+v", head, d.Files)
		}
		if !strings.Contains(d.Unified, "func Nuevo()") {
			t.Errorf("HEAD~1..%s: el diff unificado no trae el cambio", head)
		}
	}
}

// La segunda capa, probada saltándose la primera a propósito: se llama a `read`
// directamente con el valor envenenado, que es lo que pasaría si la validación
// tuviera un hueco o si mañana alguien añade un llamador que no valide.
//
// --end-of-options (git 2.24+) le dice a git que ahí se acabaron las opciones,
// así que el "--output=..." se queda en argumento posicional: git muere con
// exit 128 en vez de escribir el archivo. Sin él, esto crea el archivo y
// devuelve exit 0, que es justo como H021 se colaba.
func TestEndOfOptionsFrenaAunqueLaValidacionSeSalte(t *testing.T) {
	repo := repoDePrueba(t)
	trampas := t.TempDir()

	_, err := read(repo, nil, []string{"--output=" + filepath.Join(trampas, "pwned") + "..HEAD"})
	if err == nil {
		t.Error("git aceptó una opción en el sitio del rango: --end-of-options no está haciendo su trabajo")
	}

	entradas, lerr := os.ReadDir(trampas)
	if lerr != nil {
		t.Fatal(lerr)
	}
	if len(entradas) != 0 {
		var nombres []string
		for _, e := range entradas {
			nombres = append(nombres, e.Name())
		}
		t.Errorf("git escribió en disco pese a --end-of-options: %v", nombres)
	}
}

// Defensa en profundidad: aunque la validación fallara o alguien añadiera un
// llamador nuevo que no valide, git no debe interpretar como bandera un valor
// que ocupa el sitio del rango. --end-of-options existe desde git 2.24 justo
// para esto.
//
// La prueba mira el modo staged, que es el que corre en CADA commit: si el
// reordenado de argumentos que hace falta para meter --end-of-options rompiera
// algo, se rompería aquí.
func TestStagedSigueFuncionandoConElOrdenNuevo(t *testing.T) {
	repo := repoDePrueba(t)
	escribir(t, repo, "otro.go", "package p\n\nfunc Otro() {}\n")
	git(t, repo, "add", "otro.go")

	d, err := Staged(repo)
	if err != nil {
		t.Fatalf("Staged: %v", err)
	}
	if len(d.Files) != 1 || d.Files[0].Path != "otro.go" {
		t.Errorf("se esperaba otro.go staged, se obtuvo %+v", d.Files)
	}
}
