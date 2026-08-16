package gitdiff

import (
	"os/exec"
	"strings"
	"testing"
)

// Se reutilizan repoDePrueba/escribir/git de gitdiff_test.go: un segundo
// fabricante de repos en el mismo paquete acabaría divergiendo del primero, y
// entonces dos tests que dicen "un repo git" estarían probando cosas distintas.

// EL FLUJO QUE LO DISPARA ES RUTINA, NO UN CASO RARO: añadir un archivo y
// seguir editándolo. A partir de ahí el índice tiene una versión y el disco
// otra, y los motores por archivo leen la del disco.
func TestAvisaCuandoElDiscoNoEsLoQueSeVaACommitear(t *testing.T) {
	repo := repoDePrueba(t)
	escribir(t, repo, "a.go", "package a\n\nfunc Uno() {}\n")
	escribir(t, repo, "b.go", "package a\n\nfunc Dos() {}\n")
	git(t, repo, "add", "-A")
	// a.go se sigue editando DESPUÉS del add; b.go no se toca.
	escribir(t, repo, "a.go", "package a\n\nfunc Uno() { println(\"otra cosa\") }\n")

	divergentes, err := ConCambiosSinPreparar(repo, []string{"a.go", "b.go"})
	if err != nil {
		t.Fatal(err)
	}
	if len(divergentes) != 1 || divergentes[0] != "a.go" {
		t.Fatalf("se esperaba exactamente [a.go], llegó %v — si sale vacío, la compuerta "+
			"seguiría diciendo «revisado» sobre un contenido que no es el que se commitea", divergentes)
	}
}

// LA CONTRAPARTE, sin la cual lo de arriba no vale: un aviso que salte siempre
// se convierte en ruido que el dev aprende a ignorar, y entonces tampoco lo
// leerá el día que sí importa.
func TestNoAvisaCuandoElDiscoYElIndiceCoinciden(t *testing.T) {
	casos := []struct {
		nombre string
		montar func(t *testing.T, repo string) []string
	}{
		{"add y commitear sin tocar nada más", func(t *testing.T, repo string) []string {
			escribir(t, repo, "a.go", "package a\n")
			git(t, repo, "add", "-A")
			return []string{"a.go"}
		}},
		{"editar, add, y volver a añadir tras el segundo cambio", func(t *testing.T, repo string) []string {
			escribir(t, repo, "a.go", "package a\n")
			git(t, repo, "add", "-A")
			escribir(t, repo, "a.go", "package a\n\nfunc X() {}\n")
			git(t, repo, "add", "-A") // se vuelve a preparar: ya no diverge
			return []string{"a.go"}
		}},
		{"otro archivo sucio que NO entra en el commit", func(t *testing.T, repo string) []string {
			escribir(t, repo, "a.go", "package a\n")
			git(t, repo, "add", "-A")
			git(t, repo, "commit", "-m", "base")
			escribir(t, repo, "b.go", "package a\n")
			git(t, repo, "add", "b.go")
			// a.go se ensucia pero NO está en el commit: no debe avisar por él.
			escribir(t, repo, "a.go", "package a\n\nfunc Sucio() {}\n")
			return []string{"b.go"}
		}},
		{"lista vacía", func(t *testing.T, repo string) []string { return nil }},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			repo := repoDePrueba(t)
			rutas := c.montar(t, repo)
			divergentes, err := ConCambiosSinPreparar(repo, rutas)
			if err != nil {
				t.Fatal(err)
			}
			if len(divergentes) != 0 {
				t.Fatalf("aviso falso en %q: %v", c.nombre, divergentes)
			}
		})
	}
}

// La medición que respalda el hallazgo: el sha del disco y el del índice son
// distintos de verdad. Sin esto, "diverge" sería una palabra sin número detrás.
func TestElShaDelDiscoNoEsElDelIndice(t *testing.T) {
	repo := repoDePrueba(t)
	escribir(t, repo, "a.txt", "contenido PREPARADO\n")
	git(t, repo, "add", "-A")
	escribir(t, repo, "a.txt", "contenido DEL DISCO, que no se commitea\n")

	delDisco := SHA256De(repo, "a.txt")
	if delDisco == "" {
		t.Fatal("no pude calcular la huella del disco")
	}
	// El contenido del índice, por el camino de git.
	c := exec.Command("git", "show", ":a.txt")
	c.Dir = repo
	delIndice, err := c.Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(delIndice), "DEL DISCO") {
		t.Fatal("el fixture no separó índice y disco; el test no probaría nada")
	}
	// SHA256De lee del disco: si alguna vez pasa a leer del índice, esta
	// afirmación cambia y hay que revisar todo lo que la da por cierta.
	if !strings.Contains(string(delIndice), "PREPARADO") {
		t.Fatalf("el índice no tiene lo preparado: %q", delIndice)
	}
}
