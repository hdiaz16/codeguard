package codegraph

import (
	"os"
	"path/filepath"
	"testing"
)

// El grafo de Go se extrae con el AST y SIN go/types, así que la resolución de
// llamadas es un heurístico. Estos son los primeros tests del paquete y fijan su
// frontera: qué arista se emite, y —sobre todo— cuál NO.
//
// La regla es asimétrica a propósito: una arista que falta es un límite declarado
// del heurístico; una arista falsa es una dependencia que no existe dibujada en
// el explorador, y sobre ese dibujo un agente decide dónde tocar.

func repoDePrueba(t *testing.T, archivos map[string]string) string {
	t.Helper()
	raiz := t.TempDir()
	if err := os.WriteFile(filepath.Join(raiz, "go.mod"), []byte("module ejemplo\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for ruta, cuerpo := range archivos {
		abs := filepath.Join(raiz, filepath.FromSlash(ruta))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte(cuerpo), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return raiz
}

func aristas(t *testing.T, g *Graph) map[string]bool {
	t.Helper()
	m := map[string]bool{}
	for _, e := range g.Edges {
		m[e.From+" -> "+e.To] = true
	}
	return m
}

// DOS MÉTODOS HOMÓNIMOS DE TIPOS DISTINTOS NO PUEDEN RECIBIR LA MISMA ARISTA.
//
// Era el defecto: byName indexa por nombre simple, y cualquier x.Cerrar()
// repartía arista a TODOS los Cerrar() del repo. Aquí el llamante tiene un
// receptor de tipo conocido, así que la arista sólo puede ir a SU método.
func TestUnaLlamadaAMetodoNoSalpicaALosHomonimos(t *testing.T) {
	raiz := repoDePrueba(t, map[string]string{
		"almacen/almacen.go": `package almacen

type Puerta struct{}

func (p *Puerta) Cerrar() {}

type Ventana struct{}

func (v *Ventana) Cerrar() {}

func (p *Puerta) Rutina() {
	p.Cerrar()
}
`,
		"otro/otro.go": `package otro

type Grifo struct{}

func (g *Grifo) Cerrar() {}
`,
	})
	g, err := BuildGo(raiz)
	if err != nil {
		t.Fatal(err)
	}
	e := aristas(t, g)
	if !e["almacen.Puerta.Rutina -> almacen.Puerta.Cerrar"] {
		t.Errorf("se perdió la arista deducible por el receptor; aristas: %v", e)
	}
	if e["almacen.Puerta.Rutina -> almacen.Ventana.Cerrar"] {
		t.Error("arista falsa al Cerrar de OTRO tipo del mismo paquete")
	}
	if e["almacen.Puerta.Rutina -> otro.Grifo.Cerrar"] {
		t.Error("arista falsa al Cerrar de otro PAQUETE: la dependencia no existe")
	}
}

// Una llamada calificada por paquete (fmt.Sprintf, almacen.Abrir) sí se puede
// resolver: los imports del archivo dicen que la izquierda del punto es un
// paquete. Y sólo puede apuntar a una FUNCIÓN de ese paquete, nunca a un método.
func TestUnaLlamadaConPaqueteResuelveAlPaqueteImportado(t *testing.T) {
	raiz := repoDePrueba(t, map[string]string{
		"almacen/almacen.go": `package almacen

func Abrir() {}
`,
		"gemelo/gemelo.go": `package gemelo

func Abrir() {}
`,
		"app/app.go": `package app

import "ejemplo/almacen"

func Arrancar() {
	almacen.Abrir()
}
`,
	})
	g, err := BuildGo(raiz)
	if err != nil {
		t.Fatal(err)
	}
	e := aristas(t, g)
	if !e["app.Arrancar -> almacen.Abrir"] {
		t.Errorf("se perdió la arista al paquete importado; aristas: %v", e)
	}
	if e["app.Arrancar -> gemelo.Abrir"] {
		t.Error("arista falsa al homónimo de un paquete que NI SE IMPORTA")
	}
}

// LO QUE SE PIERDE, DICHO EXPLÍCITAMENTE: cuando la izquierda del punto no es un
// identificador con tipo deducible —un campo de struct, el retorno de una
// función—, no hay arista. Es el precio de no inventarlas, y queda fijado aquí
// para que nadie lo lea como un defecto nuevo.
func TestLaLlamadaAmbiguaNoEmiteArista(t *testing.T) {
	raiz := repoDePrueba(t, map[string]string{
		"almacen/almacen.go": `package almacen

type Puerta struct{}

func (p *Puerta) Cerrar() {}

type Casa struct {
	puerta *Puerta
}

func (c *Casa) Salir() {
	c.puerta.Cerrar()
}
`,
	})
	g, err := BuildGo(raiz)
	if err != nil {
		t.Fatal(err)
	}
	if e := aristas(t, g); e["almacen.Casa.Salir -> almacen.Puerta.Cerrar"] {
		t.Error("se emitió una arista por un campo de struct: sin go/types no se " +
			"puede saber el tipo, y acertar por casualidad hoy es inventar mañana")
	}
}

// El identificador desnudo sigue acotado a su paquete (lo cerró el lote anterior;
// queda fijado porque no había test).
func TestUnIdentificadorDesnudoNoCruzaDePaquete(t *testing.T) {
	raiz := repoDePrueba(t, map[string]string{
		"uno/uno.go": `package uno

func Validar() {}

func Correr() {
	Validar()
}
`,
		"dos/dos.go": `package dos

func Validar() {}
`,
	})
	g, err := BuildGo(raiz)
	if err != nil {
		t.Fatal(err)
	}
	e := aristas(t, g)
	if !e["uno.Correr -> uno.Validar"] {
		t.Errorf("se perdió la arista dentro del paquete; aristas: %v", e)
	}
	if e["uno.Correr -> dos.Validar"] {
		t.Error("un identificador desnudo cruzó de paquete")
	}
}
