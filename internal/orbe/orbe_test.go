package orbe

import (
	"bytes"
	"image/png"
	"sync"
	"testing"
	"unicode"
	"unicode/utf8"
)

var todosLosEstados = []string{"idle", "working", "pass", "blocked", "degraded", "offline"}

// TestPNGConcurrente reproduce el uso real: el ícono de la bandeja se pide
// desde varias goroutines a la vez (callbacks de IPC, temporizadores y
// handlers de menú), así que PNG tiene que aguantar lecturas del cache
// simultáneas con escrituras de claves nuevas. Con el mapa desnudo esto
// dispara "DATA RACE" bajo -race, o directamente mata al proceso con
// "fatal error: concurrent map read and map write".
func TestPNGConcurrente(t *testing.T) {
	// Los tamaños chicos son los de la bandeja según el DPI del monitor; 256
	// es el ícono de la ventana y del "acerca de".
	tamanos := []int{16, 20, 24, 32, 40, 48, 256}

	// Precalentamos los de 256 a propósito, por dos razones: son los caros de
	// dibujar, y así la carrera es la real —unas goroutines leyendo claves ya
	// presentes mientras otras insertan claves nuevas y el mapa crece—, no
	// sólo escritura contra escritura.
	for _, e := range todosLosEstados {
		_ = PNG(256, e)
	}

	const goroutines = 100
	arranque := make(chan struct{})
	var wg sync.WaitGroup

	// Cada goroutine guarda lo que obtuvo para poder comprobar después que
	// todas vieron los mismos bytes para la misma clave: un cache con carrera
	// puede además devolver una entrada a medio escribir.
	obtenidos := make([]map[int][]byte, goroutines)
	estados := make([]string, goroutines)

	for i := range goroutines {
		estado := todosLosEstados[i%len(todosLosEstados)]
		estados[i] = estado
		obtenidos[i] = make(map[int][]byte, len(tamanos))

		wg.Add(1)
		go func(i int, estado string) {
			defer wg.Done()
			<-arranque // todas salen a la vez, para que la ventana sea ancha
			for _, tamano := range tamanos {
				// Cada vuelta mezcla una clave ya cacheada (256) con una que
				// puede ser nueva: lectura y escritura conviven en el mismo
				// instante, que es justo lo que el mapa desnudo no tolera.
				_ = PNG(256, estado)
				obtenidos[i][tamano] = PNG(tamano, estado)
			}
		}(i, estado)
	}
	close(arranque)
	wg.Wait()

	// Mismo (tamaño, estado) ⇒ mismos bytes, siempre.
	type clave struct {
		tamano int
		estado string
	}
	porClave := map[clave][]byte{}
	for i := range goroutines {
		for tamano, b := range obtenidos[i] {
			k := clave{tamano, estados[i]}
			if len(b) == 0 {
				t.Fatalf("PNG(%d, %q) devolvió vacío", k.tamano, k.estado)
			}
			antes, ok := porClave[k]
			if !ok {
				porClave[k] = b
				continue
			}
			if !bytes.Equal(antes, b) {
				t.Errorf("PNG(%d, %q) devolvió bytes distintos entre goroutines",
					k.tamano, k.estado)
			}
		}
	}
}

// TestPNGTamanosDistintosNoColisionan fija la corrección de la clave del
// cache. La versión con string(rune(tamano)) no es inyectiva: cualquier
// tamaño que no sea un punto de código válido (negativos, sustitutos)
// colapsa en U+FFFD, así que dos tamaños distintos comparten entrada y el
// segundo recibe el PNG del primero. Los tamaños degenerados de aquí son el
// canario barato de ese defecto; con 16/32/256 hoy funciona de casualidad.
func TestPNGTamanosDistintosNoColisionan(t *testing.T) {
	for _, caso := range []struct{ a, b int }{{-1, -2}, {16, 24}} {
		anchoA := anchoPNG(t, PNG(caso.a, "idle"))
		anchoB := anchoPNG(t, PNG(caso.b, "idle"))
		if anchoA == anchoB {
			t.Errorf("PNG(%d) y PNG(%d) devolvieron la misma imagen (ancho %d): las claves del cache colisionan",
				caso.a, caso.b, anchoA)
		}
	}
}

// TestClaveEsUnicaYLegible fija la construcción de la clave del cache. La
// versión vieja, estado + ":" + string(rune(tamano)), metía caracteres de
// control (16 es \x10, 24 es \x18) y mandaba a U+FFFD todo tamaño que no
// fuera un punto de código válido, con lo que tamaños distintos terminaban
// compartiendo entrada.
func TestClaveEsUnicaYLegible(t *testing.T) {
	vistos := map[string]int{}
	for _, tamano := range []int{-2, -1, 0, 16, 20, 24, 32, 48, 256, 0xD800, 0xD801, 0x110000} {
		k := clave(tamano, "idle")
		if otro, ok := vistos[k]; ok {
			t.Errorf("los tamaños %d y %d comparten la clave %q", otro, tamano, k)
		}
		vistos[k] = tamano
		for _, r := range k {
			if unicode.IsControl(r) || r == utf8.RuneError {
				t.Errorf("clave(%d, \"idle\") = %q: lleva la runa %U", tamano, k, r)
			}
		}
	}
	if k := clave(16, "idle"); k != "idle:16" {
		t.Errorf("clave(16, \"idle\") = %q, se esperaba \"idle:16\"", k)
	}
}

// TestPNGDevuelveElTamanoPedido protege lo que de verdad le importa a la
// bandeja: que el PNG cacheado mida lo que se pidió.
func TestPNGDevuelveElTamanoPedido(t *testing.T) {
	for _, tamano := range []int{16, 24, 32, 256} {
		for _, estado := range todosLosEstados {
			if ancho := anchoPNG(t, PNG(tamano, estado)); ancho != tamano {
				t.Errorf("PNG(%d, %q) mide %d px", tamano, estado, ancho)
			}
		}
	}
}

// TestPNGMemoiza comprueba que el cache sigue siendo un cache: la segunda
// llamada devuelve exactamente lo mismo que la primera.
func TestPNGMemoiza(t *testing.T) {
	primera := PNG(24, "blocked")
	segunda := PNG(24, "blocked")
	if !bytes.Equal(primera, segunda) {
		t.Error("dos llamadas al mismo (tamaño, estado) devolvieron bytes distintos")
	}
}

func anchoPNG(t *testing.T, b []byte) int {
	t.Helper()
	img, err := png.Decode(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("no se pudo decodificar el PNG: %v", err)
	}
	return img.Bounds().Dx()
}
