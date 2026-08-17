package store

import (
	"path/filepath"
	"testing"
)

// La otra puerta a la MISMA base de datos, con la guarda a medias.
//
// `dirDatos()` en cmd/codeguard ya impone que la ruta sea ABSOLUTA. DefaultPath
// —que abre el mismo archivo desde cachecmd, daemoncmd, statscmd, synccmd y el
// panel— sólo comprobaba que LOCALAPPDATA no fuera la cadena vacía. Con un valor
// en blanco o relativo las dos funciones dejan de coincidir: una manda al
// temporal y la otra devuelve algo como `.\   \codeguard\codeguard.db`, relativo
// al directorio de trabajo — que durante un commit es el repo que se analiza.
//
// Dos consecuencias, y la segunda es peor que la primera: el usuario acaba con
// DOS bases de datos distintas según por qué comando entre, y una de ellas
// dentro de su repositorio, donde puede acabar commiteada.
//
// Es la misma clase que H007 (config), N001 (ejecución) y N003 (identidad), y la
// lección que dejaron: la guarda va donde se resuelve la ruta, no en cada
// llamador. Aquí faltaba generalizarla a la segunda puerta del mismo archivo.
func TestLaRutaPorDefectoNuncaEsRelativa(t *testing.T) {
	casos := []struct {
		nombre string
		valor  string
	}{
		{"variable ausente", ""},
		{"variable en blanco", "   "},
		{"valor relativo puesto a mano", filepath.Join("datos", "local")},
		{"punto", "."},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			t.Setenv("LOCALAPPDATA", c.valor)
			ruta := DefaultPath()
			if ruta == "" {
				return // no hay dónde escribir y se dice: es la respuesta honesta
			}
			if !filepath.IsAbs(ruta) {
				t.Errorf("LOCALAPPDATA=%q dio la ruta relativa %q: la base de datos "+
					"acabaría dentro del directorio de trabajo, que durante un commit "+
					"es el repo que se está analizando", c.valor, ruta)
			}
		})
	}
}

// La contraparte, para que "arreglarlo" devolviendo siempre "" no pase: con una
// LOCALAPPDATA normal la ruta sigue saliendo donde siempre.
func TestConLocalappdataNormalLaRutaNoCambia(t *testing.T) {
	base := t.TempDir()
	t.Setenv("LOCALAPPDATA", base)

	ruta := DefaultPath()
	esperada := filepath.Join(base, "codeguard", "codeguard.db")
	if ruta != esperada {
		t.Errorf("DefaultPath() = %q, esperaba %q", ruta, esperada)
	}
}
