package main

import (
	"os"
	"path/filepath"
	"testing"

	"codeguard/internal/config"
	"codeguard/internal/pipeline"
)

// La base de datos jamás puede acabar dentro del árbol de trabajo.
//
// persistRun componía `filepath.Join(os.Getenv("LOCALAPPDATA"), "codeguard")` y
// comprobaba el resultado contra `filepath.Join("", "codeguard")`, que vale
// "codeguard". O sea que atrapaba EXACTAMENTE el caso LOCALAPPDATA="" y ningún
// otro: con "   " sale `   \codeguard` y con un valor relativo sale
// `datos\local\codeguard`, los dos relativos, los dos se colaban. Y como el
// directorio de trabajo durante un commit es el repo que se está analizando, la
// BD y su directorio se creaban DENTRO del repo del usuario.
//
// Es la misma clase de razonamiento indirecto que causó H007 (config) y N001
// (ejecución): deducir la propiedad que se quiere —"esto es una ruta absoluta"—
// comparando contra una cadena construida, en vez de comprobarla.
//
// Se prueba por el efecto y no por el valor devuelto: lo que le importa a quien
// commitea es que no le aparezcan archivos en su repo.
func TestLaBaseDeDatosNuncaSeCreaDentroDelArbolDeTrabajo(t *testing.T) {
	casos := []struct {
		nombre       string
		localappdata string
	}{
		{"sin LOCALAPPDATA (runner de CI)", ""},
		{"LOCALAPPDATA en blanco", "   "},
		{"LOCALAPPDATA con una ruta relativa", filepath.Join("datos", "local")},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			// Hace de repo que se está analizando: durante un hook, el
			// directorio de trabajo ES el repo del usuario.
			trabajo := t.TempDir()
			t.Chdir(trabajo)
			t.Setenv("LOCALAPPDATA", c.localappdata)

			// El error da igual: la telemetría nunca tumba el análisis (P4) y el
			// directorio se crea antes que cualquier fallo posterior.
			_ = persistRun(trabajo, &config.Config{},
				&pipeline.Result{Verdict: pipeline.Pass},
				pipeline.Finalizar(&pipeline.Result{Verdict: pipeline.Pass}, "", nil), 0, false, "prueba")

			entradas, err := os.ReadDir(trabajo)
			if err != nil {
				t.Fatal(err)
			}
			if len(entradas) > 0 {
				var nombres []string
				for _, e := range entradas {
					nombres = append(nombres, e.Name())
				}
				t.Errorf("se escribió dentro del árbol de trabajo: %v.\n"+
					"Durante un commit eso es el repo del usuario: aparecen archivos "+
					"que él no creó, y que git le ofrece añadir al siguiente commit.",
					nombres)
			}
		})
	}
}

// Y la otra mitad: con un LOCALAPPDATA legítimo la BD tiene que ir ahí.
//
// Sin esto, el arreglo de arriba se "consigue" mandándolo todo al temporal, y
// entonces el historial de runs se borra en cada limpieza del sistema sin que
// nadie entienda por qué.
func TestConLocalappdataValidoLaBaseDeDatosVaAhi(t *testing.T) {
	trabajo := t.TempDir()
	datos := t.TempDir() // absoluto, como el LOCALAPPDATA de verdad
	t.Chdir(trabajo)
	t.Setenv("LOCALAPPDATA", datos)

	if err := persistRun(trabajo, &config.Config{},
		&pipeline.Result{Verdict: pipeline.Pass},
		pipeline.Finalizar(&pipeline.Result{Verdict: pipeline.Pass}, "", nil), 0, false, "prueba"); err != nil {
		t.Fatalf("con LOCALAPPDATA válido no debería fallar: %v", err)
	}

	if _, err := os.Stat(filepath.Join(datos, "codeguard", "codeguard.db")); err != nil {
		t.Errorf("la BD no está en %s: %v", filepath.Join(datos, "codeguard"), err)
	}
}
