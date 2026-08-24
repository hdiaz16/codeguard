package registry

import (
	"os"
	"path/filepath"
	"testing"
)

// El registro de proyectos jamás puede acabar dentro del repo que se analiza.
//
// `path()` resolvía `%LOCALAPPDATA%` con la guarda `base == ""`, que atrapa
// exactamente el caso de la variable ausente y ningún otro: con "   " sale
// `   \codeguard\repos.json` y con un valor relativo sale
// `datos\local\codeguard\repos.json`. Los dos son RELATIVOS, y relativo
// significa relativo al directorio de trabajo — que durante un commit es el
// repositorio del usuario. Y aquí no sólo se lee: `path()` hace MkdirAll y Add
// escribe, así que al desarrollador le aparece un `codeguard\repos.json` dentro
// de su árbol que git le ofrece añadir al commit siguiente.
//
// Es la misma clase que H007 (config), N001 (ejecución), N003 (identidad) y la
// BD de runs, y la misma lección: la guarda va donde se RESUELVE la ruta, y
// comprobar la propiedad que se quiere —`filepath.IsAbs`— en vez de deducirla
// comparando contra la cadena vacía.
//
// Se prueba por el efecto y no por el valor devuelto porque `path()` no es
// pública y porque lo que le importa a quien commitea es que no le aparezcan
// archivos en su repo.
func TestElRegistroNuncaSeEscribeDentroDelArbolDeTrabajo(t *testing.T) {
	casos := []struct {
		nombre       string
		localappdata string
	}{
		{"variable ausente", ""},
		{"variable en blanco", "   "},
		{"valor relativo", filepath.Join("datos", "local")},
		{"punto", "."},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			// Hace de repo que se está analizando: durante un hook, el
			// directorio de trabajo ES el repo del usuario.
			trabajo := t.TempDir()
			t.Chdir(trabajo)
			t.Setenv("LOCALAPPDATA", c.localappdata)

			// El bool de Remove NO se descarta, y esa es la mitad que faltaba:
			// «el árbol de trabajo quedó limpio» se cumple igual de bien si Add
			// no llegó a escribir nada, así que sin comprobar que el ciclo
			// ocurrió de verdad este test podría pasar por no haber hecho nada
			// —el verde silencioso de siempre—. Remove devuelve true sólo si
			// encontró la entrada que Add escribió, o sea que exige que el
			// registro haya funcionado, y en el fallback %TEMP%\codeguard,
			// porque estos LOCALAPPDATA no son absolutos. Mismo uso del bool
			// que hace registry_test.go.
			//
			// Se registra `trabajo` y no un `trabajo\proyecto` inventado: Load
			// purga —y reescribe— las entradas cuyo Root no existe en disco
			// (registry.go, «los que ya no existen se olvidan solos»), así que
			// con una ruta ficticia el Load de en medio borraba la entrada y el
			// bool salía false sin que nada estuviera roto. Registrar el
			// directorio de trabajo es además lo que pasa de verdad: durante un
			// hook, el repo que se enrola ES el CWD.
			Add(trabajo, "proyecto", "go")
			Load()
			if !Remove(trabajo) {
				t.Fatal("Add no dejó rastro del proyecto: el árbol de trabajo está " +
					"limpio porque no se escribió nada, no porque se escribiera en su sitio")
			}

			entradas, err := os.ReadDir(trabajo)
			if err != nil {
				t.Fatal(err)
			}
			if len(entradas) > 0 {
				var nombres []string
				for _, e := range entradas {
					nombres = append(nombres, e.Name())
				}
				t.Errorf("el registro se escribió dentro del árbol de trabajo: %v.\n"+
					"Durante un commit eso es el repo del usuario: aparecen archivos que "+
					"él no creó y que git le ofrece añadir al siguiente commit.", nombres)
			}
		})
	}
}

// La otra mitad, sin la cual el arreglo se "conseguiría" no escribiendo nunca:
// con un LOCALAPPDATA legítimo el registro tiene que ir ahí y funcionar.
func TestConLocalappdataValidoElRegistroSigueFuncionando(t *testing.T) {
	trabajo := t.TempDir()
	datos := t.TempDir() // absoluto, como el LOCALAPPDATA de verdad
	t.Chdir(trabajo)
	t.Setenv("LOCALAPPDATA", datos)

	proyecto := filepath.Join(trabajo, "proyecto")
	if err := os.MkdirAll(proyecto, 0o755); err != nil {
		t.Fatal(err)
	}
	Add(proyecto, "proyecto", "go")

	if _, err := os.Stat(filepath.Join(datos, "codeguard", "repos.json")); err != nil {
		t.Fatalf("el registro no está en %s: %v", filepath.Join(datos, "codeguard"), err)
	}
	if repos := Load(); len(repos) != 1 {
		t.Errorf("se registró 1 proyecto y Load devolvió %d", len(repos))
	}
}
