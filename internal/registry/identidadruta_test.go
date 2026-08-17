package registry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// formaAlternativa devuelve OTRA escritura del mismo directorio físico.
//
// La que de verdad pasa en esta máquina es la forma corta 8.3: %TEMP% viene
// como C:\Users\HECTOR~1\..., así que cualquier repo bajo el temporal ya está
// escrito de dos maneras. Si el volumen no diera nombres cortos, se cae a las
// otras dos formas reales —mayúsculas y barra final— que reproducen lo mismo.
func formaAlternativa(t *testing.T, dir string) string {
	t.Helper()
	if largo, err := filepath.EvalSymlinks(dir); err == nil && largo != dir {
		return largo
	}
	return strings.ToUpper(dir) + string(filepath.Separator)
}

func rutas(repos []Repo) []string {
	out := make([]string, len(repos))
	for i, r := range repos {
		out[i] = r.Root
	}
	return out
}

// H028: Add decía ser idempotente pero comparaba la cadena CRUDA, mientras
// Remove comparaba la ruta normalizada. Dos definiciones distintas de "es el
// mismo proyecto" en el mismo archivo: la misma carpeta escrita de dos formas
// —la corta de %TEMP% y la larga— entraba dos veces, y el panel mostraba el
// proyecto duplicado.
func TestAddNoDuplicaElMismoDirectorio(t *testing.T) {
	base := enTemporal(t)
	repo := filepath.Join(base, "Proyecto Con Espacios")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	otra := formaAlternativa(t, repo)
	if otra == repo {
		t.Fatal("no se pudo construir una segunda escritura del mismo directorio")
	}

	Add(repo, "proyecto", "go")
	Add(otra, "proyecto", "go")

	repos := Load()
	if len(repos) != 1 {
		t.Fatalf("el mismo directorio escrito de dos formas es UN proyecto; quedaron %d: %q", len(repos), rutas(repos))
	}
}

// La entrada se persiste en forma canónica de disco: es lo que hace que las
// dos escrituras colapsen. Y con la capitalización REAL, no en minúsculas,
// porque este campo se le enseña al usuario en el panel.
func TestAddGuardaLaRutaCanonica(t *testing.T) {
	base := enTemporal(t)
	repo := filepath.Join(base, "Proyecto Con Espacios")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}

	// Se registra por la forma NO canónica —la corta, que es la que entrega
	// %TEMP%— y aun así debe persistirse la de disco.
	Add(repo, "proyecto", "go")

	repos := Load()
	if len(repos) != 1 {
		t.Fatalf("esperaba 1 entrada, hay %d", len(repos))
	}
	esperado, err := filepath.EvalSymlinks(repo)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := repos[0].Root, filepath.ToSlash(esperado); got != want {
		t.Errorf("Root = %q, se esperaba la forma canónica %q", got, want)
	}
	if !strings.Contains(repos[0].Root, "Proyecto Con Espacios") {
		t.Errorf("Root debe conservar la capitalización real para el panel: %q", repos[0].Root)
	}
}

// Un repos.json que YA tiene duplicados —el de esta máquina, escrito por las
// versiones anteriores— tiene que arreglarse solo al leerlo. Sin esto el
// arreglo sólo evita duplicados nuevos y deja el archivo roto para siempre.
func TestLoadColapsaDuplicadosPreexistentes(t *testing.T) {
	base := enTemporal(t)
	repo := filepath.Join(base, "Proyecto")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	canonico, err := filepath.EvalSymlinks(repo)
	if err != nil {
		t.Fatal(err)
	}

	sembrar(t, []Repo{
		// La vieja: se enroló primero y su análisis es más antiguo.
		{Root: filepath.ToSlash(repo), Nombre: "proyecto", Alta: "2026-01-05T09:00:00Z",
			UltVez: "2026-01-05T09:00:00Z", Lenguaje: "go"},
		// La nueva: mismo directorio, otra escritura, análisis reciente.
		{Root: strings.ToUpper(filepath.ToSlash(canonico)) + "/", Nombre: "proyecto", Alta: "2026-08-01T10:00:00Z",
			UltVez: "2026-08-10T18:30:00Z", Lenguaje: "go,ts"},
	})

	repos := Load()
	if len(repos) != 1 {
		t.Fatalf("las dos entradas son el mismo proyecto; quedaron %d: %q", len(repos), rutas(repos))
	}
	r := repos[0]
	if r.UltVez != "2026-08-10T18:30:00Z" || r.Lenguaje != "go,ts" {
		t.Errorf("debe sobrevivir la entrada del análisis más reciente: %+v", r)
	}
	// El alta es "cuándo se enroló": de dos representaciones del mismo repo,
	// la buena es la primera, no la del duplicado que apareció después.
	if r.Alta != "2026-01-05T09:00:00Z" {
		t.Errorf("Alta = %q, se esperaba la más antigua de las dos", r.Alta)
	}
	if got, want := r.Root, filepath.ToSlash(canonico); got != want {
		t.Errorf("Root = %q, se esperaba la forma canónica %q", got, want)
	}

	// Y el arreglo tiene que quedar EN EL ARCHIVO: si sólo se filtrara al
	// leer, cualquier otro lector —el panel— seguiría viendo el duplicado.
	if enDisco := leer(t); len(enDisco) != 1 {
		t.Errorf("el archivo conserva %d entradas; debía quedar 1: %q", len(enDisco), rutas(enDisco))
	}

	// La migración tiene que converger: el panel llama a Load sin parar y una
	// que reescribiera en cada lectura sería un goteo de escrituras a disco.
	antes := crudo(t)
	Load()
	if despues := crudo(t); despues != antes {
		t.Errorf("una segunda lectura volvió a reescribir el archivo:\n antes:  %s\n después: %s", antes, despues)
	}
}

// Add no pasa por Load —lee el archivo por su cuenta— así que también tiene
// que colapsar lo que encuentre; si no, reescribiría el duplicado que Load
// acababa de limpiar.
func TestAddColapsaDuplicadosPreexistentes(t *testing.T) {
	base := enTemporal(t)
	repo := filepath.Join(base, "Proyecto")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	canonico, err := filepath.EvalSymlinks(repo)
	if err != nil {
		t.Fatal(err)
	}
	sembrar(t, []Repo{
		{Root: filepath.ToSlash(repo), Nombre: "proyecto", Alta: "2026-01-05T09:00:00Z", UltVez: "2026-01-05T09:00:00Z"},
		{Root: strings.ToUpper(filepath.ToSlash(canonico)), Nombre: "proyecto", Alta: "2026-08-01T10:00:00Z", UltVez: "2026-08-10T18:30:00Z"},
	})

	Add(repo, "proyecto", "go")

	if enDisco := leer(t); len(enDisco) != 1 {
		t.Fatalf("el archivo conserva %d entradas; debía quedar 1: %q", len(enDisco), rutas(enDisco))
	}
}

// Dos proyectos DISTINTOS con nombre parecido siguen siendo dos: el colapso no
// puede comerse repos por prefijo ni por nombre.
func TestProyectosDistintosNoSeColapsan(t *testing.T) {
	base := enTemporal(t)
	uno := filepath.Join(base, "proyecto")
	dos := filepath.Join(base, "proyecto-2")
	for _, d := range []string{uno, dos} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	Add(uno, "proyecto", "")
	Add(dos, "proyecto-2", "")

	if repos := Load(); len(repos) != 2 {
		t.Fatalf("son dos proyectos distintos; quedaron %d: %q", len(repos), rutas(repos))
	}
}

func sembrar(t *testing.T, repos []Repo) {
	t.Helper()
	data, err := json.MarshalIndent(repos, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path(), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func crudo(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(path())
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func leer(t *testing.T) []Repo {
	t.Helper()
	raw, err := os.ReadFile(path())
	if err != nil {
		t.Fatal(err)
	}
	var repos []Repo
	if err := json.Unmarshal(raw, &repos); err != nil {
		t.Fatal(err)
	}
	return repos
}
