package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"codeguard/internal/registry"
)

// repoConConfig es un repo enrolado de verdad: repo de git con archivos
// RASTREADOS, y su config con el stack dentro.
//
// Tiene que ser git de verdad y con `git add`: las capas del repo salen de
// preguntarle a cada motor por el árbol RASTREADO (gitdiff.Rastreados, o sea
// `git ls-files`), que es el mismo censo que alimenta el análisis. Un fixture
// de archivos sueltos daría cero capas y la prueba pasaría o fallaría por la
// razón equivocada.
//
// Y el config lleva `rulepack` porque config.Load lo EXIGE —sin él devuelve
// error y no hay stack—. Lo aprendí escribiendo este fixture sin él: la prueba
// falló acusando al código de no leer el stack cuando quien no lo escribía era
// yo.
func repoConConfig(t *testing.T, nombre, configYAML string, archivos map[string]string) registry.Repo {
	t.Helper()
	dir := filepath.Join(t.TempDir(), nombre)
	if err := os.MkdirAll(filepath.Join(dir, ".codeguard"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".codeguard", "config.yaml"), []byte(configYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	for rel, contenido := range archivos {
		abs := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte(contenido), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"init"}, {"add", "-A"}} {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	return registry.Repo{Root: filepath.ToSlash(dir), Nombre: nombre}
}

// EL FALLO QUE VIO HÉCTOR EN PANTALLA: enrolas un repo, `init` dice LISTO y
// escribe `languages: [go, sql]` en el config… y el panel enseña la ficha con
// la cabecera VACÍA. Ni stack, ni capas. Sus palabras: "no se detecta el stack
// ni los motores al hacer el init".
//
// La detección funcionaba: el dato estaba escrito en el config desde el
// segundo cero. Lo que fallaba es que la ficha placeholder que se crea al dar
// de alta un proyecto enrolado sólo llevaba nombre, ruta y "sin análisis" — los
// campos Languages y Capas del payload existían y nadie los rellenaba hasta el
// primer commit.
//
// Y eso es peor que un hueco cosmético: lo primero que hace un dev después de
// instalar es mirar el panel, y lo que veía era un producto que no sabe nada de
// su repo. La respuesta correcta —qué stack tiene y qué capas lo vigilan— no
// necesita ningún análisis: se sabe con el árbol y el config.
func TestUnRepoReciénEnroladoYaEnseñaSuStackYSusCapas(t *testing.T) {
	repo := repoConConfig(t, "demo-go-api",
		"version: 1\nrulepack: \"2026.08.2\"\nlanguages: [go, sql]\n",
		map[string]string{
			"go.mod":                  "module demo\n",
			"cmd/api/main.go":         "package main\n\nfunc main() {}\n",
			"migrations/001_init.sql": "CREATE TABLE t (id int);\n",
		})

	e, _ := escritorioDePrueba([]registry.Repo{repo})
	e.mu.Lock()
	e.altaDeProyectosEnroladosLocked()
	ficha := e.porProyecto[repo.Root]
	e.mu.Unlock()

	if ficha == nil {
		t.Fatal("el repo enrolado ni siquiera entró en el mapa de proyectos")
	}
	if !slices.Equal(ficha.Languages, []string{"go", "sql"}) {
		t.Errorf("la ficha nace sin el stack que el config YA declara: %v.\n"+
			"El dev acaba de correr init, que se lo dijo por pantalla, y el panel no lo sabe.",
			ficha.Languages)
	}
	// Las capas del REPO, que es la pregunta que hace quien mira el panel: no
	// "qué corrió en el último commit" —no ha habido ninguno— sino "qué vigila
	// mi repo".
	for _, quiero := range []string{"semgrep", "gofmt", "govet"} {
		if !slices.Contains(ficha.CapasRepo, quiero) {
			t.Errorf("falta la capa %q: el repo es Go y esa capa lo vigila. Capas: %v",
				quiero, ficha.CapasRepo)
		}
	}
	// Y no se inventan las que no: este repo no tiene una línea de Python ni de
	// TypeScript. Prometer cobertura que no existe es el fallo caro.
	for _, sobra := range []string{"mypy", "tsc", "ruff", "eslint"} {
		if slices.Contains(ficha.CapasRepo, sobra) {
			t.Errorf("se anunció %q sobre un repo que no tiene nada de eso: %v", sobra, ficha.CapasRepo)
		}
	}
}

// Un repo enrolado SIN config —o con el config a medio escribir— no puede
// tumbar el panel ni inventarse un stack. Es el caso de quien corrió `install`
// pero todavía no `init`.
func TestUnRepoSinConfigNoRompeElPanelNiSeInventaStack(t *testing.T) {
	repo := repoEnDisco(t, "recien-instalado")
	e, _ := escritorioDePrueba([]registry.Repo{repo})

	e.mu.Lock()
	e.altaDeProyectosEnroladosLocked()
	ficha := e.porProyecto[repo.Root]
	e.mu.Unlock()

	if ficha == nil {
		t.Fatal("un repo sin config sigue siendo un repo enrolado y tiene que aparecer")
	}
	if len(ficha.Languages) != 0 {
		t.Errorf("sin config no hay stack que enseñar, y se inventó %v", ficha.Languages)
	}
	if ficha.Verdict != "—" {
		t.Errorf("la ficha tiene que seguir diciendo que no hay análisis, dice %q", ficha.Verdict)
	}
}
