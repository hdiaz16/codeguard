package daemon

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"codeguard/internal/config"
)

// arbol escribe un repo de mentira en disco y devuelve su raíz y sus rutas.
//
// Tiene que ser disco de verdad y no una lista de rutas: mypy, tsc y eslint
// deciden si aplican BUSCANDO la configuración del repo (mypy.ini, tsconfig,
// .eslintrc), así que un test que sólo pasara nombres los daría siempre por no
// aplicables y pasaría por las razones equivocadas.
func arbol(t *testing.T, archivos map[string]string) (string, []string) {
	t.Helper()
	raiz := t.TempDir()
	rastreados := make([]string, 0, len(archivos))
	for rel, contenido := range archivos {
		abs := filepath.Join(raiz, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte(contenido), 0o644); err != nil {
			t.Fatal(err)
		}
		rastreados = append(rastreados, rel)
	}
	slices.Sort(rastreados)
	return raiz, rastreados
}

func conLanguages(langs ...string) *config.Config {
	return &config.Config{Languages: langs}
}

// EL CASO QUE LO DESTAPÓ. Héctor preguntó dos veces mirando el panel: "sólo 1
// motor se activó, ¿es correcto?". Lo era para ESE commit, pero él preguntaba
// por su REPO, y esa pregunta no existía como dato en ningún sitio.
//
// El config de demo-tienda declara [go, python, sql, typescript]. Si las capas
// del repo salieran de `languages` —que es lo que parece razonable y es lo que
// haría cualquiera— el panel prometería mypy, tsc y squawk sobre un repo que no
// tiene ni mypy.ini, ni tsconfig, ni una sola migración. Prometer cobertura que
// no existe es peor que quedarse corto: lo corto se nota, lo falso no.
func TestLasCapasDelRepoSalenDelArbolYNoDeLanguages(t *testing.T) {
	raiz, rastreados := arbol(t, map[string]string{
		"go.mod":          "module tienda\n\ngo 1.26\n",
		"cmd/api/main.go": "package main\n\nfunc main() {}\n",
		"README.md":       "# tienda\n",
	})

	got := CapasDelRepo(conLanguages("go", "python", "sql", "typescript"), raiz, rastreados)

	for _, quiero := range []string{"semgrep", "gofmt", "govet", "staticcheck", "govulncheck"} {
		if !slices.Contains(got, quiero) {
			t.Errorf("falta %q: el repo es Go y tiene go.mod, esa capa sí lo vigila. Capas: %v", quiero, got)
		}
	}
	for _, sobra := range []string{"mypy", "tsc", "squawk", "ruff", "eslint"} {
		if slices.Contains(got, sobra) {
			t.Errorf("%q no puede correr JAMÁS en este repo y el panel lo anunciaría como cobertura: %v",
				sobra, got)
		}
	}
}

// La asimetría, aislada: `languages` sobre-declara SIEMPRE y nunca se queda
// corto, así que usarlo como fuente sólo puede producir mentiras hacia el lado
// caro. Este test es el que se pone rojo si alguien "simplifica" la función
// leyendo el config en vez de preguntarle al árbol.
func TestUnLenguajeDeclaradoSinUnSoloArchivoNoEnciendeSuCapa(t *testing.T) {
	raiz, rastreados := arbol(t, map[string]string{
		"cmd/api/main.go": "package main\n",
		"go.mod":          "module x\n",
	})
	got := CapasDelRepo(conLanguages("typescript", "python", "java", "csharp"), raiz, rastreados)
	for _, sobra := range []string{"tsc", "eslint", "mypy", "ruff", "google-java-format", "pmd",
		"dotnet-format", "dotnet-build", "dotnet-vuln"} {
		if slices.Contains(got, sobra) {
			t.Errorf("el config declara lenguajes que no existen en el árbol y se coló %q: %v", sobra, got)
		}
	}
}

// Y el simétrico, que es el control: si el repo TIENE el material, la capa
// tiene que salir. Sin esto, "no declares nada" pasaría todos los tests de
// arriba y sería un producto inútil.
func TestUnRepoConMaterialDeVerdadEnciendeSusCapas(t *testing.T) {
	raiz, rastreados := arbol(t, map[string]string{
		"tsconfig.json":      `{"compilerOptions":{"strict":true}}`,
		"package.json":       `{"name":"web","devDependencies":{"eslint":"^9"}}`,
		"eslint.config.js":   "export default [];\n",
		"src/api.ts":         "export const x = 1;\n",
		"mypy.ini":           "[mypy]\nstrict = True\n",
		"worker/sincro.py":   "def f():\n    return 1\n",
		"migrations/001.sql": "ALTER TABLE t ADD COLUMN c int;\n",
	})
	cfg := conLanguages("typescript", "python", "sql")
	cfg.Paths.Migrations = []string{"migrations/*.sql", "migrations/**/*.sql"}
	cfg.Paths.MigrationsDialect = "postgres"

	got := CapasDelRepo(cfg, raiz, rastreados)
	for _, quiero := range []string{"tsc", "eslint", "mypy", "ruff", "squawk", "semgrep"} {
		if !slices.Contains(got, quiero) {
			t.Errorf("falta %q, y el repo tiene justo lo que esa capa mira: %v", quiero, got)
		}
	}
	if slices.Contains(got, "gofmt") {
		t.Errorf("no hay un solo .go y salió gofmt: %v", got)
	}
}

// Las dos preguntas son distintas, y esta es la que faltaba. Las capas del REPO
// no pueden moverse porque el commit de hoy toque sólo el README: si se
// movieran, seguiríamos respondiendo la pregunta del commit con otro nombre.
func TestLasCapasDelRepoNoDependenDeQueCambioHoy(t *testing.T) {
	raiz, rastreados := arbol(t, map[string]string{
		"go.mod":          "module x\n",
		"cmd/api/main.go": "package main\n",
		"README.md":       "# x\n",
	})
	completo := CapasDelRepo(conLanguages("go"), raiz, rastreados)

	// El mismo repo, preguntado otra vez: el árbol no ha cambiado, la respuesta
	// tampoco puede cambiar.
	otraVez := CapasDelRepo(conLanguages("go"), raiz, rastreados)
	if !slices.Equal(completo, otraVez) {
		t.Errorf("la misma pregunta dio dos respuestas: %v vs %v", completo, otraVez)
	}
	if !slices.Contains(completo, "gofmt") {
		t.Fatalf("el repo es Go: %v", completo)
	}
}

// Un repo de sólo documentación no está "vigilado por 5 capas": está vigilado
// por UNA, semgrep, y eso es cierto.
//
// Escribí este test esperando cero y falló enseñándome el producto: semgrep
// aplica a cualquier archivo que no sea un borrado, así que también mira un
// README —nuestras reglas incluyen secretos en documentación y ejemplos—. Decir
// cero sería la mentira aquí, y hacia el lado contrario al habitual: prometer
// menos de lo que se hace.
//
// Y es EXACTAMENTE la queja de Héctor vista desde el otro lado ("sólo semgrep
// se activó en todos los repos"): semgrep era el único que salía porque es el
// único que aplica siempre. No estaba roto el reparto de motores; estaba mal la
// pregunta que contestaba el panel.
func TestUnRepoDeSoloDocumentacionTieneUnaCapaYSoloUna(t *testing.T) {
	raiz, rastreados := arbol(t, map[string]string{"README.md": "# nuevo\n", "LICENSE": "MIT\n"})

	got := CapasDelRepo(conLanguages(), raiz, rastreados)
	if !slices.Equal(got, []string{"semgrep"}) {
		t.Errorf("un repo de sólo documentación lo vigila semgrep y nadie más, y salió %v", got)
	}
	if got := CapasDelRepo(nil, raiz, nil); len(got) != 0 {
		t.Errorf("sin archivos rastreados no hay nada que responder, y salieron %v", got)
	}
}

// Lo que el repo EXCLUYE no puede encender una capa.
//
// Lo destapé midiendo el propio codeguard: salían google-java-format, pmd y
// dotnet-format porque el repo tiene fixtures .java y .cs bajo testdata. El
// pipeline los descarta con paths.exclude ANTES de que ningún motor los vea
// (pipeline.go, filterExcluded), así que esas tres capas no correrían jamás y
// el panel las habría anunciado igual.
//
// Es la misma clase de fallo que este trabajo venía a arreglar, cometida por mí
// un nivel más abajo: dos criterios distintos para la misma pregunta. Por eso
// aquí se llama al MISMO filtro del pipeline y no a una copia.
func TestLoQueElRepoExcluyeNoEnciendeUnaCapa(t *testing.T) {
	archivos := map[string]string{
		"go.mod":                     "module x\n",
		"cmd/api/main.go":            "package main\n",
		"testdata/fixtures/App.java": "class App {}\n",
		"vendor/ajeno/Otro.java":     "class Otro {}\n",
		"internal/gen/api.pb.go":     "package gen\n",
	}
	raiz, rastreados := arbol(t, archivos)

	sinExcluir := CapasDelRepo(conLanguages("go"), raiz, rastreados)
	if !slices.Contains(sinExcluir, "google-java-format") {
		t.Fatalf("control: sin exclusiones los .java sí encienden la capa de Java, y salió %v", sinExcluir)
	}

	cfg := conLanguages("go")
	cfg.Paths.Exclude = []string{"testdata/**", "vendor/**"}
	cfg.Paths.Generated = []string{"**/*.pb.go"}

	got := CapasDelRepo(cfg, raiz, rastreados)
	for _, sobra := range []string{"google-java-format", "pmd"} {
		if slices.Contains(got, sobra) {
			t.Errorf("%q sólo tenía material en rutas excluidas: el análisis nunca lo correría "+
				"y el panel lo anunciaría como cobertura: %v", sobra, got)
		}
	}
	if !slices.Contains(got, "gofmt") {
		t.Errorf("el Go de verdad no está excluido y tiene que seguir ahí: %v", got)
	}
}

// gitleaks NO entra, y es deliberado: no está en Engines() porque corre en la
// etapa 1, en el proceso del hook, y por eso tampoco aparece nunca en
// Result.Capas (pipeline.go sólo llena Capas dentro del bucle de la etapa 2).
//
// Si lo contáramos aquí, el panel diría "11 capas" y el análisis reportaría 10
// para siempre, y ese descuadre se lee como una avería. La compuerta de
// secretos se nombra aparte en el texto, que además es más honesto: corre
// SIEMPRE, en todos los repos, y es la única que es fail-closed.
func TestLaCompuertaDeSecretosNoSeCuentaComoUnaCapaDelRepo(t *testing.T) {
	raiz, rastreados := arbol(t, map[string]string{"go.mod": "module x\n", "a.go": "package a\n"})
	got := CapasDelRepo(conLanguages("go"), raiz, rastreados)
	if slices.Contains(got, "gitleaks") {
		t.Errorf("gitleaks no viaja en Result.Capas: contarlo aquí descuadra el panel contra el análisis: %v", got)
	}
	if len(got) == 0 {
		t.Fatal("control: este repo sí tiene capas")
	}
}

// El orden es estable porque esto se escribe en el panel y se compara con lo
// que se guardó: una lista que baila hace parecer que cambió algo cuando no
// cambió nada. Sale en el orden de Engines(), que es el orden en que corren.
func TestLasCapasSalenEnElOrdenEnQueCorren(t *testing.T) {
	raiz, rastreados := arbol(t, map[string]string{
		"go.mod": "module x\n", "a.go": "package a\n",
	})
	got := CapasDelRepo(conLanguages("go"), raiz, rastreados)

	orden := map[string]int{}
	for i, e := range Engines(nil, false, nil) {
		orden[e.Name()] = i
	}
	for i := 1; i < len(got); i++ {
		if orden[got[i-1]] >= orden[got[i]] {
			t.Fatalf("las capas no salen en el orden de Engines(): %v", got)
		}
	}
}
