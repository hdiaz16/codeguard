package main

import (
	"slices"
	"testing"
)

// El caso que lo destapó, usando el producto: inventario-cliente, un repo real con
// API en Go, worker en Python, cliente en TypeScript y esquema en PostgreSQL.
// `init` escribía `languages: [go]` y el panel lo enseñaba tal cual — o sea,
// afirmaba en pantalla que el 75% del stack no existía.
func TestElStackDeUnRepoRealSaleCompleto(t *testing.T) {
	quiero := []string{"go", "python", "sql", "typescript"}
	got := DetectarLenguajes([]string{
		"cmd/api/main.go",
		"internal/almacen/almacen.go",
		"internal/almacen/almacen_test.go",
		"go.mod",
		"worker/sincronizar.py", // UN archivo…
		"mypy.ini",              // …pero declarado
		"pyproject.toml",
		"web/src/api.ts", // UN archivo…
		"tsconfig.json",  // …pero declarado
		"package.json",
		"migrations/001_init.sql",
		"README.md",
	})
	if !slices.Equal(got, quiero) {
		t.Errorf("stack detectado %v, esperaba %v", got, quiero)
	}
	// package.json NO puede añadir javascript a un proyecto TypeScript: sería
	// describir mal el stack y encender motores que no tocan.
	if slices.Contains(got, "javascript") {
		t.Errorf("un proyecto TypeScript no es también JavaScript por tener package.json: %v", got)
	}
}

// El umbral de dos archivos existe por algo y no se puede tirar: un script
// suelto no convierte el repo en un proyecto de ese lenguaje. Es el control
// que impide el arreglo perezoso de "cuenta todo lo que veas".
func TestUnArchivoSueltoSinManifiestoNoDefineElStack(t *testing.T) {
	got := DetectarLenguajes([]string{
		"cmd/api/main.go",
		"internal/x/x.go",
		"go.mod",
		"scripts/limpiar.py", // uno solo y sin mypy.ini/pyproject: no es el stack
	})
	if slices.Contains(got, "python") {
		t.Errorf("un script suelto no hace del repo un proyecto de Python: %v", got)
	}
	if !slices.Contains(got, "go") {
		t.Errorf("Go sí está: %v", got)
	}
}

// Y el simétrico: dos archivos bastan aunque no haya manifiesto. Si el
// manifiesto fuera obligatorio, esto habría cambiado la regla en vez de
// ampliarla, y repos que hoy se detectan bien dejarían de detectarse.
func TestDosArchivosSiguenBastandoSinManifiesto(t *testing.T) {
	got := DetectarLenguajes([]string{"a/uno.py", "b/dos.py"})
	if !slices.Contains(got, "python") {
		t.Errorf("dos archivos siempre han bastado y tienen que seguir bastando: %v", got)
	}
}

func TestUnProyectoReciénEmpezadoNoSeQuedaSinStack(t *testing.T) {
	// go.mod sin un solo .go todavía: negar el stack sería contradecir lo que
	// el propio repo declara por escrito.
	if got := DetectarLenguajes([]string{"go.mod", "README.md"}); !slices.Contains(got, "go") {
		t.Errorf("un go.mod declara Go aunque no haya código aún: %v", got)
	}
	// Y sin nada reconocible, no se inventa nada.
	if got := DetectarLenguajes([]string{"README.md", "LICENSE"}); len(got) != 0 {
		t.Errorf("sin nada que reconocer no se inventa un stack: %v", got)
	}
}

// Windows entrega rutas con barra invertida por varios caminos del producto.
//
// El manifiesto va en un SUBDIRECTORIO a propósito: en la raíz, path.Base y
// path.Ext ya funcionan con barra invertida y la prueba pasaba con y sin la
// normalización — o sea, no probaba nada. Lo cazó una prueba de mutación del
// validador. Con `web\tsconfig.json` sí se ve: sin normalizar sale `[go]`.
func TestLasRutasDeWindowsNoCambianElStack(t *testing.T) {
	got := DetectarLenguajes([]string{
		`web\src\api.ts`, `web\tsconfig.json`,
		`cmd\api\main.go`, `cmd\api\otro.go`,
	})
	for _, quiero := range []string{"go", "typescript"} {
		if !slices.Contains(got, quiero) {
			t.Errorf("falta %s con rutas de Windows: %v", quiero, got)
		}
	}
}

// La regresión que encontró el validador, y que era PEOR que el fallo original:
// un manifiesto sin un solo archivo de su lenguaje no ampliaba el stack, lo
// SUSTITUÍA. Enseñar un stack falso es peor que enseñarlo incompleto, porque
// lo incompleto se nota y lo falso no.
func TestUnManifiestoSinArchivosNoBorraElStackReal(t *testing.T) {
	for _, c := range []struct {
		nombre    string
		archivos  []string
		quiero    string
		prohibido string
	}{
		{
			"requirements.txt de pre-commit en un repo de Go",
			[]string{"cmd/api/main.go", "requirements.txt"},
			"go", "python",
		},
		{
			"package.json de scripts en un repo de Go",
			[]string{"cmd/api/main.go", "package.json"},
			"go", "javascript",
		},
		{
			"package.json en un repo TypeScript sin tsconfig",
			[]string{"web/app.ts", "package.json"},
			"typescript", "javascript",
		},
		{
			"go.mod de un cliente de ejemplo en un repo TypeScript",
			[]string{"web/a.ts", "web/b.ts", "tsconfig.json", "examples/go-client/go.mod"},
			"typescript", "go",
		},
	} {
		t.Run(c.nombre, func(t *testing.T) {
			got := DetectarLenguajes(c.archivos)
			if !slices.Contains(got, c.quiero) {
				t.Errorf("el stack REAL (%s) desapareció: %v", c.quiero, got)
			}
			if slices.Contains(got, c.prohibido) {
				t.Errorf("se inventó %q, que no tiene ni un archivo en el repo: %v", c.prohibido, got)
			}
		})
	}
}

// La guarda que impide anunciar JavaScript en un proyecto TypeScript necesita
// un repo con UN .js de verdad.
//
// Lo cazó una prueba de mutación del validador: quitar `&& !declarados
// ["typescript"]` dejaba TODA la suite en verde. El caso lo cubría antes
// TestElStackDeUnRepoRealSaleCompleto, pero al arreglar la regresión del
// manifiesto un javascript con cero archivos dejó de entrar por ningún camino,
// así que aquel test siguió pasando y dejó de proteger lo que protegía. Un
// `jest.config.js` o un `.eslintrc.js` en un repo TypeScript es lo normal.
func TestUnJestConfigNoConvierteUnRepoTypeScriptEnJavaScript(t *testing.T) {
	got := DetectarLenguajes([]string{
		"src/a.ts", "src/b.ts", "tsconfig.json", "package.json",
		"jest.config.js", // el único .js del repo, y es herramienta
	})
	if !slices.Contains(got, "typescript") {
		t.Errorf("el stack real es TypeScript: %v", got)
	}
	if slices.Contains(got, "javascript") {
		t.Errorf("un jest.config.js no hace del repo un proyecto JavaScript: %v.\n"+
			"El panel anunciaría dos lenguajes donde hay uno.", got)
	}
}

// Y sólo se declaran lenguajes que el producto sabe analizar. Un rótulo sin
// una capa detrás promete una cobertura que no existe.
func TestNoSeDeclaranLenguajesSinMotor(t *testing.T) {
	got := DetectarLenguajes([]string{"Cargo.toml", "Gemfile", "composer.json", "README.md"})
	for _, prohibido := range []string{"rust", "ruby", "php"} {
		if slices.Contains(got, prohibido) {
			t.Errorf("%s no tiene ningún motor: pintarlo promete cobertura inexistente: %v", prohibido, got)
		}
	}
}

// El stack se ordena: es lo que se escribe en el config y lo que pinta el
// panel, y una lista que baila entre corridas ensucia el diff del config y
// hace parecer que algo cambió cuando no cambió nada.
func TestElStackSaleOrdenado(t *testing.T) {
	got := DetectarLenguajes([]string{"z.ts", "z2.ts", "a.go", "a2.go", "m.py", "m2.py"})
	if !slices.IsSorted(got) {
		t.Errorf("el stack tiene que salir ordenado: %v", got)
	}
}
