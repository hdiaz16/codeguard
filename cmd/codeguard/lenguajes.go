package main

import (
	"path"
	"sort"
	"strings"

	"codeguard/internal/migraciones"
)

// manifiestosPorLenguaje: archivos cuya sola presencia DECLARA un lenguaje.
//
// Un manifiesto no es un archivo más del montón: es el equipo diciendo por
// escrito en qué está hecho su proyecto. Quien tiene `tsconfig.json` hace
// TypeScript aunque su cliente quepa en un archivo, y quien tiene `mypy.ini`
// hace Python aunque el worker sea uno solo.
var manifiestosPorLenguaje = map[string]string{
	"tsconfig.json":    "typescript",
	"mypy.ini":         "python",
	"pyproject.toml":   "python",
	"requirements.txt": "python",
	"setup.py":         "python",
	"pipfile":          "python",
	"go.mod":           "go",
	"pom.xml":          "java",
	"build.gradle":     "java",
	// Sólo lenguajes que este producto sabe analizar. Estuvieron aquí rust,
	// ruby y php: ni los mapea extToLang ni tienen motor, así que lo único que
	// hacían era PINTARSE en `status` y en el panel — un rótulo sin una sola
	// capa detrás, que es prometer cobertura que no existe.
}

// DetectarLenguajes decide qué stack declara el config del repo.
//
// La regla es "dos archivos, o uno con manifiesto que lo declare", y la segunda
// mitad salió de un fallo medido: un repo real con API en Go, worker en Python,
// cliente en TypeScript y esquema en PostgreSQL acababa con `languages: [go]`,
// porque sólo Go llegaba a dos archivos. Mientras `languages` era un dato
// interno eso pasaba desapercibido; desde que el panel ENSEÑA el stack, es una
// afirmación falsa en la pantalla del desarrollador — la misma clase de mentira
// por omisión que este producto existe para no cometer.
//
// El umbral de dos se conserva para lo que fue pensado: que un `.py` suelto de
// un script de utilidad no convierta el repo en un proyecto de Python. La
// diferencia entre ese caso y el otro es exactamente si alguien lo declaró.
//
// Devuelve la lista ordenada; vacía si no reconoce nada.
func DetectarLenguajes(rutas []string) []string {
	porLenguaje := map[string]int{}
	declarados := map[string]bool{}
	tieneNode := false

	for _, p := range rutas {
		low := strings.ToLower(path.Clean(strings.ReplaceAll(p, "\\", "/")))
		if lang, ok := extToLang[path.Ext(low)]; ok {
			porLenguaje[lang]++
		}
		base := path.Base(low)
		if lang, ok := manifiestosPorLenguaje[base]; ok {
			declarados[lang] = true
		}
		if base == "package.json" {
			tieneNode = true
		}
		if strings.HasSuffix(low, ".csproj") || strings.HasSuffix(low, ".sln") {
			declarados["csharp"] = true
		}
		// Una MIGRACIÓN declara SQL aunque sea la única. No es una excepción
		// suelta: es el mismo criterio con el que `paths.migrations` decide qué
		// vigila la compuerta de datos, así que un repo cuyo esquema SÍ se está
		// analizando no puede salir en el panel diciendo que no hace SQL.
		if migraciones.Parece(p) {
			declarados["sql"] = true
		}
	}
	// package.json declara JavaScript sólo si nadie declaró TypeScript: en un
	// proyecto TS el package.json es del mismo proyecto, y anunciar los dos
	// lenguajes describe mal el stack y enciende motores que no tocan.
	if tieneNode && !declarados["typescript"] {
		declarados["javascript"] = true
	}

	// Un manifiesto AMPLÍA lo que hay; nunca lo sustituye.
	//
	// La primera versión de esto dejaba que un manifiesto sin un solo archivo
	// de su lenguaje entrara en la lista, y eso desactivaba el rescate de
	// abajo. El efecto medido no era un stack corto sino uno BORRADO: un
	// `requirements.txt` de pre-commit junto a un único `main.go` producía
	// `[python]` en un repo de Go, y un `package.json` de scripts convertía un
	// proyecto TypeScript en `[javascript]`. Enseñar un stack falso es peor que
	// enseñarlo incompleto, porque lo incompleto se nota y lo falso no.
	var out []string
	hayArchivos := false
	for lang, n := range porLenguaje {
		if n > 0 {
			hayArchivos = true
		}
		// Dos archivos, o uno solo si un manifiesto declara ese lenguaje.
		if n >= 2 || (n >= 1 && declarados[lang]) {
			out = append(out, lang)
		}
	}

	switch {
	case len(out) > 0:
		// Ya hay stack: los manifiestos sin archivos no añaden nada. Un
		// `go.mod` de un cliente de ejemplo no hace que el repo sea de Go.
	case hayArchivos:
		// Nada llegó al umbral, pero SÍ hay código: el repo es pequeño o
		// nuevo, no ambiguo. Se enrola con lo que haya, que es lo que hacía
		// antes y hay que conservar.
		for lang, n := range porLenguaje {
			if n > 0 {
				out = append(out, lang)
			}
		}
	default:
		// Ni archivos reconocibles ni nada: aquí sí manda el manifiesto. Un
		// `go.mod` sin un solo .go todavía es un proyecto de Go recién
		// empezado, y negarlo contradice lo que el repo declara por escrito.
		for lang := range declarados {
			out = append(out, lang)
		}
	}
	sort.Strings(out)
	return out
}
