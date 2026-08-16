package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// El carril de proyectos NO puede exigir dos repos para aparecer.
//
// Estuvo con `p.otros_repos.length > 1`, y el efecto era que quien enrolaba SU
// PRIMER repositorio no lo veía nunca en la lista: la cabecera hablaba del
// proyecto y el carril seguía escondido, como si no estuviera enrolado. Héctor
// lo vio en pantalla dos veces con estas palabras: "el primer inicializado no
// se ve en la parte de proyectos".
//
// El umbral venía de leer el campo por su nombre —`otros_repos`, o sea "los
// OTROS"— que es la vista de quien ya tiene seis. Desde la del que instala hoy,
// un proyecto también es la lista de proyectos, y es justo el momento en que
// hace falta ver que está.
//
// LO QUE ESTA PRUEBA NO ES: no ejecuta el JS, mira el fuente. No sabría
// distinguir un umbral escrito de otra forma (`length > 0` está bien,
// `length >= 2` estaría mal y no lo caza). Su trabajo es impedir que vuelva
// ESTE renglón, que es el que ya volvió una vez.
func TestElCarrilDeProyectosNoExigeDosRepos(t *testing.T) {
	html := leerPanel(t)
	malo := regexp.MustCompile(`otros_repos\.length\s*>\s*1`)
	if loc := malo.FindStringIndex(html); loc != nil {
		t.Errorf("el carril se condiciona a `otros_repos.length > 1`: con un solo proyecto "+
			"—el caso de quien acaba de instalar— la lista queda escondida y su repo "+
			"parece no estar enrolado.\n  contexto: %s", recorte(html, loc[0]))
	}
	if !strings.Contains(html, "otros_repos.length >= 1") {
		t.Error("no encuentro la condición del carril: o cambió de forma o esta prueba " +
			"dejó de vigilar nada")
	}
}

// La pestaña Proyecto tiene que decir qué capas vigilan el repo ANTES del primer
// análisis. Antes sólo sabía enseñar `capas` —lo que hizo cada motor en el
// último commit— y sin commit no enseñaba ni un motor: "en la parte de proyecto
// no se ven los motores", dicho por Héctor mirando un repo recién enrolado.
//
// La pregunta sí se puede contestar sin analizar nada: sale del árbol y del
// config. Rendirse con un "haz un commit" era dejar sin respuesta lo que el
// producto ya sabe.
func TestLaPestañaProyectoEnseñaLasCapasAntesDelPrimerAnalisis(t *testing.T) {
	html := leerPanel(t)
	i := strings.Index(html, "function fichaHTML")
	if i < 0 {
		t.Fatal("no encuentro fichaHTML: esta prueba dejó de vigilar la pestaña Proyecto")
	}
	fin := strings.Index(html[i:], "\n  function dato(")
	if fin < 0 {
		t.Fatal("no encuentro el final de fichaHTML")
	}
	if !strings.Contains(html[i:i+fin], "capas_repo") {
		t.Error("fichaHTML no mira p.capas_repo: un repo recién enrolado abre la pestaña " +
			"Proyecto y no ve ni un motor, cuando saber cuáles lo vigilan no necesita " +
			"ningún commit")
	}
}

func leerPanel(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("frontend/index.html")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func recorte(s string, i int) string {
	desde := max(0, i-60)
	hasta := min(len(s), i+60)
	return strings.ReplaceAll(s[desde:hasta], "\n", " ")
}
