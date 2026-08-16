package linters

import (
	"strings"
	"testing"
)

// `go vet -json` ESCRIBE UN FLUJO, NO UN OBJETO — y el motor lo leía como un
// objeto.
//
// Un módulo con tests produce dos variantes de paquete y por tanto dos objetos
// pegados. json.Unmarshal sobre eso muere con "invalid character '{' after
// top-level value", el motor lo tomaba por «no entiendo su informe» y govet
// quedaba DEGRADADO: no analizaba nada, en cualquier repo con tests, o sea en
// todos. Se veía como una línea "capas no revisadas: govet:error" fácil de leer
// como un tropiezo pasajero.
//
// La medición que fijó el contrato de govet se hizo sobre UN paquete, donde un
// flujo de un elemento y un objeto son indistinguibles. Ésa es la lección: la
// forma de la salida hay que medirla en el caso REAL —un módulo entero—, no en
// el más pequeño que compile.
func TestVetJSONEsUnFlujoDeObjetosYNoUnoSolo(t *testing.T) {
	casos := []struct {
		nombre   string
		informe  string
		hallazgo int
	}{
		{"un solo paquete limpio (el caso que se midió al principio)", "{}", 0},
		{"módulo con tests: DOS objetos pegados, los dos limpios", "{}\n{}", 0},
		{"tres variantes de paquete", "{}\n{}\n{}", 0},
		{"un objeto limpio y otro con un diagnóstico", `{}
{"codeguard/x":{"printf":[{"posn":"C:/x/a.go:12:3","message":"algo"}]}}`, 1},
		{"dos objetos, cada uno con lo suyo: se FUNDEN, no se pisan",
			`{"codeguard/x":{"printf":[{"posn":"C:/x/a.go:12:3","message":"uno"}]}}
{"codeguard/x_test":{"printf":[{"posn":"C:/x/b.go:4:1","message":"dos"}]}}`, 2},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			fs, err := hallazgosDelJSONDeVet("C:/x", c.informe)
			if err != nil {
				t.Fatalf("no pudo leer el informe, así que govet se declara averiado "+
					"y esa capa deja de mirar: %v", err)
			}
			if len(fs) != c.hallazgo {
				t.Fatalf("hallazgos = %d, se esperaban %d", len(fs), c.hallazgo)
			}
		})
	}
}

// LA CONTRAPARTE: un flujo CORTADO a medias sigue siendo avería. Media
// respuesta se cachearía bajo la clave del contenido y se serviría después como
// si estuviera entera — que es el invariante que el contrato de los motores
// existe para sostener.
func TestUnFlujoCortadoADemiasSigueSiendoAveria(t *testing.T) {
	cortados := []string{
		`{"codeguard/x":{"printf":[{"posn":"C:/x/a.go:12:3","message":"uno"}]`,
		"{}\n{\"codeguard/x\":{\"printf\":[{",
		"no es json",
	}
	for _, informe := range cortados {
		if _, err := hallazgosDelJSONDeVet("C:/x", informe); err == nil {
			t.Errorf("un informe cortado (%q) pasó por bueno: un análisis a medias "+
				"se guarda en el caché y se sirve luego como completo",
				strings.TrimSpace(informe))
		}
	}
}
