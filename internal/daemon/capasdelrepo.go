package daemon

import (
	"codeguard/internal/config"
	"codeguard/internal/engines"
	"codeguard/internal/gitdiff"
	"codeguard/internal/pipeline"
)

// CapasDelRepo responde "¿qué capas vigilan MI repo?", que es una pregunta
// DISTINTA de "¿qué capas miraron este commit?" y hasta ahora no existía.
//
// El panel sólo sabía responder la segunda: enseñaba las capas del último
// análisis, así que un commit que tocaba un README se leía como "1 capa revisó
// tu repo" y parecía que el producto estaba apagado. La pregunta que hace el
// desarrollador cuando mira el panel es la primera, y contestarle con la
// segunda es contestarle otra cosa.
//
// EL CRITERIO ES EL ÁRBOL, NO `languages`. Es tentador leer el config —está
// ahí, es una línea— y está mal en la dirección cara: `languages` sobre-declara
// siempre y no se queda corto nunca. Medido en demo-tienda: el config dice
// [go, python, sql, typescript] y mypy, tsc y squawk no correrían jamás porque
// el repo no tiene mypy.ini, ni tsconfig, ni una migración que case. Anunciar
// esas tres capas sería prometer una cobertura inexistente, y una promesa falsa
// de cobertura no se nota nunca —a diferencia de una lista corta, que se nota
// enseguida—. Por eso se le pregunta a cada motor por el árbol entero con su
// propio Applies(), que es exactamente el mismo juez que decide en el commit:
// dos jueces distintos acabarían discrepando y el descuadre lo pagaría el
// panel.
//
// Los archivos se presentan como modificados ("M") a propósito. Es la respuesta
// a "si HOY tocaras todo el repo, ¿quién miraría?", que es justo lo que
// significa "las capas de mi repo".
//
// Lo que de verdad hay que evitar es "D": semgrep, dotnet-vuln y dotnet-format
// descartan los borrados, y con "D" la lista sale VACÍA en cualquier repo. "A"
// da hoy el mismo resultado que "M" —medido por el validador, ningún Applies
// distingue añadido de modificado—, así que la elección entre esas dos es de
// sentido, no de comportamiento: un archivo que ya está en el repo está
// modificado, no recién añadido.
//
// gitleaks no sale: no está en Engines() porque corre en la etapa 1, dentro del
// proceso del hook, y por eso tampoco viaja nunca en Result.Capas. Contarlo
// aquí dejaría al panel diciendo un número y al análisis reportando otro, para
// siempre. La compuerta de secretos se nombra aparte, que además es lo cierto:
// corre en todos los repos, siempre, y es la única fail-closed.
//
// Devuelve los nombres en el orden de Engines(), que es el orden en que corren.
func CapasDelRepo(cfg *config.Config, repoRoot string, rastreados []string) []string {
	// Atajo, no invariante: sin archivos todos los Applies darían false y la
	// respuesta sería nil igual. Se queda porque ahorra 16 recorridos de disco
	// en un repo vacío, no porque nada dependa de él.
	if len(rastreados) == 0 {
		return nil
	}
	arbol := make([]gitdiff.ChangedFile, 0, len(rastreados))
	for _, ruta := range rastreados {
		arbol = append(arbol, gitdiff.ChangedFile{Path: ruta, Status: "M"})
	}
	// El MISMO recorte que aplica la etapa 2 antes de repartir trabajo. Sin él
	// se anuncian capas que no correrían jamás: medido en el propio codeguard,
	// salían google-java-format, pmd y dotnet-format por unos fixtures .java y
	// .cs bajo testdata que paths.exclude descarta. Se llama al filtro del
	// pipeline y no a una copia, porque dos criterios para la misma pregunta es
	// exactamente el fallo que esta función viene a arreglar.
	if cfg != nil {
		arbol = pipeline.FiltrarExcluidos(cfg, arbol)
	}
	// No se rellena Input.MigrationsGl aunque exista el campo: NADIE lo lee en
	// todo el repo (se declara en engine.go:20 y no tiene un solo lector).
	// Squawk recibe sus globs por `Engines(cfg, …)`, en su propia estructura.
	// Ponerlo aquí no cambiaba nada y hacía creer al que lo leyera que es lo que
	// hace funcionar a squawk, que es peor que no ponerlo.
	in := engines.Input{RepoRoot: repoRoot, Files: arbol}

	// inCI=false: la pregunta es qué vigila el repo en la máquina del
	// desarrollador, que es quien mira el panel. cache=nil porque Applies no
	// consulta el caché — sólo mira rutas y busca la configuración del repo en
	// disco.
	var out []string
	for _, motor := range Engines(cfg, false, nil) {
		if motor.Applies(in) {
			out = append(out, motor.Name())
		}
	}
	return out
}

// CapasDelRepoEn es CapasDelRepo preguntándole a git por el árbol.
//
// Va por gitdiff.Rastreados —y no por un recorrido del disco— por dos razones:
// respeta .gitignore sin reimplementarlo, y es el MISMO censo de archivos que
// alimenta el análisis, así que el panel no puede prometer una capa por un
// archivo que el análisis nunca vería. Y no abre ventana de consola: gitdiff ya
// lanza git con proc.SinVentana.
//
// Un repo que no se puede enumerar devuelve nil, no un error: quien pregunta es
// la UI, y la respuesta honesta a "no lo sé" es no pintar nada, nunca un cero
// que se leería como "ninguna capa te vigila".
func CapasDelRepoEn(cfg *config.Config, repoRoot string) []string {
	rastreados, err := gitdiff.Rastreados(repoRoot)
	if err != nil {
		return nil
	}
	return CapasDelRepo(cfg, repoRoot, rastreados)
}
