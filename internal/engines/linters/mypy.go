package linters

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"codeguard/internal/engines"
	"codeguard/internal/engines/contrato"
	"codeguard/internal/engines/proc"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
)

const maxLineaComandosPy = 8000

// Mypy cierra la última casilla que le faltaba a Python. Hasta aquí ese lado
// del producto tenía formato y lint (ruff) y dependencias (trivy), pero NADA de
// comprobación de tipos: un `resultado: str = suma(1, 2)` llegaba entero al CI
// mientras Go llevaba govet+staticcheck y TypeScript llevaba tsc.
//
// La decisión que da forma al motor es la MISMA que tomó eslint.go, y por la
// misma razón: SÓLO APLICA SI EL REPO YA CONFIGURÓ MYPY. En código sin
// anotaciones mypy no produce hallazgos, produce ruido —cada función sin
// anotar es un "Function is missing a type annotation"—, y obligar a comprobar
// tipos a un equipo que no lo eligió convierte al agente en un obstáculo. Un
// obstáculo se desinstala.
//
// Y no basta con preguntarle a mypy: se verificó que mypy corre igual de
// contento en un directorio con un pyproject.toml SIN sección [tool.mypy] y
// reporta sus errores. La compuerta tiene que ponerla el motor mirando dentro
// del archivo, o aplicaría en casi todos los repos de Python del mundo.
type Mypy struct {
	// Cache es POR PROYECTO, no por archivo. mypy no analiza archivos sueltos:
	// sigue los imports, así que los errores de a.py dependen del contenido de
	// los módulos que a.py importa. Una clave direccionada sólo por el
	// contenido del archivo —la de eslint— serviría hallazgos de ayer en
	// cuanto cambiara un módulo vecino sin tocar el archivo. Ver
	// claveProyectoMypy.
	Cache engines.Cache
}

func (Mypy) Name() string { return "mypy" }

func (e Mypy) Applies(in engines.Input) bool { return len(e.proyectos(in)) > 0 }

// configsMypyPropias son los archivos que EXISTEN sólo para configurar mypy: su
// mera presencia ya declara la intención y no hay que leerlos.
var configsMypyPropias = []string{"mypy.ini", ".mypy.ini"}

// proyectoPy es un grupo de .py tocados que comparten configuración de mypy: el
// directorio donde vive esa configuración (relativo a la raíz, "." si es la
// propia raíz) y los archivos que le tocan.
type proyectoPy struct {
	dir      string
	archivos []gitdiff.ChangedFile
}

// proyectos agrupa los .py tocados por la configuración de mypy más cercana,
// subiendo desde cada archivo. Es el mismo descubrimiento de tsc.go y
// eslint.go, y por el mismo motivo: en el monorepo corporativo típico la
// configuración vive en backend/, no en la raíz, y mirar sólo la raíz dejaría
// la compuerta enrolada sin correr JAMÁS, en silencio.
func (Mypy) proyectos(in engines.Input) []proyectoPy {
	idx := map[string]*proyectoPy{}
	for _, f := range in.Files {
		// Los .pyi disparan igual que los .py: un stub ES tipado, y la huella
		// del módulo (claveProyectoMypy) ya los cuenta, así que la clave de caché
		// reconocía el cambio mientras el disparador lo ignoraba — un commit que
		// sólo tocaba stubs se iba sin que mypy corriera.
		ext := strings.ToLower(path.Ext(f.Path))
		if f.Status == "D" || (ext != ".py" && ext != ".pyi") {
			continue
		}
		dir, ok := configMypyDe(in.RepoRoot, f.Path)
		if !ok {
			continue // el repo no configuró mypy aquí: no es asunto nuestro
		}
		p := idx[dir]
		if p == nil {
			p = &proyectoPy{dir: dir}
			idx[dir] = p
		}
		p.archivos = append(p.archivos, f)
	}
	out := make([]proyectoPy, 0, len(idx))
	for _, p := range idx {
		out = append(out, *p)
	}
	// Orden estable: el informe no debe cambiar de forma entre dos corridas
	// idénticas sólo por el recorrido de un mapa.
	sort.Slice(out, func(i, j int) bool { return out[i].dir < out[j].dir })
	return out
}

// configMypyDe sube desde el archivo hasta el primer directorio que configure
// mypy, sin salirse de la raíz ni entrar en un entorno virtual.
//
// El orden dentro de un mismo directorio es el de cercanía declarada en la
// documentación de mypy, pero da igual cuál gane: los cuatro significan lo
// mismo —"este proyecto comprueba tipos"— y el motor no lee la configuración,
// sólo la detecta. Quien la lee es mypy, al que se invoca con ese directorio
// como cwd para que la encuentre él solito.
func (e Mypy) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	var out []finding.Finding
	for _, p := range e.proyectos(in) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		fs, err := e.correrProyectoPy(ctx, in.RepoRoot, p)
		if err != nil {
			return nil, err
		}
		out = append(out, fs...)
	}
	return out, nil
}

func (e Mypy) correrProyectoPy(ctx context.Context, repoRoot string, p proyectoPy) ([]finding.Finding, error) {
	rutas := make([]string, 0, len(p.archivos))
	for _, f := range p.archivos {
		rutas = append(rutas, enProyecto(p.dir, f.Path))
	}
	// Ordenar antes de nada: la lista entra en la clave de caché, y dos
	// corridas con los mismos archivos en distinto orden tienen que acertar.
	sort.Strings(rutas)

	clave := ""
	if e.Cache != nil {
		if clave = claveProyectoMypy(repoRoot, p.dir, rutas); clave != "" {
			if fs, ok := e.Cache.Leer([]string{clave})[clave]; ok {
				return fs, nil
			}
		}
	}

	// Trocear parte el análisis: mypy ve menos módulos por corrida y un error
	// que cruce dos lotes puede escapársele. Es el coste asumido de no
	// desbordar la línea de comandos, el mismo que aceptó semgrep — y sólo se
	// paga en commits de cientos de archivos, que es exactamente cuando la
	// alternativa sería no analizar nada.
	var nuevos []finding.Finding
	for _, lote := range lotesDeRutas(rutas, maxLineaComandosPy) {
		fs, err := correrMypy(ctx, repoRoot, p.dir, lote)
		if err != nil {
			return nil, err
		}
		nuevos = append(nuevos, fs...)
	}
	if e.Cache != nil && clave != "" {
		e.Cache.Guardar([]engines.Cacheable{{
			Clave:    clave,
			Vigente:  engines.VigenciaDeClave(clave, func() string { return claveProyectoMypy(repoRoot, p.dir, rutas) }),
			Findings: nuevos,
		}})
	}
	return nuevos, nil
}

// claveProyectoMypy identifica una comprobación de tipos completa.
//
// Lleva tres cosas y las tres hacen falta:
//
//   - La huella del módulo: los .py/.pyi del proyecto, su configuración de mypy
//     y los manifiestos de dependencias. Los últimos no son decoración — los
//     stubs de terceros (types-requests, el py.typed de una librería) cambian
//     los resultados sin que se toque una línea del repo, y subir una versión
//     en requirements.txt es la única señal legible de ese cambio.
//   - El directorio, porque dos proyectos del mismo monorepo tienen
//     configuraciones distintas.
//   - EL CONJUNTO DE ARCHIVOS ANALIZADOS, que es lo que la distingue de
//     claveProyecto de tsc.go. tsc compila el proyecto entero y le da igual qué
//     se tocó; a mypy se le pasa una lista explícita y sólo reporta sobre ella.
//     Sin esto, un commit de un archivo sembraría el caché y el commit
//     siguiente —con dos archivos y la misma huella de módulo, porque el
//     segundo ya estaba en el árbol— acertaría y se quedaría sin analizar el
//     archivo nuevo. En silencio, que es la peor forma.
//
// Devuelve vacío —no cacheable— si el repo no se puede enumerar, que es lo que
// pasa en los tests con t.TempDir y está bien: sin caché se analiza de nuevo.
func correrMypy(ctx context.Context, repoRoot, dir string, rutas []string) ([]finding.Finding, error) {
	abs := filepath.Join(repoRoot, filepath.FromSlash(dir))

	// --no-error-summary: el "Found 4 errors in 1 file" no es JSON y ensucia la
	// salida. --show-absolute-path: mypy reporta relativo a SU cwd, y con la
	// ruta absoluta la conversión a relativa-al-repo sale bien también en
	// monorepos, sin concatenar el directorio del proyecto dos veces.
	// El "--" separa banderas de operandos: sin él, un archivo cuyo nombre
	// empiece por "-" (p. ej. "--config=x.py") se leería como bandera de
	// mypy y no como dato. argparse lo consume como fin de opciones.
	args := append([]string{"--no-error-summary", "--show-absolute-path", "--output=json", "--"}, rutas...)
	cmd := exec.CommandContext(ctx, "mypy", args...)
	// El cwd es el directorio de la configuración: mypy busca su mypy.ini /
	// setup.cfg / pyproject.toml ahí, y así aplica la del proyecto y no la de
	// la raíz del monorepo.
	cmd.Dir = abs
	// Sin esto las herramientas de Python leen y escriben en cp1252 en Windows
	// y rompen los acentos de los mensajes. Misma lección que semgrep y ruff.
	cmd.Env = proc.EntornoDePerfil(proc.PerfilPython) // UTF-8 lo impone el perfil; MYPYPATH viaja en el
	salida, runErr := proc.Correr(ctx, cmd, proc.MaxSalida)

	// Sólo stdout: los avisos de configuración de mypy ("mypy.ini: [mypy]:
	// Unrecognized option") salen por stderr y pegarlos al JSON lo volvería
	// imparseable. El stderr se guarda para poder explicar los fallos.
	out := bytes.TrimSpace(salida.Stdout)
	motivo := diagnosticoJS(salida.Stderr, salida.Stdout)

	if salida.Recortada {
		return nil, fmt.Errorf("mypy devolvió más de %d MB en %s: el JSON llega a medias y no se puede parsear", proc.MaxSalida>>20, dir)
	}
	var exitErr *exec.ExitError
	if runErr != nil && !errors.As(runErr, &exitErr) {
		// No arrancó: binario ausente, permisos, plazo agotado. El orquestador
		// lo etiqueta "falta:" y `codeguard repair` lo instala con pip.
		return nil, fmt.Errorf("mypy no corrió en %s: %w", dir, runErr)
	}
	codigo := 0
	if exitErr != nil {
		codigo = exitErr.ExitCode()
	}

	// Los códigos de mypy son 0 = limpio, 1 = encontró errores (señal legítima,
	// como semgrep) y 2 = algo abortó la comprobación. Pero el 2 NO se puede
	// tratar como degradación a secas, y esto se midió: un error de sintaxis en
	// un .py sale con 2 y AUN ASÍ escribe su diagnóstico JSON, porque para mypy
	// es un "blocker" —no puede seguir analizando— sin dejar de ser un problema
	// real del código, de los que más tienen que bloquear el commit. Descartar
	// esa salida por el código 2 tiraría el hallazgo más grave que sabe dar.
	//
	// La señal fiable es la de eslint: la ausencia de salida analizable. Si
	// mypy no dejó nada en stdout y salió con 2, entonces sí falló de verdad
	// (opción inválida, config ilegible) y la capa se declara degradada.
	if len(out) == 0 {
		if codigo >= 2 {
			return nil, fmt.Errorf("mypy falló en %s (código %d): %s", dir, codigo, motivo)
		}
		// EL 1 SE QUEDABA FUERA, Y ERA EL CASO QUE MÁS CLARO ESTÁ.
		//
		// El comentario de arriba razona con cuidado sobre el 2 y luego mete el 1
		// y el 0 en la misma frase —"no hay nada que reportar"— cuando significan
		// cosas opuestas. Para mypy el 1 es EXACTAMENTE «encontré errores de
		// tipos»: si salió con 1 y no escribió ni un diagnóstico, lo que encontró
		// se perdió por el camino. Llamar «limpio» a eso es la clase de fallo que
		// dejó entrar un `return centavos` en una función que promete string.
		if codigo == 1 {
			return nil, fmt.Errorf("mypy salió con 1 en %s —su forma de decir «encontré "+
				"errores de tipos»— y no escribió NI UN diagnóstico: %s. Los errores que "+
				"encontró se perdieron, así que la capa de tipos NO está revisada", dir, motivo)
		}
		// Y el 0 sin salida sí es «no hay errores de tipos»… siempre que quien
		// calló fuera mypy. Callar con éxito es justo lo que hace también una
		// herramienta que no analizó nada, y aquí no hay salida que mirar para
		// distinguirlas: hay que preguntarle quién es. Cuesta ~260 ms medidos, lo
		// paga sólo el análisis limpio, y una vez por binario.
		if err := contrato.Identidad(ctx, contrato.Version("mypy", "mypy", "--version",
			diceSerMypy,
			"Comprueba qué resuelve `mypy` en tu PATH (¿un entorno virtual sin activar?) "+
				"o reinstálalo con `codeguard repair`.",
		)); err != nil {
			return nil, err
		}
		return nil, nil
	}
	// La raíz se pasa CRUDA: adivinar de antemano en qué forma (corta 8.3 o
	// larga) escribe mypy sus rutas fue justamente lo que creó el mismatch —
	// esta máquina devuelve la corta. La conciliación de formas vive en
	// relTo, que canonicaliza ambos lados y sirve igual a todos los motores.
	return hallazgosMypy(repoRoot, dir, out)
}
