package linters

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"codeguard/internal/engines/proc"
)

// topeSalida es el tope por flujo de runTool. Es variable y no constante para
// que las pruebas puedan provocar un recorte sin generar 64 MB.
var topeSalida int64 = proc.MaxSalida

// ExecResult es el contrato tipado de ejecución de una herramienta externa:
// TODOS los hechos del transporte, sin una gota de política. Qué código de
// salida significa «hallazgos», qué silencio es avería y qué recorte se
// tolera lo decide cada adaptador leyendo estos campos — nunca el transporte
// por él.
//
// Es el contrato definitivo: runTool, runToolConSalida y runToolSeparado
// quedan como cáscaras de compatibilidad encima de ejecutar() y se migran
// por tandas. NO añadas llamadores nuevos a esas tres; consume ejecutar().
type ExecResult struct {
	Stdout, Stderr []byte
	// ExitCode es 0 si terminó bien; el del proceso si terminó con error;
	// -1 si no arrancó, murió por señal o lo mató el plazo.
	ExitCode int
	// Started es false cuando no hubo proceso que interpretar: binario
	// ausente, permisos, contexto ya cancelado antes de arrancar. Es el hecho
	// Salida.Arranco del transporte, no una inferencia sobre el error. Un
	// adaptador jamás convierte Started=false en «limpio».
	Started bool
	// TimedOut: el error ES un vencimiento o cancelación del context (por
	// identidad, no por mirar el reloj: un proceso que terminó limpio justo
	// antes de vencer el plazo NO está aquí). La salida puede estar a medias
	// y el ExitCode no significa nada.
	TimedOut bool
	// Truncated describe el ESTADO de la salida (algún flujo superó el tope,
	// está incompleta), no la causa: también vale true cuando al proceso lo
	// mataron a media escritura. La causa se distingue por identidad en Err
	// (proc.ErrRecortada = terminó solo y no cupo; TimedOut = lo mataron).
	Truncated bool
	// Err es el error crudo de proc.Correr, para errors.Is/errors.As.
	Err error
}

// Combinada devuelve stdout seguido de stderr (el mismo contrato que
// proc.Salida.Combinada), para adaptadores que leen diagnóstico como texto.
func (r ExecResult) Combinada() string {
	if len(r.Stderr) == 0 {
		return string(r.Stdout)
	}
	return string(r.Stdout) + string(r.Stderr)
}

// ejecutar corre una herramienta y devuelve los hechos completos.
func ejecutar(ctx context.Context, dir, bin string, args ...string) ExecResult {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	// Herramientas Python en Windows: sin esto leen/escriben en cp1252
	// y rompen los acentos (mismo fix que en el adaptador de semgrep).
	cmd.Env = proc.Entorno("PYTHONUTF8=1", "PYTHONIOENCODING=utf-8")
	salida, err := proc.Correr(ctx, cmd, topeSalida)
	r := ExecResult{
		Stdout:    salida.Stdout,
		Stderr:    salida.Stderr,
		Started:   salida.Arranco,
		TimedOut:  errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled),
		Truncated: salida.Recortada,
		Err:       err,
	}
	var exitErr *exec.ExitError
	switch {
	case errors.As(err, &exitErr):
		r.ExitCode = exitErr.ExitCode() // -1 si murió por señal
	case err == nil || errors.Is(err, proc.ErrRecortada):
		// terminó con código 0, con o sin recorte
	default:
		r.ExitCode = -1 // no arrancó, o lo mató el plazo: no hay código que leer
	}
	return r
}

// runTool ejecuta una herramienta y devuelve stdout+stderr combinados.
// Un exit code != 0 NO es error si hubo salida (los linters salen con 1
// cuando encuentran problemas); sin salida sí es fallo de ejecución.
//
// Cáscara de compatibilidad sobre ejecutar(); no añadas llamadores nuevos.
func runTool(ctx context.Context, dir, bin string, args ...string) (string, error) {
	r := ejecutar(ctx, dir, bin, args...)
	// Por identidad del error y no por ctx.Err(): un proceso que terminó
	// limpio justo antes de vencer el reloj es un análisis completo, y
	// descartarlo aquí lo convertía en ("", nil) — un verde silencioso.
	if r.TimedOut {
		return "", r.Err
	}
	var exitErr *exec.ExitError
	if r.Err != nil && !errors.As(r.Err, &exitErr) && !errors.Is(r.Err, proc.ErrRecortada) {
		return "", r.Err // no arrancó (binario ausente, permisos...)
	}
	// El recorte se tolera por la IDENTIDAD del error y no por la bandera
	// Truncated: la bandera también vale true cuando al motor lo mataron
	// a media escritura, y mirarla ahí devolvía la salida parcial con err nil.
	// El daño no era el mensaje perdido — govet cachea lo que devolvamos bajo
	// la clave de contenido, así que el análisis a medias se congelaba y se
	// servía en las corridas siguientes como si estuviera completo.
	//
	// Los linters se leen línea por línea: un texto recortado sigue siendo
	// útil, a diferencia de un JSON a medias.
	combinada := r.Combinada()
	// La segunda mitad del contrato de arriba: el exit != 0 se tolera PORQUE
	// hay diagnósticos que leer. Con cero bytes no hay análisis que defender —
	// devolver ("", nil) convertía la avería en «corrió y no encontró nada».
	// %v y no ExitCode: con muerte por señal el código es -1 y «salió con
	// código -1» confunde; el Error() de ExitError distingue ambos casos.
	if exitErr != nil && strings.TrimSpace(combinada) == "" {
		return "", fmt.Errorf("%s salió con %v sin escribir nada: avería de ejecución, no un análisis limpio",
			filepath.Base(bin), exitErr)
	}
	return combinada, nil
}

// runToolConSalida es runTool diciendo ADEMÁS si el proceso salió con código
// distinto de cero.
//
// Existe por un verde silencioso medido en una máquina real. El motor de tsc
// cae a `npx --no-install tsc` cuando el repo no trae node_modules, y en esa
// máquina eso resolvía a un paquete de npm llamado `tsc` que NO es TypeScript:
// imprime un banner y sale con 1. runTool tolera la salida distinta de cero a
// propósito —los linters salen con error cuando encuentran problemas— así que
// el banner llegaba al parser, el parser no encontraba ni un diagnóstico, y
// cero diagnósticos se reportaba como CERO HALLAZGOS. O sea: "revisé y está
// limpio" sobre un archivo que nadie compiló. Un `return centavos` donde la
// función promete string entró al repositorio con el ✓ verde.
//
// Con el código de salida, quien llama puede distinguir las tres situaciones
// que hasta aquí se confundían en una:
//
//	salió 0            → miró y no encontró nada. Limpio de verdad.
//	salió ≠0 CON diagnósticos → miró y encontró. Hallazgos.
//	salió ≠0 SIN diagnósticos → NO miró. No se puede decir que esté limpio.
//
// El tercer caso es el que este producto no se puede permitir callar, porque
// su silencio es idéntico al del primero.
// Cáscara de compatibilidad sobre ejecutar(); no añadas llamadores nuevos.
func runToolConSalida(ctx context.Context, dir, bin string, args ...string) (texto string, fallo bool, err error) {
	r := ejecutar(ctx, dir, bin, args...)
	var exitErr *exec.ExitError
	if r.Err != nil && !errors.As(r.Err, &exitErr) && !errors.Is(r.Err, proc.ErrRecortada) {
		return "", true, r.Err // no arrancó, o venció el plazo
	}
	// El RECORTE también cuenta como fallo, y es la cuarta situación que faltaba
	// en la tabla de arriba: el proceso superó el tope y se le mató a media
	// escritura, así que la salida está partida. Con `fallo=false` el llamador la
	// leería como el primer caso —«salió 0: miró y no encontró nada»— y si el
	// trozo que alcanzó a escribir no trae diagnósticos parseables, reportaría
	// CERO HALLAZGOS sobre un análisis a medias. El mismo verde silencioso que
	// esta función nació para cerrar, por otra puerta. El texto parcial se sigue
	// devolviendo —sus diagnósticos son válidos, se leen línea a línea—; lo que
	// cambia es que ya no viaja con el sello de «limpio de verdad».
	return r.Combinada(), exitErr != nil || errors.Is(r.Err, proc.ErrRecortada), nil
}

// runToolSeparado devuelve stdout y stderr SIN MEZCLAR.
//
// Los dos de arriba juntan los canales, y para casi todos los linters da igual:
// escriben sus diagnósticos por uno y no usan el otro. Pero hay herramientas que
// reparten a propósito, y ahí la mezcla borra la información que decide si
// analizaron o no.
//
// El caso que lo pidió es `go vet -json`, medido en esta máquina:
//
//	paquete limpio      → stdout `{}`             · stderr vacío   · código 0
//	con diagnósticos    → stdout el JSON          · stderr vacío   · código 0
//	no compila          → stdout VACÍO            · stderr el motivo · código 1
//	uno roto y otro no  → stdout el JSON del bueno · stderr el motivo del roto
//
// Con los canales separados, "escribió algo en stdout" ES la prueba de que vet
// analizó, y el stderr se lee como lo que es: motivos de carga, más el ruido
// propio del toolchain (`go: downloading …`). Mezclados, ese ruido inofensivo
// era indistinguible de un fallo de carga y govet se declaraba incapaz sobre un
// módulo que había analizado perfectamente.
//
// El código de salida NO se devuelve, y no es un olvido: con -json vet sale con
// 0 aunque encuentre cosas, así que aquí el código no distingue nada que los
// canales no digan mejor.
// Cáscara de compatibilidad sobre ejecutar(); no añadas llamadores nuevos.
func runToolSeparado(ctx context.Context, dir, bin string, args ...string) (stdout, stderr string, err error) {
	r := ejecutar(ctx, dir, bin, args...)
	var exitErr *exec.ExitError
	if r.Err != nil && !errors.As(r.Err, &exitErr) && !errors.Is(r.Err, proc.ErrRecortada) {
		return "", "", r.Err // no arrancó (binario ausente, permisos...) o venció el plazo
	}
	return string(r.Stdout), string(r.Stderr), nil
}

// (runToolStdin vivió aquí para preguntarle a gofmt por stdin; se fue cuando
// el motor de formato pasó a go/format en proceso — lo señaló U1000 del
// propio staticcheck recién estrenado.)

// relTo pasa la ruta que reportó un motor a relativa-al-repo, y NO se fía de
// que filepath.Rel haya tenido éxito.
//
// Rel devuelve error sólo cuando no puede construir una relación (unidades
// distintas). Si las dos rutas son del mismo disco pero apuntan a sitios
// distintos, tiene "éxito" y devuelve algo como `..\..\..\..\otro\sitio`. Esa
// ruta no la abre ningún editor, no casa con ninguna huella de la baseline y no
// coincide con ningún archivo del diff: el hallazgo DESAPARECE en silencio, que
// es el peor final posible para un hallazgo real.
//
// El caso que lo destapó: Windows tiene dos nombres para el mismo directorio,
// el corto 8.3 (HECTOR~1.BOD) y el largo, y NO hay regla sobre qué forma
// imprime cada motor —se midió un mypy devolviendo la corta mientras la raíz
// venía en la larga, justo al revés de lo que se asumía aquí. Con las dos
// formas mezcladas, Rel devolvía nueve `..` y el hallazgo se evaporaba. Lo
// encontró una prueba de integración de mypy, no un usuario — esta vez.
//
// La defensa no depende de conocer ese caso ni de adivinar qué lado viene en
// qué forma: si el resultado se sale de la raíz, se reintenta con AMBOS lados
// canonicalizados —EvalSymlinks resuelve el 8.3 a la forma larga, así que
// corto-con-largo y largo-con-corto acaban comparándose en la misma forma—,
// luego con sólo la raíz canónica, y si aún se sale se devuelve la ruta cruda.
// Una ruta rara es incómoda; una ruta inventada esconde el hallazgo.
//
// EvalSymlinks(p) exige que p EXISTA en disco. Si no existe (hallazgo sobre
// un archivo borrado entre el análisis y la lectura) ese intento se omite y
// se cae al comportamiento de siempre: no es un silencio nuevo, es el mismo
// desenlace que ya tenía ese caso.
func relTo(root, p string) string {
	if rel, ok := relDentroDe(root, p); ok {
		return rel
	}
	// Primero los dos lados en forma canónica: es el único reintento que
	// arregla la disparidad corto/largo venga de donde venga.
	canonRoot, errRoot := filepath.EvalSymlinks(root)
	canonP, errP := filepath.EvalSymlinks(p)
	if errRoot == nil && errP == nil {
		if rel, ok := relDentroDe(canonRoot, canonP); ok {
			return rel
		}
	}
	if errRoot == nil && canonRoot != root {
		if rel, ok := relDentroDe(canonRoot, p); ok {
			return rel
		}
	}
	return filepath.ToSlash(p)
}

// relDentroDe devuelve la ruta relativa sólo si de verdad cae DENTRO de la
// raíz. Un resultado que empieza por ".." es Rel diciendo "está en otro sitio",
// no una ruta utilizable.
func relDentroDe(root, p string) (string, bool) {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return "", false
	}
	rel = filepath.ToSlash(rel)
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return "", false
	}
	return rel, true
}
