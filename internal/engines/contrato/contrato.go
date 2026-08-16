// Package contrato cierra la única mitad del contrato de los motores que la
// salida de la herramienta no puede demostrar por sí sola.
//
// EL CONTRATO: un motor devuelve hallazgos, o devuelve por qué no pudo. No hay
// tercera opción. La tercera —(nil, nil) sin haber mirado— es la que pinta un ✓
// verde sobre una capa que no analizó nada, y en un solo día se cobró a `tsc`
// (donde un `return centavos` en una función que promete string entró al repo en
// verde), a `google-java-format` y a `go vet`.
//
// Para la mayoría de las herramientas el silencio se juzga sin ayuda, porque
// dejan una huella de haber trabajado: gitleaks escribe su --report-path incluso
// sin hallazgos, y `go vet -json` escribe `{}`. Cuando existe esa huella, es la
// respuesta: sale gratis, viene de la corrida de verdad y no hay nada que
// preguntar.
//
// Pero hay herramientas que limpias no dicen NADA y salen con 0. Medido en esta
// máquina: `staticcheck -f json` sobre un módulo limpio deja 0 bytes y código 0;
// `mypy --output=json` sin errores, 0 bytes y código 0. Su silencio es idéntico,
// byte a byte, al de un impostor que no hizo nada — y ahí no hay salida que
// mirar, porque el problema es justamente que no hay salida.
//
// La única forma de separarlos es preguntarle a lo que corrió QUIÉN ES.
package contrato

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"

	"codeguard/internal/engines/proc"
)

// Prueba es la pregunta "¿quién eres?" para una herramienta concreta.
type Prueba struct {
	// Motor es el nombre con el que el usuario lo ve en el panel.
	Motor string
	// Bin es el binario tal como lo invoca el motor: el mismo valor, para que se
	// compruebe la identidad de lo que DE VERDAD corrió y no la de otro archivo
	// con el mismo nombre en otro sitio del PATH.
	Bin string
	// Args son los argumentos que la hacen decir su versión.
	Args []string
	// Dir es el directorio desde donde preguntar. Vacío = el del proceso.
	Dir string
	// Espera es lo que la respuesta tiene que contener para reconocerla.
	Espera *regexp.Regexp
	// Pista es qué hacer si no se reconoce, en imperativo y en una línea.
	Pista string
}

// respuesta guarda el veredicto de una Prueba ya hecha.
type respuesta struct {
	err error
}

var (
	memoria sync.Mutex
	hechas  = map[string]respuesta{}
)

// Identidad devuelve nil si la herramienta se identificó como la que se
// esperaba, y un error explicando el desajuste si no.
//
// Se llama SÓLO cuando la herramienta acaba de callar con éxito, que es el único
// caso que la salida no puede resolver. Así el coste no lo paga cada análisis:
// lo paga el análisis que no encontró nada, y sólo la primera vez por binario.
//
// El resultado se memoriza por ruta resuelta + tamaño + fecha del archivo, no
// por nombre: actualizar la herramienta cambia la clave y se vuelve a preguntar,
// que es lo que hay que hacer. La memoria importa porque el daemon vive días.
func Identidad(ctx context.Context, p Prueba) error {
	ruta, err := exec.LookPath(p.Bin)
	if err != nil {
		// Que el binario no esté es un asunto distinto —"falta el motor", no
		// "el motor miente"— y el orquestador lo clasifica aparte con errors.Is.
		// Por eso el error viaja entero en vez de envolverse en un mensaje.
		return err
	}
	clave := ruta + "\x00" + strings.Join(p.Args, " ")
	if info, err := os.Stat(ruta); err == nil {
		clave = fmt.Sprintf("%s\x00%d\x00%d", clave, info.Size(), info.ModTime().UnixNano())
	}

	memoria.Lock()
	previa, vista := hechas[clave]
	memoria.Unlock()
	if vista {
		return previa.err
	}

	veredicto := preguntar(ctx, ruta, p)

	// Un plazo agotado NO se memoriza: es una circunstancia del momento, y
	// guardarla condenaría al motor durante toda la vida del daemon por un
	// arranque en frío que fue lento una vez.
	if ctx.Err() == nil {
		memoria.Lock()
		hechas[clave] = respuesta{err: veredicto}
		memoria.Unlock()
	}
	return veredicto
}

func preguntar(ctx context.Context, ruta string, p Prueba) error {
	cmd := exec.CommandContext(ctx, ruta, p.Args...)
	cmd.Dir = p.Dir
	cmd.Env = proc.Entorno()
	salida, err := proc.Correr(ctx, cmd, proc.MaxSalida)
	// El código de salida se ignora a propósito: hay herramientas que responden
	// a --version por stderr, y alguna que sale distinto de cero al hacerlo. Lo
	// que se juzga es la RESPUESTA.
	dijo := strings.TrimSpace(string(salida.Combinada()))

	if p.Espera != nil && p.Espera.MatchString(dijo) {
		return nil
	}

	// UN PLAZO AGOTADO NO ES UNA HERRAMIENTA MENTIROSA, y la diferencia la nota el
	// desarrollador.
	//
	// El orquestador clasifica con errors.Is: `context.DeadlineExceeded` lo
	// etiqueta "motor:plazo" —«no terminó a tiempo», que en una primera corrida en
	// frío es normal y se arregla solo— y cualquier otro error lo etiqueta
	// "motor:error", que manda a buscar una avería. Si el centinela llega como
	// TEXTO dentro del mensaje, errors.Is no lo ve y el aviso miente.
	//
	// Pasa de verdad: la sonda corre DENTRO del plazo del motor, y justo se lanza
	// cuando el motor acaba de terminar, o sea con el presupuesto casi gastado.
	if ctx.Err() != nil {
		return fmt.Errorf("%s no llegó a decir quién es antes de agotarse el plazo: %w",
			p.Motor, ctx.Err())
	}
	if dijo == "" {
		return fmt.Errorf("%s terminó sin encontrar nada, y al preguntarle quién es (`%s %s`) "+
			"tampoco contestó%s. Una herramienta que no sabe decir su versión no ha analizado "+
			"nada: no se puede llamar «limpio» a su silencio. %s",
			p.Motor, nombreCorto(ruta), strings.Join(p.Args, " "), porque(err), p.Pista)
	}
	return fmt.Errorf("%s terminó sin encontrar nada, pero al preguntarle quién es (`%s %s`) "+
		"contestó algo que no reconozco: %q. Lo que hay en tu PATH con ese nombre no es la "+
		"herramienta que este motor necesita, así que su silencio no significa «limpio». %s",
		p.Motor, nombreCorto(ruta), strings.Join(p.Args, " "), recorte(dijo), p.Pista)
}

func porque(err error) string {
	if err == nil {
		return ""
	}
	return " (" + err.Error() + ")"
}

// nombreCorto deja el nombre del ejecutable: la ruta entera de un binario
// instalado ocupa media línea y no añade nada al diagnóstico.
func nombreCorto(ruta string) string {
	if i := strings.LastIndexAny(ruta, `/\`); i >= 0 {
		return ruta[i+1:]
	}
	return ruta
}

func recorte(s string) string {
	if i := strings.IndexByte(s, '\n'); i > 0 {
		s = s[:i]
	}
	if len(s) > 120 {
		s = s[:120] + "…"
	}
	return strings.TrimSpace(s)
}

// OlvidarTodo borra la memoria de identidades. Es para los tests: sin esto, un
// caso que sustituye la herramienta por un impostor heredaría el veredicto del
// caso anterior y pasaría —o fallaría— por el motivo equivocado.
func OlvidarTodo() {
	memoria.Lock()
	hechas = map[string]respuesta{}
	memoria.Unlock()
}

// Version arma la Prueba habitual: preguntar por la versión y reconocerla.
func Version(motor, bin, bandera string, espera *regexp.Regexp, pista string) Prueba {
	return Prueba{Motor: motor, Bin: bin, Args: []string{bandera}, Espera: espera, Pista: pista}
}
