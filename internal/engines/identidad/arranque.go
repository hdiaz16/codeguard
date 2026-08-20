package identidad

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// versionDeClase saca de la queja del JVM las dos versiones de formato de clase:
// la que exige el artefacto y la que soporta el runtime instalado.
//
// Los dos números se buscan POR SEPARADO y no con un solo patrón: el mensaje
// viaja en una o en dos líneas según quién lo formatee, y un `.*?` entre ellos
// no cruza el salto.
// falloDeCarga recoge las quejas con las que la JVM confiesa que NO pudo cargar
// el artefacto: jar corrupto, manifiesto sin Main-Class, clase principal
// inencontrable, o versión de clase incompatible cuando el mensaje no trae los
// números que buscan claseNecesita/claseTiene. Son las únicas salidas con código
// de error que PRUEBAN que el artefacto no arranca. El resto —el uso que imprime
// un jar sano al no reconocer --version, por ejemplo— prueba lo contrario: la
// JVM arrancó y el main corrió.
var falloDeCarga = regexp.MustCompile(`Invalid or corrupt jarfile|no main manifest attribute|Could not find or load main class|UnsupportedClassVersionError`)

var (
	claseNecesita = regexp.MustCompile(`class file version (\d+)\.`)
	claseTiene    = regexp.MustCompile(`up to (\d+)\.`)
)

// noArranca devuelve el motivo si el artefacto NO se puede ejecutar en esta
// máquina, o "" si arranca (o si no procede preguntarlo).
//
// Existe porque el hash y la ejecución son preguntas distintas y hasta ahora
// sólo se hacía la primera. google-java-format 1.36.1 es exactamente el jar que
// publicó Google —el checksum cuadra— y con un JDK 17 muere al arrancar, porque
// está compilado para Java 21. `codeguard engines` lo listaba como "coincide con
// el binario publicado": cierto, y engañoso, porque el formateo de Java quedaba
// degradado de forma PERMANENTE y nada decía por qué ni que no se iba a arreglar
// solo.
//
// Sólo se pregunta de lo que corre sobre la JVM. Un .exe nativo no tiene el
// problema de versión de clase, y arrancar cada binario en cada `engines` para
// nada costaría más de lo que informa.
// plazoArranque es lo que se le da a un motor para decir su versión. 20 s es
// holgado para arrancar una JVM en frío. Es var y no const para que las pruebas
// puedan agotarlo a propósito: la confusión entre "tardó" y "no arranca" sólo se
// puede probar provocando el plazo.
var plazoArranque = 20 * time.Second

func noArranca(ruta string) string {
	var cmd *exec.Cmd
	ctx, cancel := context.WithTimeout(context.Background(), plazoArranque)
	defer cancel()

	switch {
	case strings.EqualFold(filepath.Ext(ruta), ".jar"):
		if _, err := exec.LookPath("java"); err != nil {
			// Sin java no se puede afirmar que no arranque: lo que falta es el
			// runtime, y de eso ya se queja el motor cuando lo invoca el análisis.
			return ""
		}
		cmd = comandoIdentidad(ctx, "java", "-jar", ruta, "--version")
	case esArbolDePMD(ruta):
		if _, err := exec.LookPath("java"); err != nil {
			return ""
		}
		cmd = comandoIdentidad(ctx, filepath.Join(ruta, "bin", "pmd.bat"), "--version")
	default:
		return "" // .exe nativo: no aplica
	}

	// Al vencer el plazo hay que tumbar el ÁRBOL, no sólo el proceso directo:
	// pmd.bat es un cmd que lanza java, y el Kill por defecto de CommandContext
	// mata el cmd y deja la JVM huérfana — una fuga de memoria y CPU por cada
	// comprobación que agote el plazo, en un daemon que vive días. taskkill /T
	// recorre el árbol y se los lleva juntos.
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// El taskkill también pasa por comandoIdentidad: es la regla del paquete
		// —y hay una prueba que la vigila— porque un hijo armado a mano abre
		// ventana negra y hereda el entorno entero, con la clave del modelo
		// dentro. Lleva contexto propio: el del comando acaba de vencer, y con
		// ése el kill se cancelaría antes de empezar.
		ctxKill, cancelKill := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelKill()
		return comandoIdentidad(ctxKill, "taskkill",
			"/PID", strconv.Itoa(cmd.Process.Pid), "/T", "/F").Run()
	}
	// Y WaitDelay acota la espera de Wait por si un hijo moribundo retiene las
	// tuberías: sin él, CombinedOutput podía colgarse más allá del plazo que
	// acababa de agotarse. Mismo recurso que ya usa auditoria.go.
	cmd.WaitDelay = 5 * time.Second

	salida, err := cmd.CombinedOutput()
	if err == nil {
		return ""
	}
	// EL PLAZO SE COMPRUEBA ANTES QUE EL ExitError, y el orden es el arreglo.
	//
	// La guarda de abajo quiere decir justo esto —"el plazo agotado habla del
	// ENTORNO, no del motor"— y en Windows no lo conseguía: al vencer el plazo,
	// exec mata el proceso y Wait devuelve "exit status 1", que ES un
	// *exec.ExitError. Así que el plazo entraba por la rama de la acusación, no
	// encontraba versiones de clase en una salida vacía y terminaba devolviendo
	// "no arranca en esta máquina: " con el motivo EN BLANCO. El mismo "no
	// arranca: sin mensaje" sobre un artefacto impecable que el comentario de
	// abajo da por resuelto, entrando por otra puerta.
	//
	// Medido con un plazo de 150 ms sobre el pmd.bat real: ctx.Err() es
	// "context deadline exceeded", err es "exit status 1", errors.As da true y
	// la salida viene vacía. Y no es teórico: lanzando la comprobación muchas
	// veces seguidas, PMD —que arranca perfectamente, 0 fallos en 12 intentos
	// sueltos— salía como "no-arranca" de forma intermitente. Con esto de por
	// medio, una máquina lenta o cargada deja de acusar a un motor sano.
	if ctx.Err() != nil {
		return ""
	}
	// Sólo un código de salida distinto de cero prueba que el artefacto no
	// arranca. Cualquier otro error —java roto o ausente, el plazo agotado, un
	// fallo de E/S— habla del ENTORNO, no del motor, y acusar al artefacto ahí
	// sería la misma mentira al revés: con un java inválido, CombinedOutput
	// devuelve salida vacía y esto llegaba a decir "no arranca: sin mensaje"
	// sobre un jar impecable. Además es incoherente con la rama de LookPath, que
	// en ese caso calla a propósito.
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return ""
	}
	texto := string(salida)
	if n, t := primerNumero(claseNecesita, texto), primerNumero(claseTiene, texto); n > 0 && t > 0 {
		// Versión de clase → versión de JDK: 45 = Java 1.1, así que la resta es
		// 44 (61 → 17, 65 → 21).
		return "necesita JDK " + strconv.Itoa(n-44) +
			" y esta máquina tiene JDK " + strconv.Itoa(t-44) +
			": instala uno más nuevo o esta capa quedará degradada"
	}
	// Fuera de la versión de clase, sólo se acusa con PRUEBA de que la JVM no
	// pudo cargar el artefacto. Un jar o un PMD que arranca perfectamente pero no
	// reconoce --version imprime su uso y sale con código distinto de cero: eso
	// no es «no arranca», es «arrancó y no le gustó el flag». Acusarlo sería la
	// misma mentira contra un artefacto sano que los dos comentarios de arriba
	// vienen a desterrar — y manda al dev a reinstalar algo que funciona.
	if !falloDeCarga.MatchString(texto) {
		return ""
	}
	// Fallo de carga probado: se da la primera línea real, sin inventar un
	// diagnóstico que no se pudo leer.
	return "no arranca en esta máquina: " + primeraLinea(texto)
}

// esArbolDePMD reconoce la instalación de PMD por su LANZADOR, no por el nombre
// del directorio.
//
// Mirar el nombre fallaba hacia el lado peligroso: el día que un zip cambie la
// carpeta raíz (pmd-8.x, pmd-dist) esto daría false, noArranca devolvería "" y
// PMD volvería a listarse como "coincide con el binario publicado" sin que nada
// avisara de que se dejó de comprobar. La existencia del .bat es lo que de
// verdad decide si hay algo que arrancar.
func esArbolDePMD(ruta string) bool {
	st, err := os.Stat(filepath.Join(ruta, "bin", "pmd.bat"))
	return err == nil && !st.IsDir()
}

func primerNumero(re *regexp.Regexp, s string) int {
	m := re.FindStringSubmatch(s)
	if m == nil {
		return 0
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0
	}
	return n
}

func primeraLinea(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	const tope = 200
	if len(s) > tope {
		return s[:tope] + "…"
	}
	if s == "" {
		return "sin mensaje"
	}
	return s
}
