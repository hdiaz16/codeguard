package pipeline_test

// El arnés de extremo a extremo existe para cazar motores que dejan de mirar.
// Este archivo es el arnés DEL ARNÉS: comprueba que sus absoluciones —"se
// degradó", "no aplica"— sólo se conceden cuando de verdad corresponden, y que
// sabe distinguir un daemon muerto de uno lento.
//
// El motivo es concreto. La tabla clasificaba así:
//
//	degradados[n]      → DEGRADADO, sólo t.Logf. NUNCA fallaba.
//	v.requiere != ""   → NO APLICA, sin comprobar si el requisito estaba.
//
// Con eso, un semgrep que empezara a reventar salía DEGRADADO y la prueba
// seguía verde; y un trivy roto con red disponible salía NO APLICA, que tampoco
// falla. Es decir: las dos pruebas que tenían que avisarnos de los fail-open del
// producto estaban apagadas justo para los casos que importan.

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

// ── el guardián del arranque del daemon ──────────────────────────────────────

// Un daemon que muere al arrancar y uno que va lento se parecen desde fuera: el
// pipe no contesta en los dos casos. El arnés decía distinguirlos mirando
// c.ProcessState, que SÓLO lo rellena Wait — y en ese bucle no se llamaba a Wait
// nunca. La rama era código muerto: el daemon podía estar muerto desde el primer
// milisegundo y la prueba esperaba el plazo entero para acusarlo de lento,
// mandando a buscar el problema justo donde no estaba.
func TestElArnesDelDaemonDistingueMuerteDeLentitud(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("los pipes con nombre son de Windows")
	}
	// Un proceso que sale de inmediato es exactamente lo que deja un daemon que no
	// arranca: config ilegible, puerto tomado, panic al iniciar.
	c := exec.Command("cmd", "/c", "exit 1")
	if err := c.Start(); err != nil {
		t.Fatalf("no se pudo arrancar el proceso de prueba: %v", err)
	}
	t.Cleanup(func() { _ = c.Process.Kill() })

	const plazo = 6 * time.Second
	inicio := time.Now()
	err := esperarAlPipe(c, `\\.\pipe\codeguard-que-nadie-atiende-jamas`, plazo)
	tardo := time.Since(inicio)

	if err == nil {
		t.Fatal("el proceso estaba muerto y la espera dijo que el pipe se atendió")
	}
	if !strings.Contains(err.Error(), "se murió") {
		t.Errorf("el daemon murió al arrancar y el arnés lo llamó lentitud: %q.\n"+
			"El diagnóstico manda a mirar el cronómetro en vez del log de arranque, "+
			"que es donde está el problema.", err)
	}
	if tardo >= plazo {
		t.Errorf("tardó %v (plazo %v) en notar que el proceso YA estaba muerto: "+
			"esperó el plazo entero, o sea que no se enteró", tardo, plazo)
	}
}

// salidaCon fabrica la salida del producto que corresponde a un estado dado.
// Es el formato que revisarInforme parsea de verdad (reLinea y reDegradado), no
// una aproximación: si el producto cambia cómo se anuncia, estas pruebas lo
// notan igual que el arnés.
func salidaCon(lineas ...string) string {
	return strings.Join(lineas, "\n") + "\n"
}

func filaDe(t *testing.T, filas []fila, motor string) fila {
	t.Helper()
	for _, f := range filas {
		if f.motor == motor {
			return f
		}
	}
	t.Fatalf("el motor %q no salió en la tabla del arnés", motor)
	return fila{}
}

// ── el guardián de "se degradó" ──────────────────────────────────────────────

// Un motor SIN dependencias externas que se degrada es una regresión: no hay
// nada del entorno a lo que culpar. Antes salía DEGRADADO y la prueba pasaba.
func TestElArnesFallaSiUnMotorSinDependenciasSeDegrada(t *testing.T) {
	filas, err := revisarInforme(t.TempDir(), salidaCon(
		"semgrep degradado: se acabó el plazo",
		"gofmt: 1 hallazgo(s)",
	))
	if err != nil {
		t.Fatal(err)
	}
	f := filaDe(t, filas, "semgrep")
	if !f.falla {
		t.Errorf("semgrep no tiene dependencias externas y se degradó: eso es una regresión "+
			"del producto y el arnés la dejó pasar (estado %q).\n"+
			"Un motor que deja de correr y no pone nada en rojo es exactamente el fallo "+
			"que este arnés existe para cazar.", f.estado)
	}
}

// conLaDependencia fija la respuesta de "¿falta la dependencia?" durante una
// prueba y la restaura al terminar.
//
// Los guardianes de abajo prueban la TABLA DE DECISIÓN del arnés, no el
// inventario de esta máquina. Preguntándole a la máquina no probaban nada:
// medido antes de existir esto, el guardián de "no aplica" ejercitaba CERO de
// sus diez motores, y no por falta de herramientas sino por construcción — ver
// el comentario de faltaLaDependencia en extremo_a_extremo_test.go.
func conLaDependencia(t *testing.T, presente bool) {
	t.Helper()
	previo := faltaLaDependencia
	t.Cleanup(func() { faltaLaDependencia = previo })
	faltaLaDependencia = func(violacion, string) bool { return !presente }
}

// motoresConDependencia son los que declaran un requisito externo, sacados de la
// tabla y no de una lista escrita a mano: así, un motor que se añada mañana
// entra solo en los dos guardianes en vez de quedarse fuera en silencio.
func motoresConDependencia() []string {
	var out []string
	for _, v := range violaciones() {
		if v.requiere != "" {
			out = append(out, v.motor)
		}
	}
	return out
}

// La otra cara: si la dependencia NO está, degradarse es lo correcto y no puede
// poner la prueba en rojo. Sin esto, el arreglo de arriba se "conseguiría"
// fallando siempre, y la suite quedaría roja en cualquier máquina sin JDK.
func TestElArnesToleraElDegradadoDeUnMotorSinSuDependencia(t *testing.T) {
	conLaDependencia(t, false)

	filas, err := revisarInforme(t.TempDir(), salidaCon(
		"pmd degradado: no se encontró PMD",
		"gofmt: 1 hallazgo(s)",
	))
	if err != nil {
		t.Fatal(err)
	}
	f := filaDe(t, filas, "pmd")
	if f.falla {
		t.Errorf("pmd se degradó porque falta su dependencia (%s) y el arnés lo tomó por "+
			"regresión: eso pone la suite en rojo por el entorno, no por el producto", f.detalle)
	}
	if f.estado != "DEGRADADO" {
		t.Errorf("pmd debía quedar DEGRADADO y quedó %q", f.estado)
	}
}

// ── el guardián de "no aplica" ───────────────────────────────────────────────

// NO APLICA se concedía por DECLARAR una dependencia, no por que faltara. Un
// motor con su dependencia presente que anuncia 0 hallazgos CORRIÓ y no vio su
// violación: es ¡NO CAZÓ!, el estado peligroso.
func TestElArnesNoAbsuelveAUnMotorConSuDependenciaPresente(t *testing.T) {
	conLaDependencia(t, true) // presente: la absolución ya no es legítima

	motores := motoresConDependencia()
	// El guardián del guardián. Esta prueba se pasó una remediación entera
	// saltándose entera —«nada que absolver mal»— porque preguntaba por las
	// herramientas de la máquina; un t.Skip no se lee en la salida y nadie
	// volvió a mirar. Ahora, quedarse sin motores que ejercitar es un FALLO.
	if len(motores) == 0 {
		t.Fatal("ningún motor declara dependencia externa: este guardián no comprueba nada")
	}

	for _, motor := range motores {
		t.Run(motor, func(t *testing.T) {
			filas, err := revisarInforme(t.TempDir(), salidaCon(
				motor+": 0 hallazgo(s)",
				"gofmt: 1 hallazgo(s)",
			))
			if err != nil {
				t.Fatal(err)
			}
			f := filaDe(t, filas, motor)
			if f.estado != "¡NO CAZÓ!" {
				t.Errorf("%s tiene su dependencia PRESENTE y anunció 0 hallazgos con la violación "+
					"delante: corrió y no la vio. El arnés lo llamó %q en vez de ¡NO CAZÓ!",
					motor, f.estado)
			}
			if !f.falla {
				t.Errorf("%s corrió con su dependencia presente y no vio su violación, y el arnés "+
					"NO puso la prueba en rojo (estado %q).\n"+
					"Así, un motor roto con su herramienta instalada pasa por «no aplica» y la "+
					"casilla se queda verde para siempre.", motor, f.estado)
			}
		})
	}
	t.Logf("motores ejercitados con la dependencia presente: %d (%v)", len(motores), motores)
}

// Y la cara opuesta, otra vez para que el arreglo no pueda ser "fallar siempre":
// sin la dependencia, 0 hallazgos es NO APLICA y no puede romper la suite.
func TestElArnesSiguePerdonandoAlMotorSinSuDependencia(t *testing.T) {
	conLaDependencia(t, false) // ausente: absolver es lo correcto

	motores := motoresConDependencia()
	if len(motores) == 0 {
		t.Fatal("ningún motor declara dependencia externa: este guardián no comprueba nada")
	}

	for _, motor := range motores {
		t.Run(motor, func(t *testing.T) {
			filas, err := revisarInforme(t.TempDir(), salidaCon(
				motor+": 0 hallazgo(s)",
				"gofmt: 1 hallazgo(s)",
			))
			if err != nil {
				t.Fatal(err)
			}
			f := filaDe(t, filas, motor)
			if f.falla {
				t.Errorf("%s no tiene su dependencia y el arnés lo dio por roto: "+
					"la suite se pondría roja por el entorno (estado %q)", motor, f.estado)
			}
			if f.estado != "NO APLICA" {
				t.Errorf("%s sin dependencia debe decir NO APLICA en voz alta, dijo %q", motor, f.estado)
			}
		})
	}
	t.Logf("motores ejercitados con la dependencia ausente: %d (%v)", len(motores), motores)
}

// ── el contrato de la tabla ──────────────────────────────────────────────────

// Toda violación que declara un requisito tiene que traer la forma de
// COMPROBARLO. Sin esto, añadir mañana un motor con `requiere:` y sin `presente:`
// reabriría el agujero en silencio: volvería a absolverse por declarar.
func TestTodaDependenciaDeclaradaEsComprobable(t *testing.T) {
	for _, v := range violaciones() {
		if v.requiere != "" && v.presente == nil {
			t.Errorf("%s declara requerir %q pero no trae con qué comprobarlo: "+
				"se absolvería solo por declararlo, que es el fallo que esto arregla",
				v.motor, v.requiere)
		}
		if v.requiere == "" && v.presente != nil {
			t.Errorf("%s trae comprobación de dependencia pero no declara ninguna", v.motor)
		}
	}
}

// Y el cierre del círculo: que el arnés DE VERDAD siga preguntándole a la
// comprobación de cada motor.
//
// Los dos guardianes de arriba sustituyen faltaLaDependencia para poder probar
// la tabla de decisión en cualquier máquina. El precio de un punto de
// sustitución es que el camino real deje de ejercitarse: si alguien cambiara el
// valor por defecto por un `return false`, los dos guardianes seguirían verdes y
// el arnés absolvería a todo el mundo otra vez, que es exactamente el bug del
// que venimos. Esta prueba mira el valor por defecto, sin sustituir nada.
func TestElValorPorDefectoPreguntaALaComprobacionDeVerdad(t *testing.T) {
	llamada := 0
	conDep := violacion{motor: "inventado", requiere: "algo", presente: func(string) bool {
		llamada++
		return false // la dependencia NO está
	}}
	if !faltaLaDependencia(conDep, "/repo") {
		t.Error("con `presente` diciendo que la dependencia no está, faltaLaDependencia dijo que sí " +
			"está: el arnés daría por corrido un motor que no puede correr")
	}
	if llamada != 1 {
		t.Errorf("no se consultó la comprobación del motor (%d llamadas): el valor por defecto "+
			"está decidiendo por su cuenta", llamada)
	}

	conDep.presente = func(string) bool { return true } // la dependencia SÍ está
	if faltaLaDependencia(conDep, "/repo") {
		t.Error("con la dependencia presente, faltaLaDependencia dijo que falta: el arnés " +
			"absolvería como NO APLICA a un motor que sí podía correr")
	}

	// nil = sin dependencia externa. Nunca falta, y por eso un degradado suyo es
	// siempre una regresión.
	if faltaLaDependencia(violacion{motor: "gofmt"}, "/repo") {
		t.Error("un motor sin dependencia externa no puede tener una dependencia que falte")
	}
}
