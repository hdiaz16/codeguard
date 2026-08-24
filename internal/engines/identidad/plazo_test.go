package identidad

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"codeguard/internal/instalacion"
)

// Un motor que TARDA no es un motor que NO ARRANCA.
//
// La diferencia no es de matiz: lo primero es una máquina cargada y se arregla
// sola; lo segundo es una acusación contra el artefacto que el panel le va a
// enseñar al desarrollador ("instala un JDK más nuevo") y que no puede
// comprobar mirando. Decirlo cuando no es verdad es la mentira cara.
//
// El código YA quería distinguirlas —la guarda del *exec.ExitError dice
// exactamente eso— y en Windows no lo conseguía: al vencer el plazo, exec mata
// el proceso y Wait devuelve "exit status 1", que ES un ExitError. Medido:
// ctx.Err()="context deadline exceeded", err="exit status 1", errors.As=true,
// salida vacía. El resultado era "no arranca en esta máquina: " con el motivo en
// blanco, sobre un PMD sano. Se veía en la práctica: llamando a Verificar en
// bucle, pmd salía "no-arranca" de forma intermitente aunque en 12 intentos
// sueltos no falle ni uno.
func TestUnMotorQueTardaNoSeAcusaDeNoArrancar(t *testing.T) {
	// La regresión que se mide aquí es específica de exec en Windows: al vencer
	// el plazo, Wait devuelve "exit status 1", que ES un ExitError. Fuera de
	// Windows el skip era implícito —no existe pmd.bat— y con un mensaje que
	// apuntaba a PMD en vez de al sistema: la restricción de plataforma queda
	// dicha, en vez de disfrazada de «falta una herramienta».
	if runtime.GOOS != "windows" {
		t.Skip("la regresión medida es específica de exec en Windows; " +
			"la distinción plazo-agotado vs no-arranca no tiene cobertura fuera de él")
	}

	pmd := filepath.Join(instalacion.DirMotores(), "pmd-bin-7.26.0")
	if _, err := os.Stat(filepath.Join(pmd, "bin", "pmd.bat")); err != nil {
		t.Skip("sin PMD instalado no hay nada que medir")
	}

	// Control: con el plazo de verdad, PMD arranca y no se le acusa de nada.
	if motivo := noArranca(pmd); motivo != "" {
		t.Fatalf("control: PMD arranca en esta máquina y salió acusado: %q", motivo)
	}

	// Y ahora un plazo imposible: la JVM no llega ni a empezar.
	//
	// OJO: esto muta la global plazoArranque, que noArranca lee sin
	// sincronización. Mientras el plazo sea una global y no un parámetro, NINGÚN
	// test de este paquete puede usar t.Parallel(): la carrera sería sobre el
	// plazo y el fallo saldría intermitente en otro test que no tiene la culpa.
	// Si algún día se paraleliza, primero hay que pasar el plazo por parámetro.
	original := plazoArranque
	plazoArranque = 120 * time.Millisecond
	t.Cleanup(func() { plazoArranque = original })

	if motivo := noArranca(pmd); motivo != "" {
		t.Errorf("se agotó el plazo y se acusó al motor de no arrancar: %q\n"+
			"Un plazo agotado habla de la máquina, no del artefacto, y esa frase "+
			"llega al panel como «instala un JDK más nuevo» sobre un motor sano.", motivo)
	}
}
