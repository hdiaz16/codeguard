package identidad

import (
	"context"
	"os/exec"

	"codeguard/internal/engines/proc"
)

// comandoIdentidad arma TODOS los hijos que lanza este paquete. Es el único
// sitio donde se llama a exec, y TestNingunHijoDeIdentidadSeArmaAMano es lo que
// lo mantiene así.
//
// Existe por dos razones que hasta ahora no coincidían en el tiempo y ahora sí.
//
//  1. LA VENTANA. Este paquete comprueba que un motor ARRANCA, y para eso lanza
//     `java -jar …` y el `pmd.bat` de PMD. Mientras sólo lo llamaba la CLI no se
//     notaba: la CLI es una aplicación de consola y el hijo hereda la suya. El
//     daemon NO tiene consola (se compila con -H windowsgui), y Windows le
//     REGALA una nueva y visible a cada ejecutable de consola que lance. Medido
//     con un padre sin consola y un hijo que reporta GetConsoleWindow: sin
//     atributos hwnd≠0 e IsWindowVisible=1; con ellos, ni ventana. Y pmd.bat es
//     peor que java: un .bat arranca por COMSPEC, así que la ventana la abre
//     cmd.exe aunque el .bat no imprima nada.
//
//     Deja de ser hipotético en cuanto el daemon importe este paquete, que es lo
//     que va a pasar: identidad es la ÚNICA fuente que distingue "instalado" de
//     "instalado pero no arranca" (el jar de google-java-format con un JDK 17),
//     y el panel necesita ese dato para no prometer una capa que no puede
//     correr. Sin esto, la comprobación abre una ventana negra por motor JVM.
//
//  2. EL ENTORNO. El daemon guarda la API key del modelo en el suyo, y un hijo
//     sin cmd.Env hereda os.Environ() ENTERO. Comprobar que un jar de terceros
//     arranca no es motivo para enseñarle la clave. auditoria.go ya acotaba el
//     entorno de su trivy (proc.Entorno) y arranque.go no: el mismo paquete con
//     dos criterios, que es como se cuela la tercera invocación.
//
// Acotar el entorno es seguro para lo que se lanza aquí, comprobado contra la
// lista de permitidas y medido: JAVA_HOME, PATH, PATHEXT y COMSPEC están todas
// dentro, y son las que java y el .bat necesitan para resolverse. El veredicto
// de Verificar no cambia — sigue diciendo "no arranca" del google-java-format
// con JDK 17, que es el dato del que va a colgar el panel.
func comandoIdentidad(ctx context.Context, nombre string, args ...string) *exec.Cmd {
	c := exec.CommandContext(ctx, nombre, args...)
	proc.SinVentana(c)
	c.Env = proc.EntornoDePerfil(proc.PerfilJava) // sondas de version; la de java necesita JAVA_HOME
	return c
}
