//go:build !codeguard_demo

package main

import "github.com/wailsapp/wails/v3/pkg/application"

// N004 — la demo de estados no viaja en el producto instalado.
//
// QUÉ HACÍA. Una entrada del menú de la bandeja, «Demo de estados (12 s)», que
// recorría los seis estados del orbe con un set() cada dos segundos y cerraba
// con set("idle", "demo terminada").
//
// POR QUÉ NO PUEDE ESTAR EN PRODUCCIÓN. El orbe es un indicador de seguridad:
// todo su valor es que sea una función fiel del último análisis. La remediación
// del ✓ falso cerró una por una las rutas por las que podía afirmar algo que no
// era —el verde sobre un análisis omitido, el verde sobre un proyecto sin
// analizar, y las dos rutas que se contradecían—, y dejó orbStateFor como el
// único sitio donde se decide el color. Esta entrada lo saltaba entero: era la
// única forma de poner el orbe en CUALQUIER estado, en CUALQUIER momento, desde
// un menú de un build de producción.
//
// Y el daño estaba medido, no supuesto. Con un bloqueo real entrando a mitad, la
// secuencia emitida era [idle, working, blocked, pass, blocked, degraded,
// offline, idle]: el «pass» de la demo tapaba el bloqueo real de inmediato — el
// orbe diciendo «todo bien» con un secreto sin resolver. El contador de
// generación que arregló H006 no puede hacer nada, porque estos son set()
// legítimos y cada uno abre su propia generación. Y en un aspecto era peor que
// el H006 original: aquél necesitaba que el bloqueo cayera dentro de la ventana
// de 15 s de un pass; la demo garantiza el pisotón durante los 12 s enteros, y
// el set("idle") final dejaba la bandeja mintiendo hasta el siguiente análisis
// —sin límite de tiempo, que es lo más grave de todo.
//
// POR QUÉ NO SE ARREGLÓ EN VEZ DE QUITARSE. Se consideraron las otras dos
// salidas y las dos dejan la puerta entornada. Restaurar el estado anterior al
// terminar arregla el final pero no los 12 s de en medio, y encima añade una
// forma nueva de mentir: si durante la demo entra un bloqueo, restaurar la foto
// previa lo borra. Negarse a correr con un bloqueo activo deja fuera el bloqueo
// que llega DURANTE la demo —una carrera—, y además el bloqueo no es lo único
// que no se puede tapar: un estado degradado también es información que el
// usuario necesita. Sólo quitarla del producto cierra el agujero entero.
//
// QUÉ SE PIERDE, Y DÓNDE ESTÁ EL REEMPLAZO. Ver a qué se parece cada estado
// sigue siendo una necesidad legítima —de quien desarrolla el orbe, y de quien
// se lo explica a alguien—. Para lo primero está la etiqueta de compilación
// `codeguard_demo`, que devuelve la entrada al menú (ver demoestados_debug.go).
// Para lo segundo, el sitio correcto es la «Guía de uso», que ya está en el
// menú y puede enseñar una leyenda con los colores y su significado sin tocar el
// orbe real: además enseña mejor, porque la demo mostraba la paleta y no lo que
// cada color quiere decir.
//
// La compilación de la distribución (dist/build-dist.ps1) no pasa etiquetas, así
// que el producto instalado se queda sin la demo sin tener que acordarse de
// nada. Desactivado por defecto y a propósito.
func (e *escritorio) anadirDemoDeEstados(*application.Menu) {}

// demoDeEstadosCompilada dice si esta compilación lleva la demo. La prueba de al
// lado la mira para que nadie la reactive por descuido en el build normal.
const demoDeEstadosCompilada = false
