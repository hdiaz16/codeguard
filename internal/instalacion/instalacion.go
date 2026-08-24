// Package instalacion sabe dónde deja las cosas el instalador de CodeGuard.
package instalacion

import (
	"os"
	"path/filepath"
)

// DirMotores es el directorio donde el instalador deja los motores
// descargables: los .exe (gitleaks, trivy) y los .jar y directorios de las
// herramientas de Java, que no se resuelven por PATH.
//
// Devuelve "" si no puede resolver una ruta ABSOLUTA. "" significa que NO HAY
// directorio de motores, y quien pregunte tiene que tratarlo como "no están
// instalados" — jamás buscar en otro sitio.
//
// El motivo es un agujero de ejecución de código. filepath.Join no falla cuando
// LOCALAPPDATA viene vacía: devuelve `CodeGuard\engines`, que es RELATIVA al
// directorio de trabajo, y el directorio de trabajo durante un commit es el
// repositorio que se está analizando. Como la búsqueda de herramientas Java
// hace un Glob ahí y se queda con la VERSIÓN MÁS ALTA, a un repo hostil le
// bastaba con traer `CodeGuard\engines\google-java-format-99.0.0-all-deps.jar`
// en su árbol para que acabara en `java -jar` al analizarlo. Con PMD es peor:
// entra el directorio entero en el classpath.
//
// Y LOCALAPPDATA puede faltar en Windows por causas de todos los días: cuenta
// de servicio, proceso lanzado con un bloque de entorno acotado — este mismo
// repo filtra por lista blanca el entorno con el que corre los motores.
//
// Vive en un paquete propio, y no como dos funciones iguales, porque hacían
// falta en internal/engines/linters y en cmd/codeguard, internal/ no puede
// importar cmd/, y las dos copias tenían el mismo fallo. Una sola copia es lo
// que impide que el arreglo se quede a medias.
func DirMotores() string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		return ""
	}
	dir := filepath.Join(base, "CodeGuard", "engines")
	// La comprobación no sobra aunque la variable tenga valor: puede traer algo
	// que no sea una ruta absoluta. Lo que no puede salir de aquí es relativo.
	if !filepath.IsAbs(dir) {
		return ""
	}
	return dir
}
