// Package fsutil junta las operaciones de filesystem que varios paquetes
// (registry, baseline, store) necesitan idénticas. Vive en un paquete
// neutral porque esas capas no deberían importarse entre sí por una
// utilidad de disco.
package fsutil

import (
	"os"
	"path/filepath"
)

// EscribirAtomico reemplaza path con data de forma atómica: escribe a un
// temporal EN EL MISMO DIRECTORIO y luego os.Rename.
//
// Un os.WriteFile directo NO es atómico: trunca el destino antes de
// escribir, y si el proceso muere a media escritura (crash, corte de luz,
// OOM) el archivo queda truncado o corrupto. Para un archivo de estado
// —registro de repos, baseline— eso es perder datos sin avisar. Con
// temp+rename el destino siempre es la versión vieja completa o la nueva
// completa; nunca una mezcla.
//
// El temporal se crea en el mismo directorio que el destino porque
// os.Rename sólo es atómico dentro del mismo filesystem: un temp en
// %TEMP% podría estar en otra unidad y el rename cruzaría filesystems
// (falla o degrada a copia, según el SO).
//
// Matiz Windows: os.Rename reemplaza un destino existente (Go usa
// MoveFileEx con MOVEFILE_REPLACE_EXISTING desde hace muchas versiones),
// así que el patrón funciona igual que en POSIX. Lo que Windows NO
// permite es reemplazar un archivo que otro proceso tiene abierto sin
// FILE_SHARE_DELETE (sharing violation); los archivos de estado de este
// repo se leen con os.ReadFile —que cierra al instante— y no se mantienen
// abiertos durante la escritura, así que no aplica.
func EscribirAtomico(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*.tmp")
	if err != nil {
		return err
	}
	nombre := tmp.Name()
	// Cualquier paso que falle borra el temporal antes de salir: nada de
	// basura .tmp huérfana junto al archivo de estado.
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(nombre)
		return err
	}
	// Sync antes de cerrar: sin él, un corte de luz justo tras el rename
	// puede dejar el nombre nuevo apuntando a datos que nunca llegaron al
	// disco.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(nombre)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(nombre)
		return err
	}
	// CreateTemp crea con 0600; se ajusta al permiso pedido.
	if err := os.Chmod(nombre, perm); err != nil {
		os.Remove(nombre)
		return err
	}
	if err := os.Rename(nombre, path); err != nil {
		os.Remove(nombre)
		return err
	}
	return nil
}
