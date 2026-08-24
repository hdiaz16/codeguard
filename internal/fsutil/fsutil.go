// Package fsutil junta las operaciones de filesystem que varios paquetes
// (registry, baseline, store) necesitan idénticas. Vive en un paquete
// neutral porque esas capas no deberían importarse entre sí por una
// utilidad de disco.
package fsutil

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// EscribirAtomico reemplaza path con data de forma atómica: escribe a un
// temporal EN EL MISMO DIRECTORIO y luego os.Rename.
func EscribirAtomico(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*.tmp")
	if err != nil {
		return err
	}
	nombre := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(nombre)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(nombre)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(nombre)
		return err
	}
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

// EstaDentroDe informa si ruta se resuelve dentro del directorio base.
// Canonicaliza ambas rutas resolviendo symlinks/junctions reales para
// impedir que un symlink en el repo escape a archivos sensibles fuera de la raíz.
func EstaDentroDe(base, ruta string) bool {
	if base == "" || ruta == "" {
		return false
	}
	if RechazarSintaxisPeligrosa(ruta) != nil {
		return false
	}

	absBase, err := filepath.Abs(base)
	if err != nil {
		return false
	}
	var absRuta string
	esAbsoluta := filepath.IsAbs(ruta) ||
		strings.HasPrefix(ruta, "/") ||
		strings.HasPrefix(ruta, "\\") ||
		(len(ruta) >= 2 && esLetraUnidad(ruta[0]) && ruta[1] == ':')

	if !esAbsoluta {
		absRuta = filepath.Join(absBase, ruta)
	} else {
		a, err := filepath.Abs(ruta)
		if err != nil {
			return false
		}
		absRuta = a
	}

	// Resolver symlinks reales si existen
	realBase, err := filepath.EvalSymlinks(absBase)
	if err == nil {
		absBase = realBase
	}
	realRuta, err := filepath.EvalSymlinks(absRuta)
	if err == nil {
		absRuta = realRuta
	} else {
		// Si el archivo no existe aún, resolver el padre existente más cercano
		if padreResuelto, errPadre := resolverPadreExistente(absRuta); errPadre == nil {
			absRuta = padreResuelto
		}
	}

	absBase = filepath.Clean(absBase)
	absRuta = filepath.Clean(absRuta)

	if runtime.GOOS == "windows" {
		absBase = strings.ToLower(absBase)
		absRuta = strings.ToLower(absRuta)
	}

	if absRuta == absBase {
		return true
	}
	rel, err := filepath.Rel(absBase, absRuta)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// RechazarSintaxisPeligrosa verifica que la ruta no contenga patrones de ataque
// (UNC, namespaces NT, caracteres NUL, Alternate Data Streams o nombres reservados).
func RechazarSintaxisPeligrosa(p string) error {
	if strings.ContainsRune(p, 0) {
		return os.ErrInvalid
	}

	inspeccion := strings.ReplaceAll(p, "/", `\`)

	// Rechazo de UNC o namespaces NT: \\, \\?\, \\.\, \??\, \Device\, GLOBALROOT
	if strings.HasPrefix(inspeccion, `\\`) ||
		strings.HasPrefix(inspeccion, `\??\`) ||
		strings.HasPrefix(inspeccion, `\Device\`) ||
		strings.Contains(inspeccion, `GLOBALROOT`) {
		return os.ErrInvalid
	}

	// Rechazo de Alternate Data Streams (colon en nombres de archivo de Windows)
	if idx := strings.Index(p, ":"); idx != -1 {
		if !(idx == 1 && esLetraUnidad(p[0])) {
			return os.ErrInvalid
		}
		if strings.Contains(p[idx+1:], ":") {
			return os.ErrInvalid
		}
	}

	// Dispositivos reservados de DOS (CON, PRN, AUX, NUL, COM1-9, LPT1-9)
	base := strings.ToUpper(filepath.Base(p))
	if i := strings.Index(base, "."); i != -1 {
		base = base[:i]
	}
	switch base {
	case "CON", "PRN", "AUX", "NUL",
		"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		return os.ErrInvalid
	}
	return nil
}

func esLetraUnidad(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func resolverPadreExistente(p string) (string, error) {
	restante := []string{}
	actual := p
	for i := 0; i < 64; i++ {
		resuelto, err := filepath.EvalSymlinks(actual)
		if err == nil {
			for j := len(restante) - 1; j >= 0; j-- {
				resuelto = filepath.Join(resuelto, restante[j])
			}
			return resuelto, nil
		}
		padre := filepath.Dir(actual)
		if padre == actual {
			break
		}
		restante = append(restante, filepath.Base(actual))
		actual = padre
	}
	return p, nil
}

// SanitizarRutas filtra rutas devolviendo únicamente las que se
// resuelven dentro de base, limpiadas con filepath.Clean y
// deduplicadas, preservando el orden de entrada.
func SanitizarRutas(base string, rutas []string) []string {
	vistas := make(map[string]struct{}, len(rutas))
	salida := make([]string, 0, len(rutas))
	for _, r := range rutas {
		if r == "" {
			continue
		}
		if RechazarSintaxisPeligrosa(r) != nil {
			continue
		}
		limpia := filepath.Clean(r)
		if !EstaDentroDe(base, limpia) {
			continue
		}
		if _, dup := vistas[limpia]; dup {
			continue
		}
		vistas[limpia] = struct{}{}
		salida = append(salida, limpia)
	}
	return salida
}

// ComoArgumentosCLI prefija el separador "--" a una lista de rutas
// para pasarlas de forma segura a herramientas CLI.
func ComoArgumentosCLI(rutas []string) []string {
	args := make([]string, 0, len(rutas)+1)
	args = append(args, "--")
	return append(args, rutas...)
}
