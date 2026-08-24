//go:build windows

package proc

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// pathVigente devuelve el PATH compuesto por las rutas de CodeGuard (%LOCALAPPDATA%\CodeGuard\bin
// y engines) y lo que esté configurado en el sistema, asegurando resolución de motores
// sin depender de escrituras en el registro.
func pathVigente() string {
	var partes []string

	if localAppData := os.Getenv("LOCALAPPDATA"); localAppData != "" {
		partes = append(partes,
			filepath.Join(localAppData, "CodeGuard", "bin"),
			filepath.Join(localAppData, "CodeGuard", "engines"),
		)
	}

	// El de máquina primero y el de usuario después es el orden en que Windows
	// los compone al crear una sesión nueva (solo lectura).
	if p := leerPath(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Session Manager\Environment`); p != "" {
		partes = append(partes, p)
	}
	if p := leerPath(registry.CURRENT_USER, `Environment`); p != "" {
		partes = append(partes, p)
	}
	if len(partes) == 0 {
		return ""
	}
	return strings.Join(partes, ";")
}

// leerPath devuelve el valor Path de una clave de entorno del registro, ya
// expandido, o "" si la clave no existe, no tiene Path o lo tiene vacío.
//
// Es una sola copia a propósito: la lectura de máquina y la de usuario eran dos
// bloques calcados, y el fallo de expansión estaba en los dos. Con una copia,
// arreglarlo una vez lo arregla en todas partes.
func leerPath(root registry.Key, subclave string) string {
	k, err := registry.OpenKey(root, subclave, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue("Path")
	if err != nil || v == "" {
		return ""
	}
	return expandirVariables(v)
}

// expandirVariables resuelve los %VAR% de un valor del registro con la misma
// API que usa Windows al componer el entorno de una sesión nueva.
//
// No sirve os.ExpandEnv traduciendo '%' por '$': la sintaxis no es la misma ni
// se puede convertir carácter a carácter. El '%' DELIMITA un par (abre y cierra
// el nombre) mientras que el '$' sólo PREFIJA, así que el '%' de cierre se
// queda como un '$' huérfano dentro de la ruta — %SystemRoot%\system32 salía
// como C:\WINDOWS$\system32, que no existe. Además os.ExpandEnv sólo admite
// nombres [A-Za-z0-9_] y trunca los que Windows sí permite, como
// ProgramFiles(x86), y vacía las variables indefinidas donde Windows deja el
// literal (una entrada vacía se vuelve una ruta relativa que apunta a otro
// sitio).
//
// Si la API falla se devuelve el valor CRUDO, nunca uno a medio expandir: un
// %VAR% sin resolver deja inservible esa entrada del PATH, pero las demás —que
// son rutas literales y la mayoría— siguen valiendo. Descartar el valor entero
// nos dejaría sin el PATH de máquina, que es justo lo que esto viene a arreglar.
func expandirVariables(v string) string {
	expandido, err := registry.ExpandString(v)
	if err != nil {
		return v
	}
	return expandido
}

// variablesDeUsuario devuelve las variables de HKCU\Environment tal como están
// AHORA, sin PATH (de eso se encarga pathVigente, que sabe componerlo con el de
// máquina en el orden correcto).
func variablesDeUsuario() map[string]string {
	out := map[string]string{}
	k, err := registry.OpenKey(registry.CURRENT_USER, `Environment`, registry.QUERY_VALUE)
	if err != nil {
		return out
	}
	defer k.Close()
	nombres, err := k.ReadValueNames(0)
	if err != nil {
		return out
	}
	for _, n := range nombres {
		if strings.EqualFold(n, "Path") {
			continue
		}
		v, _, err := k.GetStringValue(n)
		if err != nil || v == "" {
			continue
		}
		out[n] = v
	}
	return out
}
