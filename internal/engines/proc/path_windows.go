//go:build windows

package proc

import (
	"os"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// pathVigente devuelve el PATH tal como está AHORA en el registro de Windows,
// no el que heredó este proceso.
//
// El instalador añade %LOCALAPPDATA%\CodeGuard\engines y el directorio de
// scripts de Python al PATH del usuario, pero un proceso que ya estaba
// corriendo conserva su copia: la terminal que tenías abierta, el editor, el
// cliente gráfico de git. Desde ahí los motores no existen.
//
// Y no degrada por igual: la compuerta de secretos es fail-closed, así que la
// falta de gitleaks BLOQUEA el commit diciendo que hay que instalarlo — cuando
// está instalado, a un directorio de distancia. Pasó al commitear en bds.portal
// después de reinstalar el agente. El aviso del instalador ("abre una terminal
// nueva para heredar el PATH") no basta: nadie reinicia VS Code por eso.
//
// Devuelve "" si no se puede leer el registro, y entonces manda el heredado.
func pathVigente() string {
	var partes []string

	// El de máquina primero y el de usuario después es el orden en que Windows
	// los compone al crear una sesión nueva.
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Session Manager\Environment`, registry.QUERY_VALUE); err == nil {
		if v, _, err := k.GetStringValue("Path"); err == nil && v != "" {
			partes = append(partes, os.ExpandEnv(strings.ReplaceAll(v, "%", "$")))
		}
		k.Close()
	}
	if k, err := registry.OpenKey(registry.CURRENT_USER, `Environment`, registry.QUERY_VALUE); err == nil {
		if v, _, err := k.GetStringValue("Path"); err == nil && v != "" {
			partes = append(partes, os.ExpandEnv(strings.ReplaceAll(v, "%", "$")))
		}
		k.Close()
	}
	if len(partes) == 0 {
		return ""
	}
	return strings.Join(partes, ";")
}
