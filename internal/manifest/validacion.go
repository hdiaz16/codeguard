package manifest

import (
	"errors"
	"fmt"
	"strings"
)

// validarRutaRelativa rechaza toda ruta que pueda salirse del árbol del
// artefacto o nombrar algo distinto de lo aparente: absolutas, `..`, ADS de
// NTFS (`:`), y separadores no canónicos (el manifiesto habla en `/`).
func validarRutaRelativa(p string) error {
	if strings.TrimSpace(p) == "" {
		return errors.New("ruta vacía")
	}
	if strings.ContainsAny(p, ":") {
		return fmt.Errorf("ruta %q: absoluta o con ADS (contiene ':')", p)
	}
	if strings.Contains(p, "\\") {
		return fmt.Errorf("ruta %q: separador '\\' — el manifiesto usa '/'", p)
	}
	if strings.HasPrefix(p, "/") {
		return fmt.Errorf("ruta %q: absoluta", p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return fmt.Errorf("ruta %q: contiene '..'", p)
		}
		if seg == "" {
			return fmt.Errorf("ruta %q: segmento vacío", p)
		}
	}
	return nil
}

// esHex64Min exige 64 hex EN MINÚSCULAS: un SHA-256 con la misma grafía
// siempre, para que dos manifiestos del mismo árbol no difieran por el caso.
func esHex64Min(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
