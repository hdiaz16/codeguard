package finding

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// LA REGLA ARQUITECTÓNICA de las huellas v2 (turno 83, defecto 5): la
// identidad se calcula SOLO en este paquete. Hubo 36 llamadores de
// ComputeFingerprint repartidos por los parsers y 5 copias del re-cálculo en
// los cachés — y la regla de ambigüedad es imposible de aplicar por partes.
// Este test es el que impide que aparezca el llamador 37: quien necesite una
// huella pide una asignación colectiva (AsignarHuellas), no un cálculo local.
//
// Va por texto y no por go/types a conciencia: lo que se prohíbe es el NOMBRE
// — cualquier `X.ComputeFingerprint(` fuera de aquí y de los _test (los tests
// lo usan como ORÁCULO de la v1 para verificar la legacy, y eso es legítimo
// hasta que la ventana dual muera).
func TestNadieCalculaHuellasFueraDeEstePaquete(t *testing.T) {
	raiz := filepath.Join("..", "..")
	var violaciones []string
	err := filepath.WalkDir(raiz, func(ruta string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", "tools", "frontend", "sitio":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		rel := filepath.ToSlash(ruta)
		if strings.Contains(rel, "internal/finding/") {
			return nil
		}
		raw, err := os.ReadFile(ruta)
		if err != nil {
			return err
		}
		for i, linea := range strings.Split(string(raw), "\n") {
			// Los comentarios pueden nombrarlo (historia, porqués); el CÓDIGO no.
			sinComentario := linea
			if idx := strings.Index(linea, "//"); idx >= 0 {
				sinComentario = linea[:idx]
			}
			if strings.Contains(sinComentario, ".ComputeFingerprint(") {
				violaciones = append(violaciones, rel+":"+itoa(i+1))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(violaciones) > 0 {
		t.Errorf("la identidad se asigna SOLO con finding.AsignarHuellas (colectiva, con "+
			"regla de ambigüedad); estos sitios volvieron a calcular por su cuenta:\n  %s",
			strings.Join(violaciones, "\n  "))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
