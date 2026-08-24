package instalacion

import (
	"path/filepath"
	"testing"
)

// Esta función es el único sitio donde se impone el invariante, así que se
// prueba aquí y no sólo a través de quien la llama: si mañana alguien quita el
// envoltorio de linters o el de cmd/codeguard, la garantía tiene que seguir
// teniendo dueño y prueba.
//
// Lo que se garantiza: o una ruta ABSOLUTA, o "". Nunca una relativa, porque
// una relativa apunta al directorio de trabajo —el repo que se analiza— y de
// ese directorio sale un binario que se ejecuta.
func TestDirMotoresEsAbsolutaOEsNada(t *testing.T) {
	casos := []struct {
		nombre       string
		localappdata string
		quieroVacio  bool
	}{
		{"variable ausente", "", true},
		{"variable en blanco", "   ", true},
		{"valor relativo puesto a mano", `datos\local`, true},
		{"valor relativo con punto", `.`, true},
		{"valor absoluto normal", t.TempDir(), false},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			t.Setenv("LOCALAPPDATA", c.localappdata)
			got := DirMotores()
			if c.quieroVacio {
				if got != "" {
					t.Errorf("LOCALAPPDATA=%q debía dar \"\" y dio %q", c.localappdata, got)
				}
				return
			}
			if !filepath.IsAbs(got) {
				t.Errorf("LOCALAPPDATA=%q dio una ruta relativa: %q", c.localappdata, got)
			}
			if filepath.Base(got) != "engines" {
				t.Errorf("el directorio de motores cambió de sitio: %q", got)
			}
		})
	}
}
