// Fixture de semgrep --test — no es código del producto.
// Casos de prueba del pilar calidad (stem calidad-ext), lenguaje Go.
package fixtures

import (
	"os"
	"testing"
)

func registrarFallo(err error) {}

func calcularValor() error { return nil }

// --- go-close-sin-comprobar-en-escritura ------------------------------------
func escribirReporte(ruta string) error {
	// ruleid: go-close-sin-comprobar-en-escritura
	f, err := os.Create(ruta)
	if err != nil {
		return err
	}
	defer f.Close()
	f.WriteString("reporte")
	return nil
}

func escribirSeguro(ruta string) error {
	// ok: go-close-sin-comprobar-en-escritura
	f, err := os.Create(ruta)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			registrarFallo(cerr)
		}
	}()
	f.WriteString("reporte")
	return nil
}

func leerReporte(ruta string) error {
	// ok: go-close-sin-comprobar-en-escritura
	f, err := os.OpenFile(ruta, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return nil
}

// --- go-ignored-error-completo ----------------------------------------------
func descartarValor() {
	valor := calcularValor()
	// ruleid: go-ignored-error-completo
	_ = valor
	// ok: go-ignored-error-completo
	_ = os.MkdirAll("fixtures-tmp", 0o755)
}

// --- go-test-saltado ----------------------------------------------------------
func TestPendiente(t *testing.T) {
	// ruleid: go-test-saltado
	t.Skip("se cuelga en el runner de Windows")
}

func TestDocumentado(t *testing.T) {
	// ok: go-test-saltado
	t.Skip("CG-901: reactivar cuando el driver soporte contexto")
}

// --- parametros-excesivos-go --------------------------------------------------
// ruleid: parametros-excesivos-go
func crearEnvio(a string, b string, c int, d int, e bool, g bool) {
	registrarFallo(nil)
}

// ok: parametros-excesivos-go
func crearNota(a string, b string, c int) {
	registrarFallo(nil)
}
