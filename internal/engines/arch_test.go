package engines

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// Todo proceso de MOTOR pasa por proc.Correr (W4, t.110/115, unánime): es el
// único camino con token restringido, job object, matarile de árbol por plazo
// y reporte de contención. Un exec directo fuera de él es un hijo sin armadura
// Y sin fail-visible — la clase exacta de warmup_repos.go:91 (npx tsc dentro
// del repo en cada arranque del daemon), que murió en esta misma tanda.
//
// La lista blanca es pequeña y cada entrada tiene dueño y razón; añadir una
// exige escribir POR QUÉ ese hijo no necesita la armadura. La misma doctrina
// que el arch-test de ComputeFingerprint.
var ejecucionesPermitidas = map[string]string{
	"identidad/arranque.go": "sonda de versión (--version/-jar) sobre binarios YA verificados por hash, " +
		"sin tocar contenido del repo analizado; dueño: internal/engines/identidad",
}

// La vía LIBRE de entorno (proc.Entorno sin perfil) queda prohibida en los
// motores (veto de GPT t.115: cualquier adaptador reintroducía la variable
// que quisiera). Los motores declaran su perfil: EntornoDePerfil en su sitio
// o la tabla perfilPorBin del runner genérico.
var entornosLibresPermitidos = map[string]string{
	"contrato/contrato.go": "medición de contratos: reproduce el entorno histórico con el que se " +
		"midieron los códigos de salida; no es un camino de análisis; dueño: internal/engines/contrato",
}

func TestNingunMotorArmaEntornoSinPerfil(t *testing.T) {
	_, este, _, _ := runtime.Caller(0)
	raiz := filepath.Dir(este)
	patron := regexp.MustCompile(`proc\.Entorno\(`)

	err := filepath.WalkDir(raiz, func(ruta string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "proc" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(ruta, ".go") || strings.HasSuffix(ruta, "_test.go") {
			return nil
		}
		rel := filepath.ToSlash(strings.TrimPrefix(strings.TrimPrefix(ruta, raiz), string(os.PathSeparator)))
		raw, err := os.ReadFile(ruta)
		if err != nil {
			return err
		}
		if !patron.Match(raw) {
			return nil
		}
		if razon, ok := entornosLibresPermitidos[rel]; ok {
			t.Logf("permitido: %s — %s", rel, razon)
			return nil
		}
		t.Errorf("%s arma entorno con proc.Entorno() libre. Declara el perfil del motor "+
			"(proc.EntornoDePerfil o la tabla perfilPorBin) o añádelo a entornosLibresPermitidos con dueño y razón", rel)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestNingunMotorEjecutaFueraDeProcCorrer(t *testing.T) {
	_, este, _, _ := runtime.Caller(0)
	raiz := filepath.Dir(este) // internal/engines

	// Lo que delata una ejecución directa: consumir el *exec.Cmd sin pasar por
	// proc.Correr. Crear el comando (exec.CommandContext) es legítimo — correr
	// es lo vigilado.
	patron := regexp.MustCompile(`\.(Run|Start|Output|CombinedOutput)\(\)`)

	err := filepath.WalkDir(raiz, func(ruta string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// proc ES el runner aprobado; sus tests miden justo estas llamadas.
			if d.Name() == "proc" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(ruta, ".go") || strings.HasSuffix(ruta, "_test.go") {
			return nil
		}
		rel := filepath.ToSlash(strings.TrimPrefix(strings.TrimPrefix(ruta, raiz), string(os.PathSeparator)))
		raw, err := os.ReadFile(ruta)
		if err != nil {
			return err
		}
		// Solo interesan los archivos que manejan exec.Cmd: en los demás,
		// .Run() es el Run de la interfaz Engine y no una ejecución.
		if !strings.Contains(string(raw), "os/exec") {
			return nil
		}
		if !patron.Match(raw) {
			return nil
		}
		if razon, ok := ejecucionesPermitidas[rel]; ok {
			t.Logf("permitido: %s — %s", rel, razon)
			return nil
		}
		t.Errorf("%s ejecuta un proceso sin pasar por proc.Correr (sin token, sin job, sin reporte "+
			"de contención). Pásalo por proc.Correr o añádelo a ejecucionesPermitidas con dueño y razón", rel)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
