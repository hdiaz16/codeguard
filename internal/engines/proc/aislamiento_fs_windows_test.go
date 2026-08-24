//go:build windows

package proc

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// La PRUEBA DETERMINISTA del límite del piso de W4 (t.116, condición de Kimi:
// demostrar que HOY el hueco existe, no fingir que se cerró). El token
// restringido quita privilegios pero NO restringe el sistema de archivos
// (contener_windows.go:31-34, dicho): un motor —o la config ejecutable que un
// repo hostil trae— corre con acceso de lectura/escritura fuera del árbol del
// repo. Este test lo demuestra sin depender de eslint/mypy/dotnet: un hijo
// bajo contención COMPLETA escribe un archivo FUERA de su "repo" y lo logra.
//
// Es la deuda que el spike AppContainer (tanda e) o el interruptor de
// confianza de la Q3 (decisión de Héctor) deben cerrar. Mientras exista, este
// test PASA describiéndola; el día que el aislamiento fuerte la cierre, este
// test se convierte en su regresión (habrá que invertir la aserción y decir
// por qué). Un fixture que se volviera verde en silencio al cerrarse el hueco
// sería el mismo verde silencioso que W4 combate — por eso se deja escrito
// qué significa cada resultado.
func TestElTokenNoRestringeElSistemaDeArchivos(t *testing.T) {
	repo := t.TempDir()  // el "árbol del repo": lo único que el motor debería tocar
	fuera := t.TempDir() // territorio de otro: HERMANO del repo, fuera de su árbol
	vida := filepath.Join(fuera, "escrito-desde-dentro.txt")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Un hijo con cwd DENTRO del repo que escribe FUERA — exactamente lo que
	// hace un eslint.config.js o un target de MSBuild hostil.
	ectx, rec := ConRecolector(ctx)
	c := exec.CommandContext(ectx, "cmd", "/c", "echo tocado> "+vida)
	c.Dir = repo
	c.Env = EntornoDePerfil(PerfilBasico)
	if _, err := Correr(ectx, c, 1<<20); err != nil {
		t.Fatalf("el hijo no corrió: %v", err)
	}

	// La contención estuvo COMPLETA (token + job + matarile + UI): esto no es
	// un sandbox caído, es el sandbox funcionando como está diseñado.
	rep, hubo := rec.Resultado()
	if !hubo || !rep.Completa() {
		t.Fatalf("la contención debía estar completa para que la demostración valga: %+v", rep)
	}

	if _, err := os.Stat(vida); err == nil {
		t.Logf("MEDIDO (deuda del piso de W4): un hijo bajo contención COMPLETA escribió "+
			"fuera del árbol del repo (%s). El token restringido no limita el filesystem; "+
			"esto lo cierra el aislamiento fuerte (spike AppContainer, tanda e) o el "+
			"interruptor de confianza de la Q3. La config ejecutable de un repo hostil "+
			"tiene este mismo alcance.", vida)
	} else {
		t.Fatalf("el hijo NO pudo escribir fuera del repo: si el aislamiento fuerte cerró "+
			"este hueco, INVIERTE la aserción de este test y documenta el mecanismo — no lo "+
			"dejes pasar en verde silencioso (err=%v)", err)
	}
}
