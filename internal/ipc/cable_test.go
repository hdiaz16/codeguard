package ipc

// La huella tiene que sobrevivir al pipe.
//
// Esto se descubrió midiendo la ruta del daemon de extremo a extremo: la base
// guardaba hallazgos con la columna fingerprint vacía siempre que el orbe
// estaba arriba, o sea en el commit de todos los días. La causa era invisible
// leyendo el código de un lado o del otro: finding.Finding marca la huella como
// json:"-" —correcto para el informe— y el pipe usaba el mismo struct.
//
// Esta prueba es rápida y señala el sitio exacto; la de extremo a extremo
// (TestConDaemonYSinDaemonElVeredictoEsElMismo) demuestra que además el
// producto entero lo hace bien. Hacen falta las dos: ésta sola no vería que el
// daemon dejara de calcular la huella antes de mandarla.

import (
	"encoding/json"
	"strings"
	"testing"

	"codeguard/internal/finding"
)

func TestLaHuellaCruzaElPipe(t *testing.T) {
	f := finding.Finding{
		ID: "x1", Engine: "semgrep", RuleKey: "py.subprocess-shell-true",
		File: "app/inseguro.py", Line: 5, Message: "shell=True",
		LineContent: "    return subprocess.run(orden, shell=True)",
	}
	huella := f.ComputeFingerprint()
	if huella == "" {
		t.Fatal("el fixture no tiene huella: no hay nada que medir")
	}

	crudo, err := json.Marshal(Response{RunID: "r1", Findings: []finding.Finding{f}})
	if err != nil {
		t.Fatalf("no se pudo serializar: %v", err)
	}

	var vuelta Response
	if err := json.Unmarshal(crudo, &vuelta); err != nil {
		t.Fatalf("no se pudo deserializar: %v", err)
	}
	if len(vuelta.Findings) != 1 {
		t.Fatalf("cruzaron %d hallazgos y se mandó 1", len(vuelta.Findings))
	}

	if g := vuelta.Findings[0].Fingerprint; g != huella {
		t.Errorf("la huella NO sobrevivió al pipe: llegó %q y se mandó %q.\n"+
			"Sin ella, el gancho guarda el hallazgo con fingerprint vacío y deja de "+
			"poder correlacionarse entre corridas: es la clave de la baseline, de las "+
			"excepciones y de la calibración.", g, huella)
	}
	if g := vuelta.Findings[0].LineContent; g != f.LineContent {
		t.Errorf("el contenido de la línea no sobrevivió al pipe: %q.\n"+
			"Sin él, el otro lado ni siquiera puede recalcular la huella.", g)
	}

	// Y que lo demás siga entero: sustituir Findings en el sobre es justo el
	// tipo de cambio que se lleva por delante un campo vecino sin avisar.
	if vuelta.RunID != "r1" {
		t.Errorf("el run id se perdió por el camino: %q", vuelta.RunID)
	}
	if vuelta.Findings[0].RuleKey != f.RuleKey || vuelta.Findings[0].File != f.File {
		t.Errorf("los campos normales del hallazgo no llegaron enteros: %+v", vuelta.Findings[0])
	}
}

// El informe NO debe llevar el contenido de la línea señalada. El arreglo del
// pipe se hizo aquí y no cambiando el tag de finding.Finding precisamente para
// no filtrar código fuente a los artefactos que se suben al CI.
func TestElInformeSigueSinLlevarLaLinea(t *testing.T) {
	f := finding.Finding{
		ID: "x1", Engine: "semgrep", File: "a.py", Line: 1,
		LineContent: "token = 'sk-esto-no-debe-viajar-al-informe'",
	}
	crudo, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("no se pudo serializar el hallazgo suelto: %v", err)
	}
	if strings.Contains(string(crudo), "no-debe-viajar") {
		t.Errorf("finding.Finding volvió a serializar el contenido de la línea: %s\n"+
			"El informe y el SARIF viajan al CI; el código de la línea señalada no "+
			"tiene por qué ir en ellos.", crudo)
	}
}
