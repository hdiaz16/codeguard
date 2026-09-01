//go:build windows

package proc

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows/registry"
)

// La expansión de %VAR% del PATH del registro tiene que dar lo MISMO que da
// Windows al componer una sesión nueva, porque ese PATH es con el que se buscan
// todos los motores externos: si una entrada sale mal, el motor que vivía ahí
// deja de existir para nosotros.
//
// El fallo que motiva estas pruebas era traducir '%' por '$' y llamar a
// os.ExpandEnv. En el registro real de la máquina donde se detectó, eso
// convertía siete de las 32 entradas de HKLM en rutas inexistentes, entre ellas
// C:\WINDOWS$\system32.
func TestExpandirVariablesRespetaLaSintaxisDeWindows(t *testing.T) {
	t.Setenv("CG_TEST_H018", `C:\prueba`)
	// Los paréntesis son legales en un nombre de variable de Windows y los usa
	// la propia instalación (ProgramFiles(x86)).
	t.Setenv("CG_TEST_H018(x86)", `C:\prueba (x86)`)

	casos := []struct {
		nombre  string
		entrada string
		quiero  string
	}{
		{
			// El '%' de cierre no es un carácter más: cierra el par.
			nombre:  "varias variables en una lista",
			entrada: `%CG_TEST_H018%\engines;%CG_TEST_H018%\bin`,
			quiero:  `C:\prueba\engines;C:\prueba\bin`,
		},
		{
			nombre:  "nombre con paréntesis",
			entrada: `%CG_TEST_H018(x86)%\Common Files`,
			quiero:  `C:\prueba (x86)\Common Files`,
		},
		{
			// Windows deja el literal cuando la variable no existe; vaciarla
			// convertiría la entrada en una ruta relativa que apunta a otro sitio.
			nombre:  "variable indefinida se conserva literal",
			entrada: `%CG_NO_EXISTE_XYZ%\x`,
			quiero:  `%CG_NO_EXISTE_XYZ%\x`,
		},
		{
			nombre:  "sin variables no se toca nada",
			entrada: `C:\sin\variables\aqui`,
			quiero:  `C:\sin\variables\aqui`,
		},
		{
			// Un '%' sin pareja es un carácter normal en un nombre de directorio.
			nombre:  "porcentaje suelto",
			entrada: `C:\suelto%raro\bin`,
			quiero:  `C:\suelto%raro\bin`,
		},
	}

	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			got := expandirVariables(c.entrada)
			if got != c.quiero {
				t.Errorf("expandirVariables(%q)\n  devolvió %q\n  quería   %q", c.entrada, got, c.quiero)
			}
			// Aserción transversal: el '$' es de la sintaxis POSIX y no tiene
			// nada que hacer aquí. Si aparece uno que la entrada no traía, la
			// expansión volvió a ser textual.
			if !strings.Contains(c.entrada, "$") && strings.Contains(got, "$") {
				t.Errorf("expandirVariables(%q) incrustó un '$': %q", c.entrada, got)
			}
		})
	}
}

// La variable de una instalación de verdad, para que la prueba no viva sólo de
// variables inventadas por ella misma.
func TestExpandirVariablesConVariableRealDeWindows(t *testing.T) {
	got := expandirVariables(`%SystemRoot%\system32`)
	if strings.Contains(got, "%") || strings.Contains(got, "$") {
		t.Errorf("%%SystemRoot%%\\system32 se expandió a %q, que sigue teniendo sintaxis sin resolver", got)
	}
	if !strings.HasSuffix(strings.ToLower(got), `\system32`) {
		t.Errorf("%%SystemRoot%%\\system32 se expandió a %q, que no acaba en \\system32", got)
	}
}

func TestExpandirVariablesSirveTambienParaVariablesQueNoSonPath(t *testing.T) {
	t.Setenv("USERPROFILE", `C:\Users\prueba`)
	got := expandirVariables(`%USERPROFILE%\go`)
	if got != `C:\Users\prueba\go` {
		t.Fatalf("un GOPATH de REG_EXPAND_SZ quedó inutilizable: %q", got)
	}
}

// El PATH real de ESTA máquina no debe salir con caracteres que el registro no
// tenía. Es la misma comprobación que las de arriba pero sobre el dato de
// verdad, que es donde se vio el fallo.
func TestPathVigenteNoIncrustaDolares(t *testing.T) {
	crudo := crudoDeRegistroParaPrueba(t)
	if crudo == "" {
		t.Skip("no se pudo leer ningún Path del registro en esta máquina")
	}
	if strings.Contains(crudo, "$") {
		t.Skip("el PATH del registro de esta máquina ya trae '$' propios; la aserción no podría distinguirlos")
	}
	if got := pathVigente(); strings.Contains(got, "$") {
		t.Errorf("pathVigente() incrustó '$' en un PATH que no tenía ninguno:\n%s", got)
	}
}

// crudoDeRegistroParaPrueba concatena los Path de HKLM y HKCU SIN expandir.
func crudoDeRegistroParaPrueba(t *testing.T) string {
	t.Helper()
	var partes []string
	leer := func(root registry.Key, sub string) {
		k, err := registry.OpenKey(root, sub, registry.QUERY_VALUE)
		if err != nil {
			return
		}
		defer k.Close()
		if v, _, err := k.GetStringValue("Path"); err == nil && v != "" {
			partes = append(partes, v)
		}
	}
	leer(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`)
	leer(registry.CURRENT_USER, `Environment`)
	return strings.Join(partes, ";")
}
