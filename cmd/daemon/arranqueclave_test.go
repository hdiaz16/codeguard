//go:build windows

package main

import (
	"errors"
	"os"
	"strings"
	"testing"

	"codeguard/internal/engines/proc"
	"codeguard/internal/llm"
	"codeguard/internal/secreto"
)

const varPruebaArranque = "CODEGUARD_H003_ARRANQUE"

// enElEntornoDelProceso dice si la variable viaja en os.Environ(), que es
// literalmente lo que recibe un hijo lanzado sin cmd.Env. os.Getenv por sí solo
// no basta como comprobación: son la misma fuente, pero el hijo hereda la LISTA.
func enElEntornoDelProceso(nombre string) (string, bool) {
	for _, e := range os.Environ() {
		if n, v, _ := strings.Cut(e, "="); n == nombre {
			return v, true
		}
	}
	return "", false
}

// El camino de la MIGRACIÓN AUTOMÁTICA, en el orden exacto del arranque del
// daemon (main.go:216 refresca el entorno, main.go:228 migra).
//
// Aquí estaba el agujero de verdad, y no lo cubría ninguna prueba:
// RefrescarVariables mete la clave del registro en el entorno de ESTE proceso e
// inmediatamente después MigrarClaveDelEntorno la guardaba en la bóveda y la
// borraba del registro, pero nunca la sacaba del proceso. El daemon se quedaba
// con la clave en os.Environ() y la heredaban trivy, tsc y git.
//
// No hace falta que el usuario toque nada: es lo que pasa en CADA arranque de
// una instalación que venga de la versión anterior, o de cualquier instalación
// hecha con `install.ps1 -ApiKey`.
func TestElArranqueDelDaemonNoDejaLaClaveEnElEntorno(t *testing.T) {
	const valor = "clave-que-no-debe-sobrevivir-al-arranque"
	t.Cleanup(func() {
		_ = secreto.Borrar(varPruebaArranque)
		_ = borrarVariableUsuario(varPruebaArranque)
		_ = os.Unsetenv(varPruebaArranque)
	})
	_ = secreto.Borrar(varPruebaArranque)
	_ = os.Unsetenv(varPruebaArranque)
	ponerEnElEntornoDelUsuario(t, varPruebaArranque, valor)

	// El orden de main.go, tal cual.
	proc.RefrescarVariables()
	MigrarClaveDelEntorno(varPruebaArranque)

	// La migración tiene que haber hecho su trabajo...
	if got, err := secreto.Leer(varPruebaArranque); err != nil || got != valor {
		t.Fatalf("la clave no llegó a la bóveda: %q, %v", got, err)
	}
	if v := leerDelEntornoDelUsuario(t, varPruebaArranque); v != "" {
		t.Errorf("la copia del registro sigue ahí: %q", v)
	}
	// ...y no puede dejar la clave dentro del daemon.
	if v := os.Getenv(varPruebaArranque); v != "" {
		t.Errorf("el daemon se quedó con la clave en su entorno (%q): la heredaría "+
			"cualquier hijo lanzado sin cmd.Env (trivy y tsc en warmup.go, git en "+
			"gitdiff.go)", v)
	}
	if v, ok := enElEntornoDelProceso(varPruebaArranque); ok {
		t.Errorf("la clave viaja en os.Environ() (%q): es lo que recibe un "+
			"exec.Command sin cmd.Env", v)
	}
}

// La migración también tiene que desenganchar el proceso cuando el borrado del
// registro falla.
//
// Antes esta rama hacía `return` antes de tocar nada más, así que el peor
// escenario posible —registro que no se deja limpiar— era además el que dejaba
// la clave dentro del daemon.
func TestLaMigracionLimpiaElProcesoAunqueElRegistroFalle(t *testing.T) {
	const valor = "clave-que-el-registro-no-suelta"
	t.Cleanup(func() {
		_ = secreto.Borrar(varPruebaArranque)
		_ = borrarVariableUsuario(varPruebaArranque)
		_ = os.Unsetenv(varPruebaArranque)
	})
	_ = secreto.Borrar(varPruebaArranque)
	ponerEnElEntornoDelUsuario(t, varPruebaArranque, valor)
	proc.RefrescarVariables() // la clave entra al proceso, como en el arranque real
	sustituirBoveda(t, nil, func(string) error { return errors.New("registro de sólo lectura") })

	MigrarClaveDelEntorno(varPruebaArranque)

	if got, err := secreto.Leer(varPruebaArranque); err != nil || got != valor {
		t.Fatalf("la clave no llegó a la bóveda: %q, %v", got, err)
	}
	if v, ok := enElEntornoDelProceso(varPruebaArranque); ok {
		t.Errorf("la clave se quedó en el daemon (%q) por un fallo al borrar el "+
			"registro, que es otra cosa", v)
	}
}

// El alcance del barrido del arranque: qué variables se revisan.
//
// Se comprueba esta parte y no migrarClaveSiHaceFalta entera a propósito. Para
// ejercitarla de verdad haría falta usar la variable REAL del usuario
// (FOUNDRY_API_KEY), borrándola de la bóveda y restaurándola al final; si esa
// prueba muere a medias —un Ctrl-C, un timeout— deja a quien la corrió sin su
// clave. El trabajo por variable ya lo cubre la prueba de arriba.
func TestElArranqueRevisaTodosLosProveedoresSinRepetir(t *testing.T) {
	nombres := clavesAMigrar()
	if len(nombres) == 0 {
		t.Fatal("no revisaría ninguna variable: ninguna clave se migraría jamás")
	}

	vistas := map[string]bool{}
	for _, n := range nombres {
		if n == "" {
			t.Error("un nombre vacío: MigrarClaveDelEntorno lo descarta, pero no debería llegar")
		}
		if vistas[n] {
			t.Errorf("%s se revisa dos veces", n)
		}
		vistas[n] = true
	}

	// Cambiar de proveedor no borra la clave del anterior, así que el barrido
	// tiene que cubrir los conocidos y no sólo el activo: quien probó Azure y se
	// pasó a Anthropic tiene dos claves, y la que dejó de usar es justo la que
	// nadie va a volver a tocar.
	for _, p := range llm.Proveedores {
		if p.VarEntorno != "" && !vistas[p.VarEntorno] {
			t.Errorf("%s (%s) se quedaría sin migrar", p.VarEntorno, p.ID)
		}
	}
}
