//go:build windows

package main

import (
	"strings"
	"testing"
)

// DOS DAEMONS VIVOS, DOS ORBES SUPERPUESTOS, Y EL DE ENCIMA ERA EL SORDO.
//
// Medido el 2026-08-26 en la máquina de Héctor: dos procesos lanzados por
// Explorer al iniciar sesión (residuo en HKCU\...\Run + acceso directo de
// Inicio), dos ventanas «CodeGuard estado» visibles en el MISMO rectángulo, y
// el segundo proceso —el que no consiguió el pipe— seguía vivo pintando un
// orbe que no recibe nada. La queja del usuario fue «no veo el orbe
// inicializarse»: veía el muerto.
func TestElSegundoDaemonNoArranca(t *testing.T) {
	t.Setenv("CODEGUARD_PIPE", "codeguard-prueba-instancia-unica")

	liberar, yaExiste, err := adquirirInstanciaUnica()
	if err != nil {
		t.Fatalf("la primera instancia no pudo adquirir la exclusión: %v", err)
	}
	if yaExiste {
		t.Fatal("la primera instancia se creyó segunda: quedó un mutex vivo de otra corrida")
	}

	_, segundaYaExiste, err := adquirirInstanciaUnica()
	if err != nil {
		t.Fatalf("la segunda instancia falló al comprobar: %v", err)
	}
	if !segundaYaExiste {
		liberar()
		t.Fatal("la segunda instancia NO vio a la primera: volverían los dos orbes superpuestos")
	}

	// Soltar tiene que dejar pasar al siguiente. Una guarda que se queda
	// cerrada para siempre es peor que no tenerla: deja al usuario sin agente
	// después de cualquier cierre sucio.
	liberar()
	liberarTercera, terceraYaExiste, err := adquirirInstanciaUnica()
	if err != nil {
		t.Fatalf("tras liberar, la tercera falló: %v", err)
	}
	if terceraYaExiste {
		t.Fatal("tras liberar seguía cerrada: un daemon fusilado dejaría al usuario sin orbe")
	}
	liberarTercera()
}

// El ámbito de la exclusión tiene que ser el MISMO que el del pipe.
//
// Si se atara al SID en vez de a ipc.PipeName(), una instancia aislada con
// CODEGUARD_PIPE —el mecanismo que usan las pruebas y el arranque a mano—
// quedaría bloqueada por el daemon real del usuario, que es justo lo que esa
// variable existe para evitar.
func TestLaExclusionSigueAlPipeYNoAlSID(t *testing.T) {
	t.Setenv("CODEGUARD_PIPE", "codeguard-prueba-ambito-a")
	a, err := nombreDeLaInstancia()
	if err != nil {
		t.Fatalf("nombre con el pipe A: %v", err)
	}

	t.Setenv("CODEGUARD_PIPE", "codeguard-prueba-ambito-b")
	b, err := nombreDeLaInstancia()
	if err != nil {
		t.Fatalf("nombre con el pipe B: %v", err)
	}

	if a == b {
		t.Fatalf("dos pipes distintos dieron la misma exclusión (%q): una instancia aislada "+
			"quedaría bloqueada por el daemon real", a)
	}
	if !strings.HasPrefix(a, `Local\`) {
		t.Errorf("la exclusión debe vivir en Local\\ (crear en Global\\ exige un privilegio "+
			"que el agente no pide, hardening 13); se obtuvo %q", a)
	}
	if strings.Contains(strings.TrimPrefix(a, `Local\`), `\`) {
		t.Errorf("el nombre conserva '\\' del pipe y el kernel lo rechaza: %q", a)
	}
}
