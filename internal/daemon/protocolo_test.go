package daemon

import (
	"context"
	"testing"

	"codeguard/internal/ipc"
)

// La matriz N/N-1/N-2 del handshake ([13], aceptación firmada del plan): la
// decisión es una función pura y aquí se fija ENTERA — el «sin rango = legacy
// exacto» incluido, porque interpretarlo como compatibilidad universal es la
// clase de default que un día analiza con un protocolo que no entiende.
func TestLaMatrizDeProtocolo(t *testing.T) {
	casos := []struct {
		nombre     string
		version    int
		min, max   int
		compatible bool
	}{
		{"el binario actual (rango propio)", ipc.ProtocolVersion, ipc.ProtocolMin, ipc.ProtocolMax, true},
		{"cliente anterior al handshake: legacy exacto v1", 1, 0, 0, false},
		{"cliente prehistórico sin versión siquiera", 0, 0, 0, false},
		{"cliente FUTURO que aún habla nuestro rango", 2, 1, 2, true},
		{"cliente futuro que ya NO habla nuestro rango", 3, 3, 3, false},
		{"cliente viejo de un protocolo retirado (N-2 hipotético)", 0, -1, 0, false},
		{"legacy exacto de una versión que no hablamos", 9, 0, 0, false},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			ok, _, _ := protocoloCompatible(&ipc.Request{
				ProtocolVersion: c.version, ProtocolMin: c.min, ProtocolMax: c.max})
			if ok != c.compatible {
				t.Errorf("compatible=%v, se esperaba %v", ok, c.compatible)
			}
		})
	}
}

func TestElDaemonRechazaAnalizarSinInstantanea(t *testing.T) {
	resp := (&Server{}).Analyze(context.Background(), &ipc.Request{
		RunID: "sin-snapshot", RepoRoot: t.TempDir(),
	})
	if resp.Verdict != "error" {
		t.Fatalf("sin analysis_root el daemon debe forzar el fallback local; respondió %q (%s)",
			resp.Verdict, resp.Reason)
	}
}
