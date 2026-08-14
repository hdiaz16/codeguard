package trivydb

// Prueba de integración contra el ghcr.io REAL. No corre en la suite normal:
// baja ~60 MB y depende de la red. Se invoca a mano con:
//
//	go test ./internal/trivydb/ -run TestDescargaRealDeGhcr -tags e2ereal -count=1 -v
//
// Existe porque el registro falso demuestra la lógica, pero no que ghcr.io
// hable exactamente el dialecto que esperamos (token anónimo, índice OCI,
// media types). Eso sólo se sabe contra el de verdad.

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDescargaRealDeGhcr(t *testing.T) {
	if os.Getenv("CODEGUARD_E2E_REAL") == "" {
		t.Skip("prueba contra ghcr.io real: exige CODEGUARD_E2E_REAL=1 (baja ~60 MB)")
	}
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err := Actualizar(ctx, dir); err != nil {
		t.Fatalf("la descarga real falló: %v", err)
	}
	for _, n := range []string{"trivy.db", "metadata.json"} {
		st, err := os.Stat(filepath.Join(dir, "db", n))
		if err != nil || st.Size() == 0 {
			t.Fatalf("%s no quedó en su sitio: %v", n, err)
		}
		t.Logf("  ✓ %s: %.1f MB", n, float64(st.Size())/(1<<20))
	}
}
