//go:build e2ereal

package trivydb

// La descarga sola no basta: hay que ver a trivy CAZAR con la base que bajamos
// nosotros. Si el layout no fuera exactamente el que espera, trivy fallaría o
// —peor— diría limpio.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTrivyCazaConNuestraBase(t *testing.T) {
	if os.Getenv("CODEGUARD_E2E_REAL") == "" {
		t.Skip("exige CODEGUARD_E2E_REAL=1 (baja ~60 MB y corre trivy de verdad)")
	}
	if _, err := exec.LookPath("trivy"); err != nil {
		t.Skip("sin trivy instalado no hay con qué cazar")
	}
	cache := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err := Actualizar(ctx, cache); err != nil {
		t.Fatalf("descarga: %v", err)
	}

	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "go.mod"),
		[]byte("module fixture\n\ngo 1.21\n\nrequire gopkg.in/yaml.v2 v2.2.2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "go.sum"), []byte(
		"gopkg.in/yaml.v2 v2.2.2 h1:ZCJp+EgiOT7lHqUV2J862kp8Qj64Jo6az82+3Td9dZw=\n"+
			"gopkg.in/yaml.v2 v2.2.2/go.mod h1:hI93XBmqTisBFMUTm0b8Fm+jr3Dg1NNxqwp+5A1VGuI=\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := exec.CommandContext(ctx, "trivy", "--cache-dir", cache,
		"fs", "--scanners", "vuln", "--format", "json", "--quiet", "--skip-db-update", repo).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "CVE-") {
		t.Fatalf("trivy falló: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "CVE-") {
		t.Fatalf("trivy no cazó ningún CVE con nuestra base sobre yaml.v2 v2.2.2:\n%.600s", out)
	}
	n := strings.Count(string(out), `"VulnerabilityID"`)
	t.Logf("  ✓ trivy cazó %d CVE con la base bajada por CodeGuard (--skip-db-update)", n)
}
