package manifest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCargarYVerificar(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	mOriginal := &Manifest{
		Version:     1,
		GeneratedAt: "2026-08-20T12:00:00Z",
		SignerKeyID: "test-key-01",
		Engines: []EngineDescriptor{
			{
				ID:           "gitleaks",
				Version:      "8.21.0",
				Platform:     "windows/amd64",
				Path:         "engines/gitleaks.exe",
				SHA256:       "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				SizeBytes:    0,
				Capabilities: []string{"secrets"},
				Languages:    []string{"all"},
			},
		},
	}

	manifestBytes, err := json.Marshal(mOriginal)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	firma := ed25519.Sign(privKey, manifestBytes)

	// Caso 1: Firma correcta
	m, err := CargarYVerificar(manifestBytes, firma, pubKey)
	if err != nil {
		t.Fatalf("CargarYVerificar falló con firma válida: %v", err)
	}
	if len(m.Engines) != 1 || m.Engines[0].ID != "gitleaks" {
		t.Errorf("Manifest parseado incorrectamente: %+v", m)
	}
	desc, ok := m.ObtenerMotor("gitleaks")
	if !ok || desc.Version != "8.21.0" {
		t.Errorf("ObtenerMotor no encontró el motor o versión errónea")
	}

	// Caso 2: Firma alterada / inválida
	firmaAlterada := make([]byte, len(firma))
	copy(firmaAlterada, firma)
	firmaAlterada[0] ^= 0xFF

	_, err = CargarYVerificar(manifestBytes, firmaAlterada, pubKey)
	if !errors.Is(err, ErrFirmaInvalida) {
		t.Errorf("CargarYVerificar debía fallar con ErrFirmaInvalida, got: %v", err)
	}

	// Caso 3: Manifiesto vacío
	_, err = CargarYVerificar(nil, firma, pubKey)
	if !errors.Is(err, ErrManifestVacio) {
		t.Errorf("CargarYVerificar debía fallar con ErrManifestVacio, got: %v", err)
	}
}

func TestVerificarBinario(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "motor_fake.exe")
	contenido := []byte("binario ejecutable de prueba 12345")
	if err := os.WriteFile(binPath, contenido, 0o755); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	sum := sha256.Sum256(contenido)
	hashEsperado := hex.EncodeToString(sum[:])
	tamanoEsperado := int64(len(contenido))

	descValido := EngineDescriptor{
		ID:        "motor_fake",
		SHA256:    hashEsperado,
		SizeBytes: tamanoEsperado,
	}

	// Caso 1: Binario coincide al 100%
	if err := VerificarBinario(context.Background(), binPath, descValido); err != nil {
		t.Errorf("VerificarBinario falló con binario legítimo: %v", err)
	}

	// Caso 2: Hash alterado (tampering)
	descAlterado := EngineDescriptor{
		ID:        "motor_fake",
		SHA256:    "0000000000000000000000000000000000000000000000000000000000000000",
		SizeBytes: tamanoEsperado,
	}
	err := VerificarBinario(context.Background(), binPath, descAlterado)
	if !errors.Is(err, ErrHashNoCoincide) {
		t.Errorf("VerificarBinario debía detectar ErrHashNoCoincide, got: %v", err)
	}

	// Caso 3: Tamaño alterado
	descTamanoErr := EngineDescriptor{
		ID:        "motor_fake",
		SHA256:    hashEsperado,
		SizeBytes: 999999,
	}
	err = VerificarBinario(context.Background(), binPath, descTamanoErr)
	if !errors.Is(err, ErrTamanoNoCoincide) {
		t.Errorf("VerificarBinario debía detectar ErrTamanoNoCoincide, got: %v", err)
	}

	// Caso 4: Contexto cancelado
	ctxCancel, cancel := context.WithCancel(context.Background())
	cancel()
	if err := VerificarBinario(ctxCancel, binPath, descValido); !errors.Is(err, context.Canceled) {
		t.Errorf("VerificarBinario debía respetar ctx cancelado, got: %v", err)
	}
}
