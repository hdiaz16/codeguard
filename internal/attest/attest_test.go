package attest

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSignAndVerifyRoundTrip(t *testing.T) {
	signer, err := GenerateSigner()
	if err != nil {
		t.Fatalf("GenerateSigner error: %v", err)
	}

	verifier := NewEd25519Verifier(signer.PublicKey())

	claims := Claims{
		Version:    Version,
		TreeSHA:    "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
		CommitSHA:  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4",
		PolicyHash: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		RepoID:     "github.com/org/repo",
	}

	att, err := signer.Sign(claims)
	if err != nil {
		t.Fatalf("Sign error: %v", err)
	}

	encoded, err := att.Encode()
	if err != nil {
		t.Fatalf("Encode error: %v", err)
	}

	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode error: %v", err)
	}

	// 1. Verificación exitosa
	opts := VerifyOptions{
		ExpectedTreeSHA:    claims.TreeSHA,
		ExpectedPolicyHash: claims.PolicyHash,
		MaxAge:             10 * time.Minute,
	}
	if err := verifier.Verify(decoded, opts); err != nil {
		t.Fatalf("Verify falló con atestación válida: %v", err)
	}

	// 2. Anti-Replay: Intento de presentar atestación para otro TreeSHA
	optsReplay := opts
	optsReplay.ExpectedTreeSHA = "0000000000000000000000000000000000000000"
	if err := verifier.Verify(decoded, optsReplay); !errors.Is(err, ErrTreeMismatch) {
		t.Errorf("Verify debía detectar ErrTreeMismatch, got: %v", err)
	}

	// 3. Anti-Downgrade: Intento de presentar atestación con política distinta
	optsPolicy := opts
	optsPolicy.ExpectedPolicyHash = "0000000000000000000000000000000000000000000000000000000000000000"
	if err := verifier.Verify(decoded, optsPolicy); !errors.Is(err, ErrPolicyMismatch) {
		t.Errorf("Verify debía detectar ErrPolicyMismatch, got: %v", err)
	}

	// 4. Clave desconocida
	signerOtro, _ := GenerateSigner()
	verifierAjen := NewEd25519Verifier(signerOtro.PublicKey())
	if err := verifierAjen.Verify(decoded, opts); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("Verify debía fallar con ErrUnknownKey, got: %v", err)
	}
}

func TestTrailerInjectionAndExtraction(t *testing.T) {
	msgOriginal := "feat: add payment processing\r\n\r\nThis commit implements the Stripe webhook."
	attValue := "eyJ2IjoxLCJ0cmVlIjoiNGI4MjVkYzY0MmNiNmViOWEwNjBlNTRiZjhkNjkyODhmYmVlNDkwNCJ9"

	msgConTrailer, err := InjectTrailer(msgOriginal, attValue)
	if err != nil {
		t.Fatalf("InjectTrailer error: %v", err)
	}

	if !strings.Contains(msgConTrailer, "CodeGuard-Attestation: "+attValue) {
		t.Errorf("El mensaje no contiene el trailer inyectado")
	}

	extraido, ok := ExtractTrailer(msgConTrailer)
	if !ok || extraido != attValue {
		t.Errorf("ExtractTrailer = (%q, %v), want (%q, true)", extraido, ok, attValue)
	}

	// Idempotencia: Inyectar un valor nuevo debe reemplazar el anterior
	attNuevo := "eyJ2IjoxLCJ0cmVlIjoiTkVXV19UUkVFX1NIQSJ9"
	msgActualizado, err := InjectTrailer(msgConTrailer, attNuevo)
	if err != nil {
		t.Fatalf("InjectTrailer update error: %v", err)
	}

	if strings.Count(msgActualizado, "CodeGuard-Attestation:") != 1 {
		t.Errorf("InjectTrailer duplicó el trailer en vez de actualizarlo")
	}

	extraidoNuevo, ok := ExtractTrailer(msgActualizado)
	if !ok || extraidoNuevo != attNuevo {
		t.Errorf("ExtractTrailer tras update = (%q, %v), want (%q, true)", extraidoNuevo, ok, attNuevo)
	}
}

func TestLoadOrGenerateKeyFile(t *testing.T) {
	dir := t.TempDir()

	// 1. Primera llamada genera la clave
	s1, err := LoadOrGenerateKeyFile(dir)
	if err != nil {
		t.Fatalf("LoadOrGenerateKeyFile (1) error: %v", err)
	}

	// 2. Segunda llamada carga la misma clave existente
	s2, err := LoadOrGenerateKeyFile(dir)
	if err != nil {
		t.Fatalf("LoadOrGenerateKeyFile (2) error: %v", err)
	}

	if s1.KeyID() != s2.KeyID() {
		t.Errorf("KeyID no coincide entre corridas: %s vs %s", s1.KeyID(), s2.KeyID())
	}

	pub, err := LoadPublicKeyFile(filepath.Join(dir, "signer_ed25519.pub"))
	if err != nil {
		t.Fatalf("LoadPublicKeyFile error: %v", err)
	}
	if KeyIDFor(pub) != s1.KeyID() {
		t.Errorf("KeyID de clave pública leída no coincide")
	}
}
