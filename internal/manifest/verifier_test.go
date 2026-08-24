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
	"strings"
	"testing"
)

func ptrInt64(v int64) *int64 { return &v }

// manifiestoValido produce un manifiesto que pasa validar(), para que cada
// test rompa exactamente UNA cosa.
func manifiestoValido() *Manifest {
	return &Manifest{
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
				SizeBytes:    ptrInt64(0),
				Capabilities: []string{"secrets"},
				Languages:    []string{"all"},
			},
		},
	}
}

func firmado(t *testing.T) (manifestJSON, firma []byte, pub ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	manifestJSON, firma, err = Firmar(manifiestoValido(), priv)
	if err != nil {
		t.Fatalf("Firmar: %v", err)
	}
	return manifestJSON, firma, pub
}

func TestCargarYVerificar(t *testing.T) {
	manifestJSON, firma, pub := firmado(t)

	// Caso 1: firma correcta sobre los bytes exactos de Firmar.
	m, err := CargarYVerificar(manifestJSON, firma, pub)
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

	// Caso 2: firma del tamaño correcto pero inválida.
	firmaAlterada := make([]byte, len(firma))
	copy(firmaAlterada, firma)
	firmaAlterada[0] ^= 0xFF
	if _, err := CargarYVerificar(manifestJSON, firmaAlterada, pub); !errors.Is(err, ErrFirmaInvalida) {
		t.Errorf("debía fallar con ErrFirmaInvalida, got: %v", err)
	}

	// Caso 3: manifiesto vacío.
	if _, err := CargarYVerificar(nil, firma, pub); !errors.Is(err, ErrManifestVacio) {
		t.Errorf("debía fallar con ErrManifestVacio, got: %v", err)
	}

	// Caso 4: un solo bit del contenido cambia ⇒ la firma deja de valer.
	adulterado := make([]byte, len(manifestJSON))
	copy(adulterado, manifestJSON)
	adulterado[len(adulterado)/2] ^= 0x01
	if _, err := CargarYVerificar(adulterado, firma, pub); !errors.Is(err, ErrFirmaInvalida) {
		t.Errorf("bit-flip debía dar ErrFirmaInvalida, got: %v", err)
	}
}

// El corazón de W3: TODO lo que no se puede verificar se rechaza. La rama
// vieja "clave malformada ⇒ se salta la firma" aceptaba el manifiesto.
func TestManifestFailClosed(t *testing.T) {
	manifestJSON, firma, pub := firmado(t)

	// Clave malformada (vacía, corta, larga): rechazo, jamás "sin verificar".
	for _, clave := range [][]byte{nil, {}, pub[:16], append(append([]byte{}, pub...), 0x00)} {
		if _, err := CargarYVerificar(manifestJSON, firma, clave); !errors.Is(err, ErrClaveInvalida) {
			t.Errorf("clave de %d bytes debía dar ErrClaveInvalida, got: %v", len(clave), err)
		}
	}

	// Firma truncada o ausente: error PROPIO, distinto de la firma inválida.
	for _, f := range [][]byte{nil, {}, firma[:32]} {
		if _, err := CargarYVerificar(manifestJSON, f, pub); !errors.Is(err, ErrFirmaMalformada) {
			t.Errorf("firma de %d bytes debía dar ErrFirmaMalformada, got: %v", len(f), err)
		}
	}
}

// La estructura se valida DESPUÉS de la firma: campos desconocidos, esquema
// futuro, duplicados y descriptores incompletos son rechazo aunque la firma
// sea criptográficamente válida (defensa contra un release mal construido).
func TestManifestInvalidoSeRechazaAunqueLaFirmaValga(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	firmaDe := func(b []byte) []byte { return ed25519.Sign(priv, b) }

	casos := []struct {
		nombre string
		muta   func(m *Manifest)
	}{
		{"esquema futuro", func(m *Manifest) { m.Version = 2 }},
		{"sin signer_key_id", func(m *Manifest) { m.SignerKeyID = " " }},
		{"sin generated_at", func(m *Manifest) { m.GeneratedAt = "" }},
		{"sin motores", func(m *Manifest) { m.Engines = nil }},
		{"id duplicado", func(m *Manifest) { m.Engines = append(m.Engines, m.Engines[0]) }},
		{"id vacío", func(m *Manifest) { m.Engines[0].ID = "" }},
		{"sha en mayúsculas", func(m *Manifest) { m.Engines[0].SHA256 = strings.ToUpper(m.Engines[0].SHA256) }},
		{"sha corto", func(m *Manifest) { m.Engines[0].SHA256 = "abc123" }},
		{"sha vacío", func(m *Manifest) { m.Engines[0].SHA256 = "" }},
		{"size ausente", func(m *Manifest) { m.Engines[0].SizeBytes = nil }},
		{"size negativo", func(m *Manifest) { m.Engines[0].SizeBytes = ptrInt64(-1) }},
		{"ruta absoluta", func(m *Manifest) { m.Engines[0].Path = "/etc/passwd" }},
		{"ruta con ..", func(m *Manifest) { m.Engines[0].Path = "engines/../../fuera.exe" }},
		{"ruta con drive/ADS", func(m *Manifest) { m.Engines[0].Path = "C:/engines/g.exe" }},
		{"ruta con backslash", func(m *Manifest) { m.Engines[0].Path = "engines\\g.exe" }},
	}
	for _, c := range casos {
		m := manifiestoValido()
		c.muta(m)
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("%s: Marshal: %v", c.nombre, err)
		}
		if _, err := CargarYVerificar(b, firmaDe(b), pub); !errors.Is(err, ErrManifestInvalido) {
			t.Errorf("%s: debía dar ErrManifestInvalido, got: %v", c.nombre, err)
		}
	}

	// Colisión case-insensitive entre rutas de dos motores distintos.
	m := manifiestoValido()
	otro := m.Engines[0]
	otro.ID = "gitleaks2"
	otro.Path = "Engines/Gitleaks.exe"
	m.Engines = append(m.Engines, otro)
	b, _ := json.Marshal(m)
	if _, err := CargarYVerificar(b, firmaDe(b), pub); !errors.Is(err, ErrManifestInvalido) {
		t.Errorf("colisión EqualFold de rutas debía dar ErrManifestInvalido, got: %v", err)
	}

	// Campo desconocido: el JSON firmado se parsea estricto.
	conExtra := []byte(`{"version":1,"generated_at":"x","signer_key_id":"k","engines":[],"sorpresa":true}`)
	if _, err := CargarYVerificar(conExtra, firmaDe(conExtra), pub); !errors.Is(err, ErrManifestInvalido) {
		t.Errorf("campo desconocido debía dar ErrManifestInvalido, got: %v", err)
	}

	// Datos tras el primer valor JSON.
	base, _ := json.Marshal(manifiestoValido())
	concatenado := append(append([]byte{}, base...), []byte(`{"otro":1}`)...)
	if _, err := CargarYVerificar(concatenado, firmaDe(concatenado), pub); !errors.Is(err, ErrManifestInvalido) {
		t.Errorf("JSON concatenado debía dar ErrManifestInvalido, got: %v", err)
	}
}

func TestFirmarRechazaLoInvalido(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := manifiestoValido()
	m.Engines[0].SHA256 = ""
	if _, _, err := Firmar(m, priv); !errors.Is(err, ErrManifestInvalido) {
		t.Errorf("Firmar con descriptor sin sha debía rechazar, got: %v", err)
	}
	if _, _, err := Firmar(manifiestoValido(), priv[:16]); !errors.Is(err, ErrClaveInvalida) {
		t.Errorf("Firmar con privada truncada debía dar ErrClaveInvalida, got: %v", err)
	}
}

func TestCargarYVerificarConClaves(t *testing.T) {
	manifestJSON, firma, pub := firmado(t)

	// La clave se elige por signer_key_id; un id fuera del registro es rechazo.
	if m, err := CargarYVerificarConClaves(manifestJSON, firma,
		map[string]ed25519.PublicKey{"test-key-01": pub}); err != nil || m == nil {
		t.Fatalf("con registro correcto debía verificar, got: %v", err)
	}
	if _, err := CargarYVerificarConClaves(manifestJSON, firma,
		map[string]ed25519.PublicKey{"otra-clave": pub}); !errors.Is(err, ErrClaveDesconocida) {
		t.Errorf("id fuera del registro debía dar ErrClaveDesconocida, got: %v", err)
	}
	if _, err := CargarYVerificarConClaves(manifestJSON, firma,
		map[string]ed25519.PublicKey{}); !errors.Is(err, ErrClaveDesconocida) {
		t.Errorf("registro vacío debía dar ErrClaveDesconocida, got: %v", err)
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
		SizeBytes: ptrInt64(tamanoEsperado),
	}

	// Caso 1: binario coincide al 100%.
	if err := VerificarBinario(context.Background(), binPath, descValido); err != nil {
		t.Errorf("VerificarBinario falló con binario legítimo: %v", err)
	}

	// Caso 2: hash alterado (tampering).
	descAlterado := descValido
	descAlterado.SHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
	if err := VerificarBinario(context.Background(), binPath, descAlterado); !errors.Is(err, ErrHashNoCoincide) {
		t.Errorf("debía detectar ErrHashNoCoincide, got: %v", err)
	}

	// Caso 3: tamaño alterado.
	descTamanoErr := descValido
	descTamanoErr.SizeBytes = ptrInt64(999999)
	if err := VerificarBinario(context.Background(), binPath, descTamanoErr); !errors.Is(err, ErrTamanoNoCoincide) {
		t.Errorf("debía detectar ErrTamanoNoCoincide, got: %v", err)
	}

	// Caso 4: contexto cancelado.
	ctxCancel, cancel := context.WithCancel(context.Background())
	cancel()
	if err := VerificarBinario(ctxCancel, binPath, descValido); !errors.Is(err, context.Canceled) {
		t.Errorf("debía respetar ctx cancelado, got: %v", err)
	}
}

// El fail-open medido el 2026-08-23: un descriptor sin sha o sin tamaño
// SALTABA su comparación y validaba cualquier archivo. Ahora es rechazo.
func TestVerificarBinarioFailClosed(t *testing.T) {
	dir := t.TempDir()
	binPath := filepath.Join(dir, "motor_fake.exe")
	if err := os.WriteFile(binPath, []byte("lo que sea"), 0o755); err != nil {
		t.Fatal(err)
	}

	sinHash := EngineDescriptor{ID: "m", SHA256: "", SizeBytes: ptrInt64(10)}
	if err := VerificarBinario(context.Background(), binPath, sinHash); !errors.Is(err, ErrManifestInvalido) {
		t.Errorf("descriptor sin sha debía rechazar con ErrManifestInvalido, got: %v", err)
	}

	sum := sha256.Sum256([]byte("lo que sea"))
	sinTamano := EngineDescriptor{ID: "m", SHA256: hex.EncodeToString(sum[:]), SizeBytes: nil}
	if err := VerificarBinario(context.Background(), binPath, sinTamano); !errors.Is(err, ErrManifestInvalido) {
		t.Errorf("descriptor sin size debía rechazar con ErrManifestInvalido, got: %v", err)
	}

	// Y el caso legítimo que motivó el puntero: archivo VACÍO, tamaño 0 real.
	vacioPath := filepath.Join(dir, "vacio.bin")
	if err := os.WriteFile(vacioPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	sumVacio := sha256.Sum256(nil)
	descVacio := EngineDescriptor{ID: "v", SHA256: hex.EncodeToString(sumVacio[:]), SizeBytes: ptrInt64(0)}
	if err := VerificarBinario(context.Background(), vacioPath, descVacio); err != nil {
		t.Errorf("archivo vacío con descriptor completo (sha del vacío, tamaño 0) es legítimo, got: %v", err)
	}
}
