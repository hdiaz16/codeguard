package attest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const (
	privKeyFilename = "signer_ed25519.pem"
	pubKeyFilename  = "signer_ed25519.pub"
)

// Signer define el contrato de firma de atestaciones.
type Signer interface {
	Sign(c Claims) (*Attestation, error)
	KeyID() string
	PublicKey() ed25519.PublicKey
}

// Ed25519Signer implementa Signer usando criptografía Ed25519.
type Ed25519Signer struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	kid  string
}

// KeyIDFor calcula el identificador canónico (huella SHA-256 en base64url) de una clave pública.
func KeyIDFor(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

// NewEd25519Signer construye un firmante a partir de una clave privada.
func NewEd25519Signer(priv ed25519.PrivateKey) (*Ed25519Signer, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("attest: tamaño de clave privada Ed25519 inválido")
	}
	pub := priv.Public().(ed25519.PublicKey)
	return &Ed25519Signer{
		priv: priv,
		pub:  pub,
		kid:  KeyIDFor(pub),
	}, nil
}

// GenerateSigner genera un nuevo par de claves Ed25519 con entropía CSPRNG.
func GenerateSigner() (*Ed25519Signer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("attest: no se pudo generar clave Ed25519: %w", err)
	}
	return &Ed25519Signer{
		priv: priv,
		pub:  pub,
		kid:  KeyIDFor(pub),
	}, nil
}

// KeyID retorna el identificador de la clave pública.
func (s *Ed25519Signer) KeyID() string { return s.kid }

// PublicKey retorna la clave pública Ed25519.
func (s *Ed25519Signer) PublicKey() ed25519.PublicKey { return s.pub }

// Sign firma los claims con la clave privada Ed25519 y produce la atestación.
func (s *Ed25519Signer) Sign(c Claims) (*Attestation, error) {
	if c.Version == 0 {
		c.Version = Version
	}
	if c.Timestamp == 0 {
		c.Timestamp = time.Now().UTC().Unix()
	}
	if c.Nonce == "" {
		n := make([]byte, nonceLen)
		if _, err := io.ReadFull(rand.Reader, n); err != nil {
			return nil, fmt.Errorf("attest: fallo al generar nonce: %w", err)
		}
		c.Nonce = base64.RawURLEncoding.EncodeToString(n)
	}
	c.KeyID = s.kid

	payload, err := c.CanonicalBytes()
	if err != nil {
		return nil, err
	}

	sig := ed25519.Sign(s.priv, payload)
	return &Attestation{
		Claims:    c,
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	}, nil
}

// DefaultKeyDir resuelve la ruta estándar para el almacén de claves de CodeGuard.
func DefaultKeyDir() (string, error) {
	if dir := os.Getenv("CODEGUARD_KEY_DIR"); dir != "" {
		return dir, nil
	}
	if runtime.GOOS == "windows" {
		if local := os.Getenv("LOCALAPPDATA"); local != "" {
			return filepath.Join(local, "codeguard", "keys"), nil
		}
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "codeguard", "keys"), nil
}

// LoadOrGenerateKeyFile carga la clave privada desde dir, o genera una nueva de forma transparente.
func LoadOrGenerateKeyFile(dir string) (*Ed25519Signer, error) {
	privPath := filepath.Join(dir, privKeyFilename)
	if b, err := os.ReadFile(privPath); err == nil {
		return parsePrivateKeyPEM(b)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("attest: error al leer clave privada: %w", err)
	}

	s, err := GenerateSigner()
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("attest: no se pudo crear directorio de claves: %w", err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(s.priv)
	if err != nil {
		return nil, fmt.Errorf("attest: fallo al serializar PKCS8: %w", err)
	}
	privBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privDER,
	})
	if err := os.WriteFile(privPath, privBlock, 0o600); err != nil {
		return nil, fmt.Errorf("attest: no se pudo persistir clave privada: %w", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(s.pub)
	if err == nil {
		pubBlock := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubDER,
		})
		pubPath := filepath.Join(dir, pubKeyFilename)
		_ = os.WriteFile(pubPath, pubBlock, 0o644)
	}

	return s, nil
}

func parsePrivateKeyPEM(b []byte) (*Ed25519Signer, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("attest: formato PEM de clave privada inválido")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("attest: parsing PKCS8 falló: %w", err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("attest: la clave cargada no es Ed25519")
	}
	return NewEd25519Signer(priv)
}

// LoadPublicKeyFile carga una clave pública en formato PEM desde disco.
func LoadPublicKeyFile(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("attest: formato PEM de clave pública inválido")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("attest: parsing PKIX falló: %w", err)
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("attest: la clave pública no es Ed25519")
	}
	return pub, nil
}
