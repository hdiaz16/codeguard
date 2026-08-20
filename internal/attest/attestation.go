// Package attest implementa las atestaciones criptográficas de commits para CodeGuard:
// firmas Ed25519 con separación de dominio que ligan el hash del árbol Git (tree_sha)
// a la política de seguridad aplicada y una ventana de frescura (Fix de Raíz 1).
package attest

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

const (
	// DomainPrefix previene ataques de contexto o confusión de protocolos.
	DomainPrefix = "codeguard-attest-v1:"
	// Version actual del esquema de claims.
	Version = 1
	// TrailerKey es el identificador del trailer estándar en el commit de Git.
	TrailerKey = "CodeGuard-Attestation"

	maxEncodedLen = 8192
	nonceLen      = 16
)

var (
	ErrMalformed          = errors.New("attest: atestación malformada o inválida")
	ErrUnsupportedVersion = errors.New("attest: versión de atestación no soportada")
	ErrUnknownKey         = errors.New("attest: clave pública de firma desconocida o no autorizada")
	ErrBadSignature       = errors.New("attest: firma criptográfica inválida")
	ErrTreeMismatch       = errors.New("attest: discrepancia en TreeSHA (posible ataque de replay)")
	ErrPolicyMismatch     = errors.New("attest: discrepancia en PolicyHash (posible ataque de downgrade)")
	ErrExpired            = errors.New("attest: atestación expirada")
	ErrNotYetValid        = errors.New("attest: timestamp de atestación en el futuro")
)

// Claims contiene los datos de procedencia firmados.
// No usa omitempty para garantizar determinismo estricto en la serialización.
type Claims struct {
	Version    int    `json:"v"`
	TreeSHA    string `json:"tree"`
	CommitSHA  string `json:"commit"`
	ParentSHA  string `json:"parent"`
	RepoID     string `json:"repo"`
	PolicyHash string `json:"policy"`
	KeyID      string `json:"kid"`
	Nonce      string `json:"nonce"`
	Timestamp  int64  `json:"ts"`
}

// Attestation empaqueta los claims con su firma Ed25519 en base64url.
type Attestation struct {
	Claims    Claims `json:"claims"`
	Signature string `json:"sig"` // Base64URL sin padding
}

func isHex(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func validGitSHA(s string) bool {
	return (len(s) == 40 || len(s) == 64) && isHex(s)
}

// Validate comprueba que los campos esenciales de Claims sean válidos.
func (c Claims) Validate() error {
	if c.Version != Version {
		return fmt.Errorf("%w: versión %d", ErrUnsupportedVersion, c.Version)
	}
	if !validGitSHA(c.TreeSHA) {
		return fmt.Errorf("%w: tree_sha inválido", ErrMalformed)
	}
	if c.CommitSHA != "" && !validGitSHA(c.CommitSHA) {
		return fmt.Errorf("%w: commit_sha inválido", ErrMalformed)
	}
	if c.ParentSHA != "" && !validGitSHA(c.ParentSHA) {
		return fmt.Errorf("%w: parent_sha inválido", ErrMalformed)
	}
	if c.PolicyHash == "" || !isHex(c.PolicyHash) {
		return fmt.Errorf("%w: policy_hash inválido", ErrMalformed)
	}
	if c.KeyID == "" {
		return fmt.Errorf("%w: key_id vacío", ErrMalformed)
	}
	if len(c.Nonce) < 16 {
		return fmt.Errorf("%w: nonce insuficiente", ErrMalformed)
	}
	if c.Timestamp <= 0 {
		return fmt.Errorf("%w: timestamp inválido", ErrMalformed)
	}
	return nil
}

// CanonicalBytes produce la carga de bytes determinista sobre la que se calcula la firma.
func (c Claims) CanonicalBytes() ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(DomainPrefix)+len(b))
	out = append(out, DomainPrefix...)
	out = append(out, b...)
	return out, nil
}

// Encode serializa la atestación a una cadena base64url compacta para Git trailers.
func (a *Attestation) Encode() (string, error) {
	if a == nil {
		return "", ErrMalformed
	}
	b, err := json.Marshal(a)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Decode deserializa una atestación desde base64url con validaciones de seguridad estrictas.
func Decode(s string) (*Attestation, error) {
	if s == "" || len(s) > maxEncodedLen {
		return nil, ErrMalformed
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: decodificación base64url falló: %v", ErrMalformed, err)
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()

	var a Attestation
	if err := dec.Decode(&a); err != nil {
		return nil, fmt.Errorf("%w: json inválido: %v", ErrMalformed, err)
	}
	if err := a.Claims.Validate(); err != nil {
		return nil, err
	}
	if a.Signature == "" {
		return nil, fmt.Errorf("%w: firma ausente", ErrMalformed)
	}
	return &a, nil
}
