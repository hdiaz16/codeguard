package attest

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultMaxClockSkew es la tolerancia por desfase de reloj.
	DefaultMaxClockSkew = 5 * time.Minute
)

// VerifyOptions define los criterios de aceptación deterministas del verificador.
type VerifyOptions struct {
	ExpectedTreeSHA    string        // Hash del árbol Git del commit (Anti-Replay)
	ExpectedPolicyHash string        // Hash de la política vigente (Anti-Downgrade)
	MaxAge             time.Duration // Antigüedad máxima permitida (0 = ilimitada)
	MaxClockSkew       time.Duration // Tolerancia para timestamps en el futuro
	Now                time.Time     // Tiempo de referencia (zero = time.Now())
}

// Verifier evalúa las atestaciones con política fail-closed.
type Verifier interface {
	Verify(a *Attestation, opts VerifyOptions) error
}

// Ed25519Verifier valida firmas contra un conjunto de claves públicas autorizadas.
type Ed25519Verifier struct {
	mu   sync.RWMutex
	keys map[string]ed25519.PublicKey
}

// NewEd25519Verifier crea un verificador con las claves públicas provistas.
func NewEd25519Verifier(pubs ...ed25519.PublicKey) *Ed25519Verifier {
	v := &Ed25519Verifier{
		keys: make(map[string]ed25519.PublicKey, len(pubs)),
	}
	for _, p := range pubs {
		v.AddKey(p)
	}
	return v
}

// AddKey añade una clave pública confiable al verificador.
func (v *Ed25519Verifier) AddKey(pub ed25519.PublicKey) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(pub) == ed25519.PublicKeySize {
		kid := KeyIDFor(pub)
		v.keys[kid] = append(ed25519.PublicKey(nil), pub...)
	}
}

// Verify aplica la cadena de validación estricta sobre la atestación.
func (v *Ed25519Verifier) Verify(a *Attestation, opts VerifyOptions) error {
	if a == nil {
		return fmt.Errorf("%w: atestación nula", ErrMalformed)
	}
	if err := a.Claims.Validate(); err != nil {
		return err
	}

	v.mu.RLock()
	pub, ok := v.keys[a.Claims.KeyID]
	v.mu.RUnlock()
	if !ok {
		return fmt.Errorf("%w: clave id %s", ErrUnknownKey, a.Claims.KeyID)
	}

	sig, err := base64.RawURLEncoding.DecodeString(a.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: formato de firma inválido", ErrMalformed)
	}

	payload, err := a.Claims.CanonicalBytes()
	if err != nil {
		return err
	}

	if !ed25519.Verify(pub, payload, sig) {
		return ErrBadSignature
	}

	// 1. Anti-Replay: binding estricto a TreeSHA
	if opts.ExpectedTreeSHA != "" {
		if subtle.ConstantTimeCompare([]byte(strings.ToLower(a.Claims.TreeSHA)), []byte(strings.ToLower(opts.ExpectedTreeSHA))) != 1 {
			return fmt.Errorf("%w: obtenido %s, esperado %s", ErrTreeMismatch, a.Claims.TreeSHA, opts.ExpectedTreeSHA)
		}
	}

	// 2. Anti-Downgrade: binding a PolicyHash
	if opts.ExpectedPolicyHash != "" {
		if subtle.ConstantTimeCompare([]byte(strings.ToLower(a.Claims.PolicyHash)), []byte(strings.ToLower(opts.ExpectedPolicyHash))) != 1 {
			return fmt.Errorf("%w: obtenido %s, esperado %s", ErrPolicyMismatch, a.Claims.PolicyHash, opts.ExpectedPolicyHash)
		}
	}

	// 3. Ventana de Frescura y Clock Skew
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	skew := opts.MaxClockSkew
	if skew <= 0 {
		skew = DefaultMaxClockSkew
	}

	ts := time.Unix(a.Claims.Timestamp, 0).UTC()
	if ts.After(now.Add(skew)) {
		return fmt.Errorf("%w: timestamp %s excede reloj actual %s", ErrNotYetValid, ts, now)
	}

	if opts.MaxAge > 0 && now.Sub(ts) > opts.MaxAge {
		return fmt.Errorf("%w: antigüedad %s excede límite %s", ErrExpired, now.Sub(ts), opts.MaxAge)
	}

	return nil
}
