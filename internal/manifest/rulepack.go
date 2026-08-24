package manifest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
)

// RulepackManifest es lo que se firma por cada release de rulepack (W3,
// t.95-105): la lista exacta de archivos con sus hashes y el digest del
// árbol completo. Vive en el mismo paquete que el verificador de motores
// para que la forma canónica de "qué bytes se firman" jamás diverja entre
// firmador y verificador (condición de Kimi, t.98).
//
// La VERSIÓN del rulepack va DENTRO de lo firmado y debe coincidir con el
// nombre del directorio donde se instala: eso mata el misbinding (presentar
// 2026.07 como 2026.08 copiando el árbol completo con su firma válida).
type RulepackManifest struct {
	// Schema del manifiesto en sí (compuerta de versión, como Manifest).
	Schema int `json:"schema"`
	// Rulepack es la versión del rulepack (el nombre del directorio).
	Rulepack    string `json:"rulepack"`
	GeneratedAt string `json:"generated_at"`
	SignerKeyID string `json:"signer_key_id"`
	// TreeDigest es rulepack.DigestArbol sobre el árbol distribuido (bytes
	// exactos, testdata podado, manifest.json/.sig excluidos).
	TreeDigest string `json:"tree_digest"`
	// Files permite el diagnóstico por archivo cuando el árbol no coincide.
	Files []ArchivoDeRulepack `json:"files"`
}

type ArchivoDeRulepack struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

const RulepackSchemaSoportado = 1

func (m *RulepackManifest) validar() error {
	if m.Schema != RulepackSchemaSoportado {
		return fmt.Errorf("%w: schema=%d, este binario solo entiende %d",
			ErrManifestInvalido, m.Schema, RulepackSchemaSoportado)
	}
	if strings.TrimSpace(m.Rulepack) == "" {
		return fmt.Errorf("%w: rulepack (versión) vacío", ErrManifestInvalido)
	}
	if strings.TrimSpace(m.SignerKeyID) == "" {
		return fmt.Errorf("%w: signer_key_id vacío", ErrManifestInvalido)
	}
	if strings.TrimSpace(m.GeneratedAt) == "" {
		return fmt.Errorf("%w: generated_at vacío", ErrManifestInvalido)
	}
	if !esHex64Min(m.TreeDigest) {
		return fmt.Errorf("%w: tree_digest debe ser 64 hex minúsculas", ErrManifestInvalido)
	}
	if len(m.Files) == 0 {
		return fmt.Errorf("%w: sin archivos", ErrManifestInvalido)
	}
	rutas := make(map[string]string, len(m.Files))
	for _, f := range m.Files {
		if err := validarRutaRelativa(f.Path); err != nil {
			return fmt.Errorf("%w: %v", ErrManifestInvalido, err)
		}
		bajo := strings.ToLower(f.Path)
		if otra, ya := rutas[bajo]; ya {
			return fmt.Errorf("%w: rutas %q y %q colisionan en un filesystem case-insensitive",
				ErrManifestInvalido, otra, f.Path)
		}
		rutas[bajo] = f.Path
		if !esHex64Min(f.SHA256) {
			return fmt.Errorf("%w: %s: sha256 debe ser 64 hex minúsculas", ErrManifestInvalido, f.Path)
		}
		if f.SizeBytes < 0 {
			return fmt.Errorf("%w: %s: size_bytes negativo", ErrManifestInvalido, f.Path)
		}
	}
	return nil
}

// FirmarRulepack serializa UNA vez y firma esos bytes exactos; los dos
// valores se escriben VERBATIM (manifest.json y manifest.sig). Lo que no
// valida no se firma.
func FirmarRulepack(m *RulepackManifest, priv ed25519.PrivateKey) (manifestJSON, firma []byte, err error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("%w: clave privada de %d bytes, se esperan %d",
			ErrClaveInvalida, len(priv), ed25519.PrivateKeySize)
	}
	if err := m.validar(); err != nil {
		return nil, nil, fmt.Errorf("no se firma un manifiesto inválido: %w", err)
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("manifest: no se pudo serializar: %w", err)
	}
	return b, ed25519.Sign(priv, b), nil
}

// CargarYVerificarRulepack: firma sobre los bytes exactos, luego parseo
// estricto y validación estructural — el mismo fail-closed en cada paso que
// CargarYVerificar. La clave se elige por el signer_key_id del propio
// documento contra el registro embebido; un id desconocido es rechazo.
func CargarYVerificarRulepack(manifestJSON, firma []byte, claves map[string]ed25519.PublicKey) (*RulepackManifest, error) {
	if len(manifestJSON) == 0 {
		return nil, ErrManifestVacio
	}
	var sobre struct {
		SignerKeyID string `json:"signer_key_id"`
	}
	if err := json.Unmarshal(manifestJSON, &sobre); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrManifestInvalido, err)
	}
	pub, ok := claves[sobre.SignerKeyID]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrClaveDesconocida, sobre.SignerKeyID)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: la clave registrada para %q mide %d bytes",
			ErrClaveInvalida, sobre.SignerKeyID, len(pub))
	}
	if len(firma) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: %d bytes, se esperan %d", ErrFirmaMalformada, len(firma), ed25519.SignatureSize)
	}
	if !ed25519.Verify(pub, manifestJSON, firma) {
		return nil, ErrFirmaInvalida
	}
	var m RulepackManifest
	dec := json.NewDecoder(bytes.NewReader(manifestJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrManifestInvalido, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: datos tras el primer valor JSON", ErrManifestInvalido)
	}
	if err := m.validar(); err != nil {
		return nil, err
	}
	return &m, nil
}
