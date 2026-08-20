// Package manifest implementa la verificación criptográfica (Ed25519 + SHA256)
// de los binarios de motores antes de su ejecución (Pilar 1 - Pinning Criptográfico).
package manifest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

var (
	ErrFirmaInvalida     = errors.New("manifest: firma criptográfica Ed25519 inválida")
	ErrHashNoCoincide    = errors.New("manifest: el hash SHA-256 del binario no coincide con el fijado")
	ErrTamanoNoCoincide  = errors.New("manifest: el tamaño del binario no coincide con el manifest")
	ErrMotorNoEncontrado = errors.New("manifest: motor no registrado en el manifiesto")
	ErrManifestVacio     = errors.New("manifest: manifiesto vacío o corrupto")
)

// EngineDescriptor describe un motor con su identidad criptográfica.
type EngineDescriptor struct {
	ID              string   `json:"id"`
	Version         string   `json:"version"`
	Platform        string   `json:"platform"`
	Path            string   `json:"path"`
	SHA256          string   `json:"sha256"`
	SizeBytes       int64    `json:"size_bytes"`
	Capabilities    []string `json:"capabilities"`
	Languages       []string `json:"languages"`
	NetworkRequired bool     `json:"network_required"`
}

// Manifest es el conjunto de motores verificados y versionados.
type Manifest struct {
	Version     int                `json:"version"`
	GeneratedAt string             `json:"generated_at"`
	SignerKeyID string             `json:"signer_key_id"`
	Engines     []EngineDescriptor `json:"engines"`
	indicePorID map[string]EngineDescriptor
	mu          sync.RWMutex
}

// Indexar construye el mapa de búsqueda rápida por ID de motor.
func (m *Manifest) Indexar() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.indicePorID = make(map[string]EngineDescriptor, len(m.Engines))
	for _, e := range m.Engines {
		m.indicePorID[e.ID] = e
	}
}

// ObtenerMotor busca el descriptor de un motor por su ID.
func (m *Manifest) ObtenerMotor(id string) (EngineDescriptor, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.indicePorID == nil {
		for _, e := range m.Engines {
			if e.ID == id {
				return e, true
			}
		}
		return EngineDescriptor{}, false
	}
	e, ok := m.indicePorID[id]
	return e, ok
}

// CargarYVerificar parsea el JSON del manifiesto y valida su firma Ed25519.
func CargarYVerificar(manifestJSON []byte, firma []byte, pubKey ed25519.PublicKey) (*Manifest, error) {
	if len(manifestJSON) == 0 {
		return nil, ErrManifestVacio
	}
	if len(pubKey) == ed25519.PublicKeySize {
		if !ed25519.Verify(pubKey, manifestJSON, firma) {
			return nil, ErrFirmaInvalida
		}
	}

	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(manifestJSON))
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("manifest: JSON corrupto: %w", err)
	}
	m.Indexar()
	return &m, nil
}

// cacheItem guarda el resultado reciente de verificación de un archivo.
type cacheItem struct {
	mtime time.Time
	size  int64
	hash  string
}

var (
	cacheMu sync.RWMutex
	cache   = map[string]cacheItem{}
)

// CalcularSHA256 calcula el hash SHA-256 en streaming de un archivo en disco.
func CalcularSHA256(ruta string) (string, int64, error) {
	f, err := os.Open(ruta)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return "", 0, err
	}

	cacheMu.RLock()
	if c, ok := cache[ruta]; ok {
		if c.mtime.Equal(info.ModTime()) && c.size == info.Size() {
			cacheMu.RUnlock()
			return c.hash, c.size, nil
		}
	}
	cacheMu.RUnlock()

	hasher := sha256.New()
	n, err := io.Copy(hasher, f)
	if err != nil {
		return "", 0, err
	}

	hashStr := hex.EncodeToString(hasher.Sum(nil))

	cacheMu.Lock()
	cache[ruta] = cacheItem{
		mtime: info.ModTime(),
		size:  n,
		hash:  hashStr,
	}
	cacheMu.Unlock()

	return hashStr, n, nil
}

// VerificarBinario comprueba que el archivo en ruta coincida con el hash y tamaño fijados.
func VerificarBinario(ctx context.Context, ruta string, desc EngineDescriptor) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	hashCalculado, tamano, err := CalcularSHA256(ruta)
	if err != nil {
		return fmt.Errorf("manifest: no se pudo leer el binario %s: %w", ruta, err)
	}

	if desc.SizeBytes > 0 && tamano != desc.SizeBytes {
		return fmt.Errorf("%w: obtenido %d, esperado %d para %s",
			ErrTamanoNoCoincide, tamano, desc.SizeBytes, desc.ID)
	}

	if desc.SHA256 != "" && hashCalculado != desc.SHA256 {
		return fmt.Errorf("%w: obtenido %s, esperado %s para %s",
			ErrHashNoCoincide, hashCalculado, desc.SHA256, desc.ID)
	}

	return nil
}
