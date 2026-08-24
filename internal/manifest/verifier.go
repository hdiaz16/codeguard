// Package manifest implementa la verificación criptográfica (Ed25519 + SHA256)
// de artefactos distribuidos: los binarios de motores y, desde W3, el
// manifiesto de rulepack. Doctrina fail-closed firmada por el consejo
// (plan-calidad-mundial, turnos 95-104): lo que no se puede verificar se
// RECHAZA con un error que dice por qué — una clave malformada, una firma
// truncada o un descriptor incompleto jamás se interpretan como "no hace
// falta verificar".
//
// La firma cubre BYTES, no contenido lógico: Firmar serializa una vez y esos
// bytes exactos son los que se escriben a disco y los que se verifican.
// Re-serializar (aunque el JSON sea equivalente) invalida la firma, y eso es
// correcto: el manifiesto se escribe UNA vez y nunca se reformatea.
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
	"strings"
	"sync"
	"time"
)

var (
	ErrFirmaInvalida     = errors.New("manifest: firma criptográfica Ed25519 inválida")
	ErrFirmaMalformada   = errors.New("manifest: firma de tamaño incorrecto (truncada o corrupta, no es una firma Ed25519)")
	ErrClaveInvalida     = errors.New("manifest: clave pública de tamaño incorrecto — sin clave válida no hay verificación posible")
	ErrClaveDesconocida  = errors.New("manifest: signer_key_id no corresponde a ninguna clave de release conocida")
	ErrHashNoCoincide    = errors.New("manifest: el hash SHA-256 del binario no coincide con el fijado")
	ErrTamanoNoCoincide  = errors.New("manifest: el tamaño del binario no coincide con el manifest")
	ErrMotorNoEncontrado = errors.New("manifest: motor no registrado en el manifiesto")
	ErrManifestVacio     = errors.New("manifest: manifiesto vacío o corrupto")
	ErrManifestInvalido  = errors.New("manifest: contenido estructuralmente inválido")
)

// VersionSoportada es el único esquema de manifiesto que este binario sabe
// interpretar. Un Version distinto se rechaza: la evolución del esquema pasa
// por subir esta constante en el binario que lo entiende, jamás por ignorar
// campos que no se reconocen.
const VersionSoportada = 1

// EngineDescriptor describe un motor con su identidad criptográfica.
//
// SizeBytes es puntero a propósito: distingue "campo ausente" (inválido, se
// rechaza) de "archivo de 0 bytes" (legítimo — un archivo vacío tiene el
// SHA-256 del vacío y tamaño 0, y ambos se comparan igual que cualquier otro).
type EngineDescriptor struct {
	ID              string   `json:"id"`
	Version         string   `json:"version"`
	Platform        string   `json:"platform"`
	Path            string   `json:"path"`
	SHA256          string   `json:"sha256"`
	SizeBytes       *int64   `json:"size_bytes"`
	Capabilities    []string `json:"capabilities,omitempty"`
	Languages       []string `json:"languages,omitempty"`
	NetworkRequired bool     `json:"network_required,omitempty"`
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

// validar aplica las reglas estructurales del esquema. Lo que Firmar firma y
// lo que CargarYVerificar acepta pasan por ESTA misma función: un manifiesto
// que no valida no se firma (defecto del release, se descubre al construir)
// y no se acepta (defecto o adulteración, se descubre al cargar).
func (m *Manifest) validar() error {
	if m.Version != VersionSoportada {
		return fmt.Errorf("%w: esquema version=%d, este binario solo entiende %d",
			ErrManifestInvalido, m.Version, VersionSoportada)
	}
	if strings.TrimSpace(m.SignerKeyID) == "" {
		return fmt.Errorf("%w: signer_key_id vacío", ErrManifestInvalido)
	}
	if strings.TrimSpace(m.GeneratedAt) == "" {
		return fmt.Errorf("%w: generated_at vacío", ErrManifestInvalido)
	}
	if len(m.Engines) == 0 {
		return fmt.Errorf("%w: sin motores", ErrManifestInvalido)
	}
	ids := make(map[string]bool, len(m.Engines))
	rutas := make(map[string]string, len(m.Engines))
	for _, e := range m.Engines {
		if strings.TrimSpace(e.ID) == "" {
			return fmt.Errorf("%w: motor con id vacío", ErrManifestInvalido)
		}
		if ids[e.ID] {
			return fmt.Errorf("%w: id duplicado %q (dos descriptores con el mismo nombre: uno taparía al otro)",
				ErrManifestInvalido, e.ID)
		}
		ids[e.ID] = true
		if err := validarRutaRelativa(e.Path); err != nil {
			return fmt.Errorf("%w: motor %s: %v", ErrManifestInvalido, e.ID, err)
		}
		// Colisión case-insensitive: en NTFS dos rutas que solo difieren en
		// mayúsculas nombran el mismo archivo — dos descriptores así son una
		// ambigüedad, y la ambigüedad se rechaza entera (patrón del catálogo
		// de migraciones).
		bajo := strings.ToLower(e.Path)
		if otra, ya := rutas[bajo]; ya {
			return fmt.Errorf("%w: rutas %q y %q colisionan en un filesystem case-insensitive",
				ErrManifestInvalido, otra, e.Path)
		}
		rutas[bajo] = e.Path
		if !esHex64Min(e.SHA256) {
			return fmt.Errorf("%w: motor %s: sha256 debe ser 64 hex minúsculas, tiene %q",
				ErrManifestInvalido, e.ID, e.SHA256)
		}
		if e.SizeBytes == nil {
			return fmt.Errorf("%w: motor %s: size_bytes ausente (0 es un tamaño válido; ausente no)",
				ErrManifestInvalido, e.ID)
		}
		if *e.SizeBytes < 0 {
			return fmt.Errorf("%w: motor %s: size_bytes negativo", ErrManifestInvalido, e.ID)
		}
	}
	return nil
}

// validarRutaRelativa rechaza toda ruta que pueda salirse del árbol del
// artefacto o nombrar algo distinto de lo aparente: absolutas, `..`, ADS de
// NTFS (`:`), y separadores no canónicos (el manifiesto habla en `/`).
func validarRutaRelativa(p string) error {
	if strings.TrimSpace(p) == "" {
		return errors.New("ruta vacía")
	}
	if strings.ContainsAny(p, ":") {
		return fmt.Errorf("ruta %q: absoluta o con ADS (contiene ':')", p)
	}
	if strings.Contains(p, "\\") {
		return fmt.Errorf("ruta %q: separador '\\' — el manifiesto usa '/'", p)
	}
	if strings.HasPrefix(p, "/") {
		return fmt.Errorf("ruta %q: absoluta", p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return fmt.Errorf("ruta %q: contiene '..'", p)
		}
		if seg == "" {
			return fmt.Errorf("ruta %q: segmento vacío", p)
		}
	}
	return nil
}

// CargarYVerificar valida la firma Ed25519 sobre los bytes EXACTOS del
// manifiesto y solo entonces lo parsea (estricto) y valida su estructura.
// Fail-closed en cada paso: clave de tamaño incorrecto, firma de tamaño
// incorrecto, firma inválida, JSON con campos desconocidos o con datos tras
// el primer valor, y estructura inválida son TODOS rechazo — la rama
// "sin clave ⇒ sin verificación" que vivió aquí hasta 2026-08-23 era el
// fail-open que W3 vino a matar.
func CargarYVerificar(manifestJSON []byte, firma []byte, pubKey ed25519.PublicKey) (*Manifest, error) {
	if len(manifestJSON) == 0 {
		return nil, ErrManifestVacio
	}
	if len(pubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: %d bytes, se esperan %d", ErrClaveInvalida, len(pubKey), ed25519.PublicKeySize)
	}
	if len(firma) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: %d bytes, se esperan %d", ErrFirmaMalformada, len(firma), ed25519.SignatureSize)
	}
	if !ed25519.Verify(pubKey, manifestJSON, firma) {
		return nil, ErrFirmaInvalida
	}

	var m Manifest
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
	m.Indexar()
	return &m, nil
}

// CargarYVerificarConClaves resuelve la clave por el signer_key_id del propio
// manifiesto contra el registro de claves embebidas y delega la verificación.
// El id se lee de un parseo PREVIO no confiado (solo para elegir clave); la
// única lectura que cuenta es la de CargarYVerificar, después de la firma.
// Un id que no está en el registro es rechazo (jamás "pruebo con todas").
func CargarYVerificarConClaves(manifestJSON []byte, firma []byte, claves map[string]ed25519.PublicKey) (*Manifest, error) {
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
	return CargarYVerificar(manifestJSON, firma, pub)
}

func esHex64Min(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// cacheItem guarda el resultado reciente de verificación de un archivo.
//
// OJO (doctrina W3, veto de GPT aceptado en el turno 103): este caché de
// mtime+size acelera el CÁLCULO del hash de un archivo suelto, pero jamás
// debe usarse para decidir que una FIRMA sigue válida — un reemplazo del
// mismo tamaño con timestamp restaurado lo evadiría. La verificación de
// árboles firmados re-hashea en cada resolución.
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

// VerificarBinario comprueba que el archivo en ruta coincida con el hash y
// tamaño fijados. Un descriptor incompleto es rechazo, no exención: hasta
// 2026-08-23 un SHA256 vacío o un tamaño 0 SALTABAN su comparación y el
// descriptor vacío validaba cualquier archivo.
func VerificarBinario(ctx context.Context, ruta string, desc EngineDescriptor) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if !esHex64Min(desc.SHA256) {
		return fmt.Errorf("%w: descriptor de %s sin sha256 utilizable (%q)",
			ErrManifestInvalido, desc.ID, desc.SHA256)
	}
	if desc.SizeBytes == nil {
		return fmt.Errorf("%w: descriptor de %s sin size_bytes (0 es válido; ausente no)",
			ErrManifestInvalido, desc.ID)
	}

	hashCalculado, tamano, err := CalcularSHA256(ruta)
	if err != nil {
		return fmt.Errorf("manifest: no se pudo leer el binario %s: %w", ruta, err)
	}

	if tamano != *desc.SizeBytes {
		return fmt.Errorf("%w: obtenido %d, esperado %d para %s",
			ErrTamanoNoCoincide, tamano, *desc.SizeBytes, desc.ID)
	}

	if hashCalculado != desc.SHA256 {
		return fmt.Errorf("%w: obtenido %s, esperado %s para %s",
			ErrHashNoCoincide, hashCalculado, desc.SHA256, desc.ID)
	}

	return nil
}
