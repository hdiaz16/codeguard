// Package finding define el modelo de hallazgos del contrato (sección 8 de la spec).
package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
)

type Severity string

const (
	Info    Severity = "info"
	Warning Severity = "warning"
	Error   Severity = "error"
)

type Source string

const (
	Deterministic Source = "deterministic"
	LLM           Source = "llm"
)

type Pillar string

const (
	Quality  Pillar = "quality"
	Security Pillar = "security"
	Data     Pillar = "data"
)

type Finding struct {
	ID          string   `json:"id"`
	Engine      string   `json:"engine"`
	RuleKey     string   `json:"rule_id"`
	Pillar      Pillar   `json:"pillar"`
	Severity    Severity `json:"severity"`
	Blocking    bool     `json:"blocking"`
	File        string   `json:"file"`
	Line        int      `json:"line"`
	EndLine     int      `json:"end_line,omitempty"`
	Message     string   `json:"message"`
	Why         string   `json:"why,omitempty"`
	FixHint     string   `json:"fix_hint,omitempty"`
	Verified    bool     `json:"verified"`
	Source      Source   `json:"source"`
	Fingerprint string   `json:"-"`
	// LineContent es el contenido de la línea señalada, usado solo para el fingerprint.
	LineContent string `json:"-"`
}

// ComputeFingerprint implementa la clave de supresión de la sección 9:
// sha256(rule_key + ruta_normalizada + contenido_normalizado_de_la_linea).
// Sin número de línea, para que sobreviva desplazamientos del archivo.
func (f *Finding) ComputeFingerprint() string {
	path := filepath.ToSlash(f.File)
	content := strings.TrimSpace(f.LineContent)
	h := sha256.Sum256([]byte(f.RuleKey + "\x00" + path + "\x00" + content))
	f.Fingerprint = hex.EncodeToString(h[:])
	return f.Fingerprint
}

// Normalizar corrige invariantes del Finding in situ:
//   - Line y EndLine negativas se elevan a 0.
//   - Si EndLine < Line, EndLine se iguala a Line.
func (f *Finding) Normalizar() {
	if f.Line < 0 {
		f.Line = 0
	}
	if f.EndLine < 0 {
		f.EndLine = 0
	}
	if f.EndLine < f.Line {
		f.EndLine = f.Line
	}
}

// HuellaCorta devuelve los primeros n bytes de una huella (hash),
// con guarda de longitud para evitar panics por slice out-of-bounds.
func HuellaCorta(h string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(h) <= n {
		return h
	}
	return h[:n]
}
