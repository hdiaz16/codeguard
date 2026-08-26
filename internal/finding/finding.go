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
	// LegacyFingerprint es el alias v1 de la huella (huella.go): existe SOLO
	// durante la ventana dual de la migración a v2, para que una baseline
	// escrita por el binario anterior siga suprimiendo. Nunca es identidad
	// primaria. json:"-" como Fingerprint y por lo mismo; el cable y la BD
	// lo llevan por sus campos propios.
	LegacyFingerprint string `json:"-"`
	// HuellaAmbigua marca que OTRO hallazgo de la misma corrida produjo la
	// misma huella (mismo texto y mismo contexto): ninguno de los dos se
	// suprime ni entra a la baseline — la falla va hacia bloquear, jamás
	// hacia enterrar una ocurrencia bajo la aceptación de otra.
	HuellaAmbigua bool `json:"-"`
	// Identidad dice de QUÉ se hace la huella de este hallazgo (W6, t.128):
	//   - Linea: la línea real de código (la mayoría). Si el parser no la trae,
	//     el finalizador (AsignarHuellas) la lee del archivo.
	//   - Semantica: un valor canónico que NO es la línea (trivy pkg@version,
	//     govulncheck módulo@símbolo, gofmt/javafmt ruta, playbook centinela);
	//     el parser lo pone en LineContent y el finalizador lo respeta.
	//   - NoDisponible: era clase Linea pero la línea no se pudo leer (archivo
	//     borrado, fuera de rango). No genera huella SUPRIMIBLE (NoSuprimible):
	//     queda visible como identidad incompleta y jamás entierra código nuevo.
	// El cero es Linea a propósito: un motor que no declara nada usa la línea,
	// que es el lado seguro; los semánticos DEBEN declararse.
	Identidad TipoIdentidad `json:"-"`
	// NoSuprimible: el hallazgo NO puede baselinarse (identidad incompleta).
	// La baseline lo salta y la supresión lo ignora.
	NoSuprimible bool `json:"-"`
}

// TipoIdentidad clasifica de qué se hace la huella (ver Finding.Identidad).
type TipoIdentidad uint8

const (
	IdentidadLinea TipoIdentidad = iota
	IdentidadSemantica
	IdentidadNoDisponible
)

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

