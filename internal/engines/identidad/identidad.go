// Package identidad verifica que los motores descargables sean exactamente los
// binarios que publicaron sus autores.
//
// Antes esto era confianza-en-la-primera-vez: el instalador anotaba el hash de
// lo que hubiera bajado y avisaba si cambiaba después. Detectaba el segundo
// ataque, no el primero. Ahora los hashes vienen de los checksums.txt firmados
// de cada release, fijados en motores.json y revisados como código.
//
// Lo que esto NO resuelve: los hashes se copiaron a mano de las releases; una
// verificación de cadena completa exigiría validar las firmas de los
// publicadores (trivy publica atestaciones sigstore; gitleaks no).
package identidad

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

//go:embed motores.json
var manifiestoRaw []byte

type Version struct {
	Version   string `json:"version"`
	Artefacto string `json:"artefacto"`
	URL       string `json:"url"`
	SHA256Zip string `json:"sha256_zip"`
	SHA256Exe string `json:"sha256_exe"`
	Fuente    string `json:"fuente"`
}

type Motor struct {
	// Critico marca los motores cuya manipulación invalida una compuerta de
	// seguridad. Un gitleaks alterado puede callar todos los secretos.
	Critico   bool      `json:"critico"`
	Versiones []Version `json:"versiones"`
}

type manifiesto struct {
	Motores map[string]Motor `json:"motores"`
}

var cargado manifiesto

func init() {
	if err := json.Unmarshal(manifiestoRaw, &cargado); err != nil {
		panic("manifiesto de motores ilegible: " + err.Error()) // es un archivo nuestro, embebido
	}
}

// Estado del binario frente al manifiesto.
type Estado string

const (
	Verificado  Estado = "verificado"   // coincide con una versión publicada
	Desconocido Estado = "desconocido"  // no coincide con ninguna que conozcamos
	Ausente     Estado = "ausente"      // no está instalado
	NoEvaluable Estado = "no-evaluable" // no se pudo leer el archivo
)

type Resultado struct {
	Motor   string
	Ruta    string
	Estado  Estado
	Version string // sólo cuando está verificado
	SHA256  string
	Critico bool
	Detalle string
}

// Bien indica si el binario se puede usar sin reservas.
func (r Resultado) Bien() bool { return r.Estado == Verificado }

// Verificar revisa los motores descargables del directorio dado. Los motores
// de Python (semgrep, squawk, ruff) no entran: los instala pip con sus propias
// firmas y no los distribuimos nosotros.
func Verificar(dirMotores string) []Resultado {
	nombres := make([]string, 0, len(cargado.Motores))
	for n := range cargado.Motores {
		nombres = append(nombres, n)
	}
	// Orden estable: los críticos primero, y dentro de cada grupo alfabético.
	sortNombres(nombres)

	out := make([]Resultado, 0, len(nombres))
	for _, n := range nombres {
		m := cargado.Motores[n]
		ruta := filepath.Join(dirMotores, n+".exe")
		r := Resultado{Motor: n, Ruta: ruta, Critico: m.Critico}

		suma, err := sha256Archivo(ruta)
		switch {
		case os.IsNotExist(err):
			r.Estado = Ausente
			r.Detalle = "no está instalado"
		case err != nil:
			r.Estado = NoEvaluable
			r.Detalle = err.Error()
		default:
			r.SHA256 = suma
			r.Estado = Desconocido
			r.Detalle = "no coincide con ninguna versión publicada que conozcamos"
			for _, v := range m.Versiones {
				if strings.EqualFold(v.SHA256Exe, suma) {
					r.Estado, r.Version, r.Detalle = Verificado, v.Version, ""
					break
				}
			}
		}
		out = append(out, r)
	}
	return out
}

// VersionesConocidas devuelve las versiones publicadas de un motor, para poder
// decir en pantalla cuáles esperábamos.
func VersionesConocidas(motor string) []Version {
	return cargado.Motores[motor].Versiones
}

func sortNombres(n []string) {
	for i := 1; i < len(n); i++ {
		for j := i; j > 0 && menor(n[j], n[j-1]); j-- {
			n[j], n[j-1] = n[j-1], n[j]
		}
	}
}

func menor(a, b string) bool {
	ca, cb := cargado.Motores[a].Critico, cargado.Motores[b].Critico
	if ca != cb {
		return ca // los críticos van primero
	}
	return a < b
}

func sha256Archivo(ruta string) (string, error) {
	f, err := os.Open(ruta)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("no se pudo leer %s: %w", filepath.Base(ruta), err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
