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
	"sort"
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
	// Instalado es lo que queda EN el directorio de motores tras instalar esta
	// versión, relativo a él. Vacío = "<motor>.exe", que es el caso de gitleaks
	// y trivy: un zip con un ejecutable dentro.
	//
	// Existe porque los motores de Java no son un .exe. google-java-format se
	// instala como el .jar publicado tal cual, y PMD como el ÁRBOL que trae su
	// zip (104 jars en 7.26.0): sin este campo, `codeguard engines` los buscaría
	// como pmd.exe, no los encontraría nunca y diría "no instalado" con los dos
	// funcionando — una mentira pequeña que envenena el único sitio donde se
	// mira si los motores son los que publicaron sus autores.
	//
	// Va por VERSIÓN y no por motor porque el nombre lleva la versión dentro
	// (pmd-bin-7.26.0): así conviven dos durante una actualización, que es lo
	// mismo que ya permite el arreglo de versiones.
	Instalado string `json:"instalado"`
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

// Verificar revisa los motores descargables del directorio dado. Los motores
// de Python (semgrep, squawk, ruff, mypy) no entran: los instala pip con sus
// propias
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
		out = append(out, verificarMotor(dirMotores, n, cargado.Motores[n]))
	}
	return out
}

// verificarMotor prueba la ruta de instalación de CADA versión conocida y se
// queda con la primera que exista.
//
// Recorrer las versiones —y no una ruta fija— es lo que permite que un motor se
// instale con la versión en el nombre (pmd-bin-7.26.0). Para gitleaks y trivy no
// cambia nada: sin campo "instalado" todas sus versiones apuntan al mismo
// <motor>.exe, así que la primera existente es esa y el comportamiento es el de
// siempre, incluido reportar Desconocido cuando el archivo está pero su hash no
// coincide con ninguno.
func verificarMotor(dirMotores, nombre string, m Motor) Resultado {
	r := Resultado{Motor: nombre, Critico: m.Critico}
	// Cuando no hay nada instalado, la ruta que se enseña es la de la versión
	// más reciente que conocemos: es donde debería estar.
	r.Ruta = filepath.Join(dirMotores, rutaInstalada(nombre, ultima(m.Versiones)))

	for _, v := range m.Versiones {
		ruta := filepath.Join(dirMotores, rutaInstalada(nombre, v))
		suma, err := huellaDe(ruta)
		if os.IsNotExist(err) {
			continue
		}
		r.Ruta = ruta
		if err != nil {
			r.Estado, r.Detalle = NoEvaluable, err.Error()
			return r
		}
		r.SHA256 = suma
		if strings.EqualFold(v.SHA256Exe, suma) {
			r.Estado, r.Version = Verificado, v.Version
			return r
		}
		r.Estado = Desconocido
		r.Detalle = "no coincide con ninguna versión publicada que conozcamos"
		return r
	}
	r.Estado, r.Detalle = Ausente, "no está instalado"
	return r
}

// rutaInstalada es lo que el instalador deja en el directorio de motores para
// esta versión. Sin campo "instalado" es <motor>.exe, la forma de gitleaks y
// trivy.
func rutaInstalada(nombre string, v Version) string {
	if v.Instalado != "" {
		return filepath.FromSlash(v.Instalado)
	}
	return nombre + ".exe"
}

func ultima(vs []Version) Version {
	if len(vs) == 0 {
		return Version{}
	}
	return vs[len(vs)-1]
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

// huellaDe resume lo instalado en un solo hash: el del archivo, o el del ÁRBOL
// entero si es un directorio.
func huellaDe(ruta string) (string, error) {
	st, err := os.Stat(ruta)
	if err != nil {
		return "", err
	}
	if st.IsDir() {
		return HuellaArbol(ruta)
	}
	return sha256Archivo(ruta)
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

// HuellaArbol resume un directorio entero en un hash: para cada archivo, su ruta
// relativa (con /) y el sha de su contenido, ordenados y encadenados.
//
// Hace falta porque PMD no es un ejecutable sino un árbol de 104 jars, y
// verificar uno solo de ellos —el lanzador, o pmd-core— daría una sensación de
// cobertura que no existe: las reglas de Java viven en otro jar y una regla
// silenciada no se notaría. Un hash de UN archivo sobre un motor de muchos es
// justo el tipo de verificación a medias que este paquete existe para no hacer.
//
// La construcción es la misma que engines.HuellaModulo usa para las claves de
// caché (ruta:sha por línea, ordenadas, y sha del conjunto). El instalador la
// reproduce en PowerShell para verificar el árbol recién extraído ANTES de
// dejarlo en su sitio, así que cualquier cambio aquí hay que hacerlo también
// allí — están atados a propósito, y por eso el formato es lo más simple que se
// puede escribir dos veces sin equivocarse.
//
// Sólo entra el contenido: ni fechas, ni permisos, ni el orden del zip. Es lo
// que hace que dos extracciones del mismo artefacto den el mismo hash en
// cualquier máquina.
func HuellaArbol(raiz string) (string, error) {
	var lineas []string
	err := filepath.WalkDir(raiz, func(ruta string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(raiz, ruta)
		if err != nil {
			return err
		}
		suma, err := sha256Archivo(ruta)
		if err != nil {
			return err
		}
		lineas = append(lineas, filepath.ToSlash(rel)+":"+suma)
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(lineas)
	sum := sha256.Sum256([]byte(strings.Join(lineas, "\n")))
	return hex.EncodeToString(sum[:]), nil
}
