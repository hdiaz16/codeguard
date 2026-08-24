// Package rulepack da IDENTIDAD verificable al rulepack (W3, diseño firmado
// en plan-calidad-mundial t.95-105): qué árbol de reglas corrió, de dónde
// salió y con qué digest — para que "2026.08.2" deje de ser un string que se
// cree por fe. El caso que motivó todo está medido en esta misma máquina:
// tres copias del mismo nombre de versión con dos contenidos distintos (161
// reglas en el repo, 130 instaladas) y ningún lector que lo note.
package rulepack

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Source dice de dónde salió el rulepack resuelto.
type Source string

const (
	// SourceInstalled: junto al binario o en la instalación estándar del
	// usuario — el artefacto DISTRIBUIDO, el que la tanda (c) exigirá firmado.
	SourceInstalled Source = "installed"
	// SourceVendored: dentro del repo analizado. No se le exige firma (son
	// las reglas del propio equipo) pero se DICE y su digest se estampa igual.
	SourceVendored Source = "vendored"
)

// Identity es la identidad resuelta de un rulepack: viaja en el resultado del
// análisis, el cable IPC y la fila de runs. Un lector viejo que no la conozca
// la ignora (aditiva); su ausencia se lee como legacy/unverified, jamás como
// fallo del análisis (t.103).
type Identity struct {
	// Path es el directorio resuelto (absoluto).
	Path string `json:"path"`
	// Version es la versión pinneada por config — el NOMBRE. El digest existe
	// porque el nombre, medido, puede mentir.
	Version string `json:"version"`
	// Digest es el sha256 hex del árbol (DigestArbol), "" si no se pudo
	// calcular (rulepack ausente o ilegible — el error del resolver dice why).
	Digest string `json:"digest,omitempty"`
	// Source: installed | vendored.
	Source Source `json:"source"`
	// Verified: el manifiesto firmado del árbol verificó (tanda c). Hoy
	// siempre false: calcular un digest NO es verificar una firma, y este
	// campo no miente.
	Verified bool `json:"verified"`
}

var (
	ErrNoEncontrado  = errors.New("rulepack: la versión pinneada no está en ningún candidato")
	ErrArbolInvalido = errors.New("rulepack: el árbol contiene entradas que un rulepack no puede tener")
)

// dominioDigest versiona el FORMATO del digest: si algún día cambia qué bytes
// entran o cómo se separan, cambia este prefijo y los digests viejos dejan de
// compararse por accidente con los nuevos.
const dominioDigest = "codeguard-rulepack-tree-v1"

// podas: lo que NO entra al digest, y por qué cada cosa.
//   - testdata: no se distribuye (build-dist.ps1 lo poda del instalador —
//     rulepacks/<ver>/testdata/README.md:30); hashearlo haría divergir el
//     digest del repo contra el del instalado con contenido IDÉNTICO de reglas.
//   - manifest.json / manifest.sig: autorreferencia — el manifiesto firma el
//     árbol, no puede firmarse a sí mismo. Solo se excluyen en la RAÍZ.
func excluido(rel string, esDir bool) bool {
	if esDir {
		return rel == "testdata"
	}
	return rel == "manifest.json" || rel == "manifest.sig"
}

// DigestArbol calcula el sha256 del árbol COMPLETO del rulepack sobre los
// bytes EXACTOS de cada archivo (veto de GPT t.103 a normalizar EOL: la
// identidad autentica lo distribuido; un flip CRLF↔LF es un cambio real y se
// dice). Formato, con separadores \x00 que ningún nombre de archivo legal
// contiene:
//
//	sha256( dominio \x00 (ruta-slash \x00 tamaño-decimal \x00 sha256-hex-del-contenido \x00)* )
//
// con las rutas relativas en forma slash, ordenadas con sort.Strings — la
// grafía EXACTA que emite el filesystem, sin case-folding (condición de Kimi
// t.98: normalizar mayúsculas escondería una divergencia real entre lo
// firmado y lo instalado en NTFS).
//
// Fail-closed sobre el árbol: symlinks/junctions o cualquier entrada que no
// sea archivo regular o directorio = error con nombre (una fuga apuntando
// fuera del árbol hashearía contenido no firmado); dos rutas que colisionan
// bajo EqualFold = error (en un filesystem case-insensitive nombran lo
// mismo); árbol sin un solo archivo = error (un digest de la nada no
// identifica nada).
func DigestArbol(dir string) (string, error) {
	archivos, err := Inventario(dir)
	if err != nil {
		return "", err
	}
	return DigestDeInventario(archivos), nil
}

// ArchivoDelArbol es una entrada del inventario: la ruta slash relativa, el
// hash de sus bytes exactos y su tamaño.
type ArchivoDelArbol struct {
	Rel    string
	SHA256 string
	Size   int64
}

// Inventario es LA caminata del árbol: la única (el digest y el firmador de
// release construyen sobre ella — dos caminatas separadas divergirían un
// día). Aplica las podas y el fail-closed documentados en DigestArbol, y
// re-hashea completo en cada llamada, sin caché por mtime (veto de GPT
// t.103: un reemplazo del mismo tamaño con timestamp restaurado evadiría un
// caché así).
func Inventario(dir string) ([]ArchivoDelArbol, error) {
	type entrada struct {
		rel  string
		ruta string
	}
	var archivos []entrada
	vistasBajo := map[string]string{}

	err := filepath.WalkDir(dir, func(ruta string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(dir, ruta)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if !d.Type().IsRegular() && !d.IsDir() {
			return fmt.Errorf("%w: %s no es archivo regular ni directorio (¿symlink/junction?)",
				ErrArbolInvalido, rel)
		}
		if excluido(rel, d.IsDir()) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		bajo := strings.ToLower(rel)
		if otra, ya := vistasBajo[bajo]; ya {
			return fmt.Errorf("%w: %q y %q colisionan en un filesystem case-insensitive",
				ErrArbolInvalido, otra, rel)
		}
		vistasBajo[bajo] = rel
		archivos = append(archivos, entrada{rel: rel, ruta: ruta})
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(archivos) == 0 {
		return nil, fmt.Errorf("%w: sin un solo archivo bajo %s", ErrArbolInvalido, dir)
	}

	sort.Slice(archivos, func(i, j int) bool { return archivos[i].rel < archivos[j].rel })

	out := make([]ArchivoDelArbol, 0, len(archivos))
	for _, a := range archivos {
		hexContenido, tam, err := hashArchivo(a.ruta)
		if err != nil {
			return nil, fmt.Errorf("rulepack: no se pudo leer %s: %w", a.rel, err)
		}
		out = append(out, ArchivoDelArbol{Rel: a.rel, SHA256: hexContenido, Size: tam})
	}
	return out, nil
}

// DigestDeInventario compone el digest del árbol a partir del inventario ya
// calculado (mismo formato documentado arriba).
func DigestDeInventario(archivos []ArchivoDelArbol) string {
	h := sha256.New()
	h.Write([]byte(dominioDigest))
	h.Write([]byte{0})
	for _, a := range archivos {
		h.Write([]byte(a.Rel))
		h.Write([]byte{0})
		h.Write([]byte(strconv.FormatInt(a.Size, 10)))
		h.Write([]byte{0})
		h.Write([]byte(a.SHA256))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func hashArchivo(ruta string) (string, int64, error) {
	f, err := os.Open(ruta)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
