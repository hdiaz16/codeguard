// Package trivydb baja la base de vulnerabilidades de trivy SIN pasar por
// oras-go.
//
// trivy trae dentro oras.land/oras-go para bajarse su base desde ghcr.io, y esa
// librería arrastra un CVE sin versión corregida publicada (la excepción #6 del
// archivo de excepciones). Era la ÚNICA de las seis con una ruta de red viva:
// datos que llegan de un registro remoto y se procesan con código vulnerable,
// cada vez que la base se refresca.
//
// La salida no es dejar de actualizar —una base vieja envejece la detección de
// CVE, que es exactamente lo que trivy aporta— sino que la actualización no
// pase por el código vulnerable: CodeGuard habla el protocolo OCI él mismo, con
// net/http de la librería estándar, y trivy corre SIEMPRE con --skip-db-update.
//
// El modelo de confianza queda escrito para que nadie lo suponga distinto:
//
//   - El ancla es TLS contra ghcr.io. La etiqueta ("2") es mutable a propósito
//     —la base se publica nueva cada seis horas— así que el primer documento no
//     tiene digest contra el que verificarse. Es el mismo ancla que usa oras.
//   - De ahí hacia abajo, TODO es contenido-direccionado y se verifica: el
//     manifiesto que el índice nombra se compara contra su digest, y el blob de
//     la base se hashea MIENTRAS se descarga y se compara contra el digest que
//     lista el manifiesto verificado. Nada se abre —ni gzip ni tar— antes de
//     que su hash coincida.
//   - Lo que sí parseamos de datos remotos: dos JSON pequeños con tope de 1 MB
//     (encoding/json), y un tar.gz YA VERIFICADO (compress/gzip + archive/tar,
//     con lista blanca de nombres y topes de tamaño). Esa superficie es
//     deliberadamente mínima comparada con un cliente OCI completo.
package trivydb

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// Variables y no constantes: las pruebas levantan un registro falso y apuntan
// aquí. El producto nunca las toca.
var (
	registroBase = "https://ghcr.io"
	repositorio  = "aquasecurity/trivy-db"
	etiqueta     = "2"
)

const (
	topeManifiesto = 1 << 20 // 1 MB: un índice o manifiesto OCI real ocupa ~1 KB
	topeBlob       = 1 << 30 // 1 GB comprimido: la base ronda 60 MB hoy
	topeArchivo    = 8 << 30 // 8 GB por archivo extraído: trivy.db ronda 1.2 GB
)

type manifiestoOCI struct {
	MediaType string `json:"mediaType"`
	Manifests []struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
	} `json:"manifests"` // presente cuando el documento es un índice
	Layers []struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int64  `json:"size"`
	} `json:"layers"` // presente cuando es un manifiesto
}

// Actualizar refresca la base de trivy en <dirTrivy>/db (el layout que trivy
// espera: trivy.db + metadata.json). El reemplazo es atómico: se extrae a un
// directorio aparte y sólo se intercambia cuando todo está verificado — un
// fallo a medias deja la base anterior intacta.
func Actualizar(ctx context.Context, dirTrivy string) error {
	token, err := pedirToken(ctx)
	if err != nil {
		return fmt.Errorf("token del registro: %w", err)
	}

	// El primer documento llega por etiqueta (mutable: es como se publica la
	// base nueva). Si es un índice, el manifiesto que nombra sí se verifica
	// contra su digest.
	crudo, err := pedirManifiesto(ctx, token, etiqueta)
	if err != nil {
		return fmt.Errorf("manifiesto: %w", err)
	}
	var doc manifiestoOCI
	if err := json.Unmarshal(crudo, &doc); err != nil {
		return fmt.Errorf("manifiesto ilegible: %w", err)
	}
	if len(doc.Manifests) > 0 { // era un índice
		digest := doc.Manifests[0].Digest
		crudo, err = pedirManifiesto(ctx, token, digest)
		if err != nil {
			return fmt.Errorf("manifiesto del índice: %w", err)
		}
		if got := digestDe(crudo); got != digest {
			return fmt.Errorf("el manifiesto no coincide con su digest: llegó %s y el índice nombra %s", got, digest)
		}
		doc = manifiestoOCI{}
		if err := json.Unmarshal(crudo, &doc); err != nil {
			return fmt.Errorf("manifiesto ilegible: %w", err)
		}
	}

	capa := ""
	for _, l := range doc.Layers {
		if strings.Contains(l.MediaType, "trivy.db.layer") {
			capa = l.Digest
			break
		}
	}
	if capa == "" {
		return fmt.Errorf("el manifiesto no trae ninguna capa de base de trivy (capas: %d)", len(doc.Layers))
	}

	// El blob se hashea MIENTRAS baja y no se abre hasta que coincide.
	if err := os.MkdirAll(dirTrivy, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dirTrivy, "db-descarga-*.tgz")
	if err != nil {
		return err
	}
	defer func() { tmp.Close(); os.Remove(tmp.Name()) }()

	if err := bajarBlob(ctx, token, capa, tmp); err != nil {
		return fmt.Errorf("blob de la base: %w", err)
	}

	// Verificado: ahora sí se abre. La extracción va a un directorio aparte.
	nuevo := filepath.Join(dirTrivy, "db.nuevo")
	_ = os.RemoveAll(nuevo)
	if err := extraer(tmp.Name(), nuevo); err != nil {
		_ = os.RemoveAll(nuevo)
		return fmt.Errorf("extrayendo la base: %w", err)
	}

	return intercambiar(dirTrivy, nuevo)
}

func pedirToken(ctx context.Context) (string, error) {
	url := registroBase + "/token?service=ghcr.io&scope=repository:" + repositorio + ":pull"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var t struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, topeManifiesto)).Decode(&t); err != nil {
		return "", err
	}
	if t.Token == "" {
		return "", fmt.Errorf("el registro no devolvió token")
	}
	return t.Token, nil
}

func pedirManifiesto(ctx context.Context, token, ref string) ([]byte, error) {
	url := registroBase + "/v2/" + repositorio + "/manifests/" + ref
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", strings.Join([]string{
		"application/vnd.oci.image.index.v1+json",
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.docker.distribution.manifest.v2+json",
	}, ", "))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	// LimitReader con tope+1: si el documento LLEGA al tope es sospechoso de
	// haberse cortado (o de ser gigante a propósito) y se rechaza entero.
	crudo, err := io.ReadAll(io.LimitReader(resp.Body, topeManifiesto+1))
	if err != nil {
		return nil, err
	}
	if len(crudo) > topeManifiesto {
		return nil, fmt.Errorf("el manifiesto pasa de %d bytes", topeManifiesto)
	}
	return crudo, nil
}

func bajarBlob(ctx context.Context, token, digest string, destino *os.File) error {
	url := registroBase + "/v2/" + repositorio + "/blobs/" + digest
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(destino, h), io.LimitReader(resp.Body, topeBlob+1))
	if err != nil {
		return err
	}
	if n > topeBlob {
		return fmt.Errorf("el blob pasa de %d bytes", int64(topeBlob))
	}
	if got := "sha256:" + hex.EncodeToString(h.Sum(nil)); got != digest {
		return fmt.Errorf("el contenido no coincide con su digest: llegó %s y el manifiesto nombra %s — se descarta sin abrir", got, digest)
	}
	// Volver al principio para que el extractor lea el archivo verificado.
	_, err = destino.Seek(0, io.SeekStart)
	return err
}

// extraer abre el tar.gz YA VERIFICADO y saca sólo lo que la base de trivy
// puede contener. Lista blanca y no lista negra: un nombre que no se reconoce
// se rechaza entero, incluida cualquier ruta con separadores o "..".
func extraer(rutaTgz, destino string) error {
	f, err := os.Open(rutaTgz)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	if err := os.MkdirAll(destino, 0o755); err != nil {
		return err
	}

	permitidos := map[string]bool{"trivy.db": true, "metadata.json": true}
	vistos := map[string]bool{}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		nombre := strings.TrimPrefix(hdr.Name, "./")
		if !permitidos[nombre] {
			return fmt.Errorf("el tar trae %q, que la base de trivy no contiene — se descarta entero", hdr.Name)
		}
		out, err := os.Create(filepath.Join(destino, nombre))
		if err != nil {
			return err
		}
		n, err := io.Copy(out, io.LimitReader(tr, topeArchivo+1))
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
		if n > topeArchivo {
			return fmt.Errorf("%s pasa de %d bytes", nombre, int64(topeArchivo))
		}
		vistos[nombre] = true
	}
	for nombre := range permitidos {
		if !vistos[nombre] {
			return fmt.Errorf("el tar no trae %s", nombre)
		}
	}
	return nil
}

// intercambiar mete la base nueva en su sitio con el menor hueco posible: la
// vieja se aparta, la nueva entra, la vieja se borra. Si el rename falla —en
// Windows pasa si un trivy está leyendo la base en ese instante— se restaura
// la anterior y el siguiente ciclo lo reintenta.
func intercambiar(dirTrivy, nuevo string) error {
	db := filepath.Join(dirTrivy, "db")
	viejo := filepath.Join(dirTrivy, "db.viejo")
	_ = os.RemoveAll(viejo)

	hayVieja := false
	if _, err := os.Stat(db); err == nil {
		hayVieja = true
		if err := os.Rename(db, viejo); err != nil {
			return fmt.Errorf("no se pudo apartar la base anterior (¿trivy corriendo?): %w", err)
		}
	}
	if err := os.Rename(nuevo, db); err != nil {
		if hayVieja {
			_ = os.Rename(viejo, db) // restaurar: mejor base vieja que ninguna
		}
		return fmt.Errorf("no se pudo colocar la base nueva: %w", err)
	}
	_ = os.RemoveAll(viejo)
	return nil
}

func digestDe(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}
