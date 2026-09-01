package trivydb

import (
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
	"sync"
	"time"
)

// Variables y no constantes: las pruebas levantan un registro falso y apuntan
// aquí. El producto nunca las toca.
var (
	registroBase = "https://ghcr.io"
	repositorio  = "aquasecurity/trivy-db"
	etiqueta     = "2"
)

// Clientes propios con plazo: http.DefaultClient no tiene NINGUNO, así que una
// conexión que se queda colgada a media descarga bloquearía la actualización
// para siempre cuando el ctx del llamador no trae deadline —nada obliga a que lo
// traiga—. El ctx sigue mandando cuando lo trae; esto es la red de seguridad
// para cuando no, y Client.Timeout cubre también la lectura del cuerpo.
var (
	clienteCorto = &http.Client{Timeout: 30 * time.Second} // token y manifiestos: JSON de ~1 KB
	clienteLargo = &http.Client{Timeout: 10 * time.Minute} // el blob: ~60 MB hoy, con margen
)

// muActualizar evita que dos goroutines de ESTE proceso se pongan a descargar la
// misma base de 1.2 GB a la vez: es ahorro, no la garantía de integridad.
//
// La integridad la da el diseño de las rutas, y esa es la parte que importa: cada
// llamada extrae en su propio directorio (db.nuevo-*) y aparta la base anterior
// en un respaldo derivado de ese mismo nombre, así que no queda ninguna ruta de
// trabajo compartida entre procesos. Antes sí las había —db.nuevo y db.viejo
// fijas— y este mutex no podía protegerlas: un daemon viejo y uno nuevo, o el
// daemon y el CLI, se borraban el directorio a medio extraer.
//
// Es un mutex de proceso y NO un candado en disco a propósito: un candado con
// O_EXCL sobrevive a un proceso muerto —un kill deja el archivo y a partir de ahí
// NINGUNA actualización vuelve a funcionar hasta que alguien lo borre a mano, que
// es un modo de fallo peor que la carrera que evita.
var muActualizar sync.Mutex

const (
	topeManifiesto = 1 << 20 // 1 MB: un índice o manifiesto OCI real ocupa ~1 KB
	topeBlob       = 1 << 30 // 1 GB comprimido: la base ronda 60 MB hoy
	topeBlobJava   = 2 << 30 // 2 GB comprimidos: java-db ronda 1 GB hoy
	topeArchivo    = 8 << 30 // 8 GB por archivo extraído: trivy.db ronda 1.2 GB
)

type fuenteOCI struct {
	repositorio, etiqueta, tipoCapa string
	directorio, prefijoTemporal     string
	archivos                        map[string]bool
	topeBlob                        int64
}

func fuenteVulnerabilidades() fuenteOCI {
	return fuenteOCI{
		repositorio: repositorio, etiqueta: etiqueta,
		tipoCapa: "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip", directorio: "db", prefijoTemporal: "db",
		archivos: map[string]bool{"trivy.db": true, "metadata.json": true},
		topeBlob: topeBlob,
	}
}

func fuenteJava() fuenteOCI {
	return fuenteOCI{
		repositorio: "aquasecurity/trivy-java-db", etiqueta: "1",
		tipoCapa: "application/vnd.aquasec.trivy.javadb.layer.v1.tar+gzip", directorio: "java-db", prefijoTemporal: "java-db",
		archivos: map[string]bool{"trivy-java.db": true, "metadata.json": true},
		topeBlob: topeBlobJava,
	}
}

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

// DirCache es donde trivy espera su base: %LOCALAPPDATA%/trivy en Windows.
// Se calcula aquí —el paquete dueño de la base— y no se recibe por
// configuración porque tiene que coincidir EXACTAMENTE con donde trivy la va
// a leer. Lo comparten el motor de trivy y la auditoría de identidad: dos
// cálculos separados era la receta para bajar la base a un sitio y leerla de
// otro.
func DirCache() (string, error) {
	if base := os.Getenv("LOCALAPPDATA"); base != "" {
		return filepath.Join(base, "trivy"), nil
	}
	home, err := os.UserCacheDir()
	if err != nil {
		// Un error ignorado aquí dejaba pasar una ruta RELATIVA:
		// Join("", "trivy") da "trivy", que se resuelve contra el directorio
		// de trabajo, así que la base se bajaba y se comprobaba en un sitio
		// distinto del que trivy lee. Se falla explícito en vez de operar
		// sobre una ruta ambigua.
		return "", fmt.Errorf("no se pudo resolver el directorio de caché del usuario: %w", err)
	}
	return filepath.Join(home, "trivy"), nil
}

// Actualizar refresca la base de trivy en <dirTrivy>/db (el layout que trivy
// espera: trivy.db + metadata.json). El reemplazo es atómico: se extrae a un
// directorio aparte y sólo se intercambia cuando todo está verificado — un
// fallo a medias deja la base anterior intacta.
func Actualizar(ctx context.Context, dirTrivy string) error {
	return actualizar(ctx, dirTrivy, fuenteVulnerabilidades())
}

// ActualizarJava refresca la base de índices Java en <dirTrivy>/java-db con
// las mismas garantías OCI, digest y reemplazo atómico que Actualizar.
func ActualizarJava(ctx context.Context, dirTrivy string) error {
	return actualizar(ctx, dirTrivy, fuenteJava())
}

func actualizar(ctx context.Context, dirTrivy string, fuente fuenteOCI) error {
	// Una actualización a la vez: ver muActualizar. Se toma antes de pedir el
	// token para no bajar dos veces el mismo gigabyte.
	muActualizar.Lock()
	defer muActualizar.Unlock()

	token, err := pedirToken(ctx, fuente.repositorio)
	if err != nil {
		return fmt.Errorf("token del registro: %w", err)
	}

	// El primer documento llega por etiqueta (mutable: es como se publica la
	// base nueva). Si es un índice, el manifiesto que nombra sí se verifica
	// contra su digest.
	crudo, err := pedirManifiesto(ctx, token, fuente.repositorio, fuente.etiqueta)
	if err != nil {
		return fmt.Errorf("manifiesto: %w", err)
	}
	var doc manifiestoOCI
	if err := json.Unmarshal(crudo, &doc); err != nil {
		return fmt.Errorf("manifiesto ilegible: %w", err)
	}
	if len(doc.Manifests) > 0 { // era un índice
		digest := doc.Manifests[0].Digest
		crudo, err = pedirManifiesto(ctx, token, fuente.repositorio, digest)
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
		if l.MediaType == fuente.tipoCapa {
			capa = l.Digest
			break
		}
	}
	if capa == "" {
		return fmt.Errorf("el manifiesto de %s no trae la capa esperada (capas: %d)", fuente.repositorio, len(doc.Layers))
	}

	// El blob se hashea MIENTRAS baja y no se abre hasta que coincide.
	if err := os.MkdirAll(dirTrivy, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dirTrivy, fuente.prefijoTemporal+"-descarga-*.tgz")
	if err != nil {
		return err
	}
	defer func() { tmp.Close(); os.Remove(tmp.Name()) }()

	if err := bajarBlob(ctx, token, fuente.repositorio, capa, fuente.topeBlob, tmp); err != nil {
		return fmt.Errorf("blob de la base: %w", err)
	}

	// Verificado: ahora sí se abre. La extracción va a un directorio ÚNICO por
	// llamada, no al fijo db.nuevo. Con ruta fija, el mutex sólo ordenaba a las
	// goroutines de ESTE proceso: un segundo proceso —un daemon viejo y uno
	// nuevo, o el daemon y el CLI— hacía RemoveAll del directorio que el otro
	// estaba extrayendo, y el rename final podía colocar en db una base a
	// medias. En un motor bloqueante eso es lo peor que puede pasar.
	//
	// Con directorio propio no hay estado compartido mutable: lo único que se
	// comparte son renames de directorios YA completos, cuyo solape se resuelve
	// como error y nunca como base corrupta.
	purgarExtraccionesHuerfanasDe(dirTrivy, fuente.prefijoTemporal+".nuevo-")
	nuevo, err := os.MkdirTemp(dirTrivy, fuente.prefijoTemporal+".nuevo-*")
	if err != nil {
		return fmt.Errorf("directorio de extracción: %w", err)
	}
	if err := extraerBase(tmp.Name(), nuevo, fuente.archivos); err != nil {
		_ = os.RemoveAll(nuevo)
		return fmt.Errorf("extrayendo la base: %w", err)
	}

	if err := intercambiarBase(dirTrivy, nuevo, fuente.directorio); err != nil {
		// Si el intercambio no llegó a hacerse, la extracción sigue en disco y
		// ahora tiene nombre único: se borra aquí para no acumular. Si tuvo
		// éxito, `nuevo` ya no existe y esto es un no-op.
		_ = os.RemoveAll(nuevo)
		return err
	}
	return nil
}

func pedirToken(ctx context.Context, repo string) (string, error) {
	url := registroBase + "/token?service=ghcr.io&scope=repository:" + repo + ":pull"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	resp, err := clienteCorto.Do(req)
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

func pedirManifiesto(ctx context.Context, token, repo, ref string) ([]byte, error) {
	url := registroBase + "/v2/" + repo + "/manifests/" + ref
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
	resp, err := clienteCorto.Do(req)
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

func bajarBlob(ctx context.Context, token, repo, digest string, limite int64, destino *os.File) error {
	url := registroBase + "/v2/" + repo + "/blobs/" + digest
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := clienteLargo.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(destino, h), io.LimitReader(resp.Body, limite+1))
	if err != nil {
		return err
	}
	if n > limite {
		return fmt.Errorf("el blob pasa de %d bytes", limite)
	}
	if got := "sha256:" + hex.EncodeToString(h.Sum(nil)); got != digest {
		return fmt.Errorf("el contenido no coincide con su digest: llegó %s y el manifiesto nombra %s — se descarta sin abrir", got, digest)
	}
	// Volver al principio para que el extractor lea el archivo verificado.
	_, err = destino.Seek(0, io.SeekStart)
	return err
}
