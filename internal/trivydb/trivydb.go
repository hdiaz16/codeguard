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
	// Una actualización a la vez: ver muActualizar. Se toma antes de pedir el
	// token para no bajar dos veces el mismo gigabyte.
	muActualizar.Lock()
	defer muActualizar.Unlock()

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
	purgarExtraccionesHuerfanas(dirTrivy)
	nuevo, err := os.MkdirTemp(dirTrivy, "db.nuevo-*")
	if err != nil {
		return fmt.Errorf("directorio de extracción: %w", err)
	}
	if err := extraer(tmp.Name(), nuevo); err != nil {
		_ = os.RemoveAll(nuevo)
		return fmt.Errorf("extrayendo la base: %w", err)
	}

	if err := intercambiar(dirTrivy, nuevo); err != nil {
		// Si el intercambio no llegó a hacerse, la extracción sigue en disco y
		// ahora tiene nombre único: se borra aquí para no acumular. Si tuvo
		// éxito, `nuevo` ya no existe y esto es un no-op.
		_ = os.RemoveAll(nuevo)
		return err
	}
	return nil
}

func pedirToken(ctx context.Context) (string, error) {
	url := registroBase + "/token?service=ghcr.io&scope=repository:" + repositorio + ":pull"
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

func bajarBlob(ctx context.Context, token, digest string, destino *os.File) error {
	url := registroBase + "/v2/" + repositorio + "/blobs/" + digest
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
	// El apartado también cuelga del directorio único de esta llamada, y NO de
	// un "db.viejo" compartido. Con la ruta fija quedaba una carrera fina entre
	// procesos: el RemoveAll de abajo borraba el respaldo que el OTRO proceso
	// acababa de apartar, y si a ese otro le fallaba el rename de colocación
	// —el caso documentado de un trivy leyendo la base en Windows— su
	// restauración no encontraba nada y db se quedaba AUSENTE. Derivarlo de
	// `nuevo` cierra esa clase entera: nadie más conoce este nombre.
	viejo := nuevo + ".viejo"
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

// purgarExtraccionesHuerfanas borra los directorios de extracción que dejó atrás
// un proceso muerto. Existe porque el código anterior, al usar la ruta fija
// db.nuevo, se limpiaba solo en cada corrida: sin esto, cada kill a media
// descarga dejaría hasta ~1.2 GB para siempre.
//
// El umbral de una hora es lo que hace que esto NO sea el candado en disco que
// se rechazó: no se borra nada reciente, así que jamás puede tocar la extracción
// en curso de otro proceso (extraer la base tarda minutos), y si no borra nada
// tampoco bloquea a nadie. Los errores se ignoran a propósito: es higiene de
// disco, no parte del contrato de la actualización.
func purgarExtraccionesHuerfanas(dirTrivy string) {
	entradas, err := os.ReadDir(dirTrivy)
	if err != nil {
		return
	}
	for _, e := range entradas {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "db.nuevo-") {
			continue
		}
		info, err := e.Info()
		if err != nil || time.Since(info.ModTime()) < time.Hour {
			continue
		}
		_ = os.RemoveAll(filepath.Join(dirTrivy, e.Name()))
	}
}

func digestDe(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}
