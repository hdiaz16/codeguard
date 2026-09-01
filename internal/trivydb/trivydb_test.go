package trivydb

// Este paquete existe para NO confiar en lo que llega de la red, así que sus
// pruebas son sobre todo adversarias: cada una sirve datos hostiles desde un
// registro falso y exige que se rechacen SIN abrirse. El caso feliz está al
// final, casi de cortesía.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// registroFalso publica una base de trivy inventada por el protocolo OCI real:
// token → índice → manifiesto (por digest) → blob. Cada handler puede
// sabotearse por separado, que es justo lo que las pruebas necesitan.
type registroFalso struct {
	*httptest.Server
	indice     []byte
	manifiesto []byte
	blob       []byte
	// sabotajes: se sirven estos bytes EN LUGAR de los legítimos, dejando los
	// digests apuntando a los originales.
	blobServido       []byte
	manifiestoServido []byte
}

func nuevoRegistro(t *testing.T, contenidoTar map[string]string) *registroFalso {
	return nuevoRegistroFuente(t, contenidoTar, fuenteVulnerabilidades())
}

func nuevoRegistroFuente(t *testing.T, contenidoTar map[string]string, fuente fuenteOCI) *registroFalso {
	t.Helper()
	r := &registroFalso{}

	var tgz bytes.Buffer
	gz := gzip.NewWriter(&tgz)
	tw := tar.NewWriter(gz)
	for nombre, contenido := range contenidoTar {
		if err := tw.WriteHeader(&tar.Header{Name: nombre, Mode: 0o644, Size: int64(len(contenido))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(contenido)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	r.blob = tgz.Bytes()

	man, _ := json.Marshal(map[string]any{
		"mediaType": "application/vnd.oci.image.manifest.v1+json",
		"layers": []map[string]any{{
			"mediaType": fuente.tipoCapa,
			"digest":    digestDe(r.blob),
			"size":      len(r.blob),
		}},
	})
	r.manifiesto = man

	idx, _ := json.Marshal(map[string]any{
		"mediaType": "application/vnd.oci.image.index.v1+json",
		"manifests": []map[string]any{{
			"mediaType": "application/vnd.oci.image.manifest.v1+json",
			"digest":    digestDe(man),
		}},
	})
	r.indice = idx

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"token":"token-de-prueba"}`))
	})
	baseOCI := "/v2/" + fuente.repositorio
	mux.HandleFunc(baseOCI+"/manifests/"+fuente.etiqueta, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(r.indice)
	})
	mux.HandleFunc(baseOCI+"/manifests/"+digestDe(man), func(w http.ResponseWriter, _ *http.Request) {
		if r.manifiestoServido != nil {
			_, _ = w.Write(r.manifiestoServido)
			return
		}
		_, _ = w.Write(r.manifiesto)
	})
	mux.HandleFunc(baseOCI+"/blobs/"+digestDe(r.blob), func(w http.ResponseWriter, _ *http.Request) {
		if r.blobServido != nil {
			_, _ = w.Write(r.blobServido)
			return
		}
		_, _ = w.Write(r.blob)
	})
	r.Server = httptest.NewServer(mux)
	t.Cleanup(r.Close)

	base := registroBase
	registroBase = r.URL
	t.Cleanup(func() { registroBase = base })
	return r
}

func TestActualizarJavaUsaRepositorioYLayoutOficiales(t *testing.T) {
	nuevoRegistroFuente(t, map[string]string{
		"trivy-java.db": "índice java legítimo",
		"metadata.json": `{"Version":1}`,
	}, fuenteJava())
	dir := t.TempDir()
	if err := ActualizarJava(context.Background(), dir); err != nil {
		t.Fatalf("actualizar java-db: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "java-db", "trivy-java.db"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "índice java legítimo" {
		t.Fatalf("java-db instalada con contenido inesperado: %q", b)
	}
}

func TestUnBlobAlteradoSeDescartaSinAbrirlo(t *testing.T) {
	r := nuevoRegistro(t, map[string]string{"trivy.db": "base legítima", "metadata.json": "{}"})

	// El registro sirve OTROS bytes bajo el digest legítimo: es el envenenado
	// en tránsito o el espejo alterado. gzip jamás debe llegar a abrirlos.
	r.blobServido = []byte("no soy la base, y ni siquiera soy un gzip válido")

	dir := t.TempDir()
	semilla(t, dir, "la base anterior")
	err := Actualizar(context.Background(), dir)
	if err == nil {
		t.Fatal("un blob que no coincide con su digest se instaló sin protestar")
	}
	// El mensaje culpa a la verificación, no al gzip: si dijera "gzip: invalid
	// header" es que ABRIÓ el contenido hostil antes de verificarlo.
	if !contiene(err, "no coincide con su digest") {
		t.Fatalf("el error no es el de verificación: %v", err)
	}
	exigirBaseIntacta(t, dir, "la base anterior")
}

func TestUnManifiestoAlteradoSeDescarta(t *testing.T) {
	r := nuevoRegistro(t, map[string]string{"trivy.db": "x", "metadata.json": "{}"})
	// El índice nombra un digest; el registro sirve otro documento. Un
	// manifiesto sustituido podría apuntar a un blob del atacante CON digest
	// correcto de ese blob — por eso el manifiesto mismo tiene que verificarse.
	r.manifiestoServido = []byte(`{"mediaType":"application/vnd.oci.image.manifest.v1+json","layers":[]}`)

	dir := t.TempDir()
	semilla(t, dir, "intacta")
	err := Actualizar(context.Background(), dir)
	if err == nil || !contiene(err, "no coincide con su digest") {
		t.Fatalf("el manifiesto alterado no se rechazó por verificación: %v", err)
	}
	exigirBaseIntacta(t, dir, "intacta")
}

func TestUnTarConRutasTraicionerasSeRechazaEntero(t *testing.T) {
	// El tar viene con digest CORRECTO (el atacante controla el registro y
	// publica su propio artefacto consistente): la última línea de defensa es
	// la lista blanca de nombres.
	nuevoRegistro(t, map[string]string{
		"trivy.db":      "parece legítima",
		"metadata.json": "{}",
		"../inyectado":  "fuera del directorio",
	})

	dir := t.TempDir()
	semilla(t, dir, "intacta")
	err := Actualizar(context.Background(), dir)
	if err == nil || !contiene(err, "se descarta entero") {
		t.Fatalf("el tar con ../inyectado no se rechazó: %v", err)
	}
	exigirBaseIntacta(t, dir, "intacta")
	if _, statErr := os.Stat(filepath.Join(filepath.Dir(dir), "inyectado")); statErr == nil {
		t.Fatal("el archivo traicionero quedó escrito FUERA del directorio de la base")
	}
}

func TestUnTarIncompletoNoSustituyeLaBase(t *testing.T) {
	nuevoRegistro(t, map[string]string{"metadata.json": "{}"}) // sin trivy.db

	dir := t.TempDir()
	semilla(t, dir, "intacta")
	err := Actualizar(context.Background(), dir)
	if err == nil || !contiene(err, "no trae trivy.db") {
		t.Fatalf("una base sin trivy.db no se rechazó: %v", err)
	}
	exigirBaseIntacta(t, dir, "intacta")
}

func TestDescargaVerificaYSustituyeAtomicamente(t *testing.T) {
	nuevoRegistro(t, map[string]string{"trivy.db": "base nueva", "metadata.json": `{"Version":2}`})

	dir := t.TempDir()
	semilla(t, dir, "base vieja")
	if err := Actualizar(context.Background(), dir); err != nil {
		t.Fatalf("la actualización legítima falló: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "db", "trivy.db"))
	if err != nil || string(b) != "base nueva" {
		t.Fatalf("la base nueva no quedó en su sitio: %q, %v", b, err)
	}
	// Por glob y no por la ruta fija: los directorios de trabajo llevan sufijo
	// único por llamada (db.nuevo-*, y el respaldo db.nuevo-*.viejo), así que
	// comprobar "db.nuevo" a secas pasaría siempre sin medir nada.
	exigirSinRestos(t, dir)
}

// ── andamiaje ────────────────────────────────────────────────────────────

func semilla(t *testing.T, dirTrivy, contenido string) {
	t.Helper()
	db := filepath.Join(dirTrivy, "db")
	if err := os.MkdirAll(db, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"trivy.db", "metadata.json"} {
		if err := os.WriteFile(filepath.Join(db, n), []byte(contenido), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func exigirBaseIntacta(t *testing.T, dirTrivy, contenido string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dirTrivy, "db", "trivy.db"))
	if err != nil || string(b) != contenido {
		t.Fatalf("la base anterior no quedó intacta tras el rechazo: %q, %v", b, err)
	}
	exigirSinRestos(t, dirTrivy)
}

// exigirSinRestos comprueba que no queda ningún directorio de trabajo. Mira el
// GLOB porque los nombres son únicos por llamada: la extracción es db.nuevo-* y
// el respaldo de la base anterior cuelga de ese mismo nombre.
func exigirSinRestos(t *testing.T, dirTrivy string) {
	t.Helper()
	restos, err := filepath.Glob(filepath.Join(dirTrivy, "db.nuevo-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(restos) > 0 {
		t.Errorf("quedaron directorios de trabajo atrás: %v", restos)
	}
}

func contiene(err error, s string) bool {
	return err != nil && bytes.Contains([]byte(err.Error()), []byte(s))
}

// EL RESPALDO DE OTRO PROCESO NO SE TOCA.
//
// Aquí estaba la carrera fina que el mutex del proceso no podía cubrir:
// intercambiar apartaba la base anterior en el "db.viejo" FIJO y empezaba
// borrando ese directorio. Con dos procesos —un daemon viejo y uno nuevo, o el
// daemon y el CLI— el segundo borraba el respaldo que el primero acababa de
// apartar, y si al primero le fallaba luego el rename de colocación (el caso
// documentado de un trivy leyendo la base en Windows) su restauración no
// encontraba nada: la base quedaba AUSENTE, con el motor bloqueante a ciegas.
//
// El centinela hace de respaldo ajeno. Con la ruta fija este test falla: el
// RemoveAll inicial se lo lleva. Con el respaldo derivado del directorio único
// de cada llamada, nadie más conoce ese nombre y sobrevive.
func TestUnIntercambioNoTocaElRespaldoDeOtroProceso(t *testing.T) {
	dir := t.TempDir()
	semilla(t, dir, "base vieja")

	respaldoAjeno := filepath.Join(dir, "db.viejo")
	if err := os.MkdirAll(respaldoAjeno, 0o755); err != nil {
		t.Fatal(err)
	}
	centinela := filepath.Join(respaldoAjeno, "trivy.db")
	if err := os.WriteFile(centinela, []byte("la base que otro proceso apartó"), 0o644); err != nil {
		t.Fatal(err)
	}

	nuevo, err := os.MkdirTemp(dir, "db.nuevo-*")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"trivy.db", "metadata.json"} {
		if err := os.WriteFile(filepath.Join(nuevo, n), []byte("base nueva"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := intercambiar(dir, nuevo); err != nil {
		t.Fatalf("el intercambio legítimo falló: %v", err)
	}

	b, err := os.ReadFile(centinela)
	if err != nil {
		t.Fatalf("se destruyó el respaldo de otro proceso: %v — si a ese otro le falla "+
			"el rename de colocación, se queda sin base a la que volver", err)
	}
	if string(b) != "la base que otro proceso apartó" {
		t.Errorf("el respaldo ajeno quedó alterado: %q", b)
	}
}

// Y el invariante de conjunto, bajo solape real: cada llamada sale con nil o con
// error, y al final la base es UNA de las completas, nunca un híbrido de dos.
//
// Este no reproduce el fallo de arriba —para eso hace falta que el rename de
// colocación falle, y en una máquina sin trivy leyendo la base no falla nunca—:
// se MIDIÓ que pasa igual con el código anterior. Queda como red contra roturas
// gruesas y para que -race vigile el camino.
func TestDosIntercambiosSimultaneosNuncaDejanLaBaseAMedias(t *testing.T) {
	dir := t.TempDir()
	semilla(t, dir, "base vieja")

	const cuantos = 6
	var listos sync.WaitGroup
	arranque := make(chan struct{})
	listos.Add(cuantos)
	for i := 0; i < cuantos; i++ {
		contenido := fmt.Sprintf("base nueva %d", i)
		go func() {
			defer listos.Done()
			nuevo, err := os.MkdirTemp(dir, "db.nuevo-*")
			if err != nil {
				t.Error(err)
				return
			}
			for _, n := range []string{"trivy.db", "metadata.json"} {
				if err := os.WriteFile(filepath.Join(nuevo, n), []byte(contenido), 0o644); err != nil {
					t.Error(err)
					return
				}
			}
			<-arranque
			if err := intercambiar(dir, nuevo); err != nil {
				_ = os.RemoveAll(nuevo) // igual que hace Actualizar
			}
		}()
	}
	close(arranque)
	listos.Wait()

	// La base existe, está completa, y sus dos archivos son de la MISMA
	// extracción: un híbrido probaría que alguien colocó algo a medias.
	db, err := os.ReadFile(filepath.Join(dir, "db", "trivy.db"))
	if err != nil {
		t.Fatalf("la base desapareció tras el solape: %v", err)
	}
	meta, err := os.ReadFile(filepath.Join(dir, "db", "metadata.json"))
	if err != nil {
		t.Fatalf("la base quedó incompleta tras el solape: %v", err)
	}
	if string(db) != string(meta) {
		t.Errorf("la base quedó mezclada entre dos extracciones: %q vs %q", db, meta)
	}
	if !strings.HasPrefix(string(db), "base nueva") && string(db) != "base vieja" {
		t.Errorf("contenido inesperado en la base: %q", db)
	}
}

// El huérfano que deja un proceso muerto se limpia, pero sólo el añejo: borrar
// uno reciente sería pisar la extracción en curso de otro proceso.
func TestSoloSePurganLasExtraccionesAnejas(t *testing.T) {
	dir := t.TempDir()
	reciente := filepath.Join(dir, "db.nuevo-recien")
	anejo := filepath.Join(dir, "db.nuevo-de-ayer")
	for _, d := range []string{reciente, anejo} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	ayer := time.Now().Add(-25 * time.Hour)
	if err := os.Chtimes(anejo, ayer, ayer); err != nil {
		t.Fatal(err)
	}

	purgarExtraccionesHuerfanas(dir)

	if _, err := os.Stat(anejo); err == nil {
		t.Error("la extracción huérfana de ayer sigue ocupando disco")
	}
	if _, err := os.Stat(reciente); err != nil {
		t.Error("se borró una extracción reciente: puede ser la de otro proceso en curso")
	}
}
