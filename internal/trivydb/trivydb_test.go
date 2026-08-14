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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
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
			"mediaType": "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip",
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
	mux.HandleFunc("/v2/aquasecurity/trivy-db/manifests/2", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(r.indice)
	})
	mux.HandleFunc("/v2/aquasecurity/trivy-db/manifests/"+digestDe(man), func(w http.ResponseWriter, _ *http.Request) {
		if r.manifiestoServido != nil {
			_, _ = w.Write(r.manifiestoServido)
			return
		}
		_, _ = w.Write(r.manifiesto)
	})
	mux.HandleFunc("/v2/aquasecurity/trivy-db/blobs/"+digestDe(r.blob), func(w http.ResponseWriter, _ *http.Request) {
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
	if _, err := os.Stat(filepath.Join(dir, "db.viejo")); err == nil {
		t.Error("el directorio db.viejo quedó atrás tras un intercambio limpio")
	}
	if _, err := os.Stat(filepath.Join(dir, "db.nuevo")); err == nil {
		t.Error("el directorio db.nuevo quedó atrás tras un intercambio limpio")
	}
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
	if _, err := os.Stat(filepath.Join(dirTrivy, "db.nuevo")); err == nil {
		t.Error("quedaron restos de la extracción rechazada en db.nuevo")
	}
}

func contiene(err error, s string) bool {
	return err != nil && bytes.Contains([]byte(err.Error()), []byte(s))
}
