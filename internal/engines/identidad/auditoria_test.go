package identidad

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"codeguard/internal/trivydb"
)

// errHashDistinto separa el fallo GRAVE —lo que se bajó no es lo que se espera,
// por corrupción o manipulación— de un problema de red. Quien llama tiene que
// tratarlo como fallo, nunca como «no se pudo probar»: los dos viajaban por el
// mismo canal indistinguible y el test respondía a ambos con un skip.
var errHashDistinto = errors.New("el hash no coincide con el esperado")

// asegurarBaseTrivy deja la base de vulnerabilidades lista o se salta la
// prueba: escanear va con --skip-db-update y la EXIGE, y en una máquina (o
// runner) recién instalada no existe — trivy salía con 1 y estas pruebas
// acusaban al escáner de un entorno cojo. La red ausente es un skip legítimo,
// igual que con el jar de control; Auditar en producción la baja por su
// cuenta (mismo cliente OCI verificado).
func asegurarBaseTrivy(t *testing.T) {
	t.Helper()
	dir, err := trivydb.DirCache()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := trivydb.Actualizar(ctx, dir); err != nil {
		if _, statErr := os.Stat(filepath.Join(dir, "db", "metadata.json")); statErr != nil {
			t.Skipf("sin base de vulnerabilidades y sin red para bajarla: %v", err)
		}
		t.Logf("base de trivy sin refrescar (se usa la copia local): %v", err)
	}
}

// El jar de control se baja con su hash comprobado, igual que los motores de
// verdad: no vamos a predicar integridad de la cadena y luego tragarnos
// cualquier cosa que devuelva una descarga en nuestra propia suite.
func descargarVerificado(url, sha, destino string) error {
	cli := &http.Client{Timeout: 3 * time.Minute}
	resp, err := cli.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s respondió %s", url, resp.Status)
	}
	cuerpo, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}
	suma := sha256.Sum256(cuerpo)
	if got := hex.EncodeToString(suma[:]); got != sha {
		return fmt.Errorf("%w (jar de control, obtuvimos %s)", errHashDistinto, got)
	}
	return os.WriteFile(destino, cuerpo, 0o644)
}

// El control del escáner.
//
// Esta prueba existe porque la auditoría estuvo un tiempo dando el visto bueno
// sin mirar nada: usaba `trivy fs`, que busca manifiestos de código fuente, en
// vez de `rootfs`, que busca artefactos instalados. Los cinco motores daban
// cero, y cero se lee como "limpio". Sólo se descubrió metiéndole al escáner un
// artefacto que SABEMOS vulnerable y comprobando que lo encuentra.
//
// Eso es lo que hace esta prueba, y por eso descarga log4j-core 2.14.1: si
// mañana alguien cambia el subcomando, una bandera o la versión de trivy y el
// escáner se queda ciego, esto se pone rojo. Sin control, un escáner roto y uno
// que funciona producen exactamente la misma salida.
//
// Se salta sin red o sin trivy: no vamos a romper la suite de quien trabaja en
// un avión. Pero en el CI, que sí tiene ambas cosas, corre siempre.
func TestEscanerEncuentraLoQueDebeEncontrar(t *testing.T) {
	if testing.Short() {
		t.Skip("descarga un jar de Maven Central")
	}
	if runtime.GOOS != "windows" {
		t.Skip("la ruta de trivy que resolvemos aquí es la de Windows")
	}
	trivy := filepath.Join(os.Getenv("LOCALAPPDATA"), "CodeGuard", "engines", "trivy.exe")
	if _, err := os.Stat(trivy); err != nil {
		t.Skip("trivy no está instalado en esta máquina")
	}
	asegurarBaseTrivy(t)

	const (
		url  = "https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar"
		sha  = "ade7402a70667a727635d5c4c29495f4ff96f061f12539763f6f123973b465b0"
		cve  = "CVE-2021-44228" // Log4Shell
		nomb = "control"
	)
	dir := t.TempDir()
	if err := descargarVerificado(url, sha, filepath.Join(dir, "log4j-core-2.14.1.jar")); err != nil {
		// Un hash que no coincide NO es «no se pudo probar»: es la señal de que
		// el artefacto de control no es lo que creemos, que es exactamente el
		// escenario de cadena de suministro comprometida que la verificación
		// existe para detectar. Eso se grita. La red sí es un skip legítimo.
		if errors.Is(err, errHashDistinto) {
			t.Fatalf("el jar de control no es lo que esperábamos: %v", err)
		}
		t.Skipf("no se pudo traer el jar de control: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	riesgos, err := escanear(ctx, trivy, dir, nomb)
	if err != nil {
		t.Fatalf("el escáner no pudo mirar un jar corriente: %v", err)
	}
	for _, r := range riesgos {
		if r.CVE == cve {
			if r.Severidad != "CRITICAL" {
				t.Errorf("Log4Shell debería ser CRITICAL, salió %q", r.Severidad)
			}
			return
		}
	}
	// Este es el fallo que importa: no que sobren hallazgos, sino que falte EL
	// hallazgo. Si llega aquí, la auditoría está dando por limpio lo que no mira.
	t.Fatalf("el escáner NO encontró %s en log4j-core 2.14.1 (%d hallazgos): "+
		"está mirando mal, y su visto bueno no significa nada", cve, len(riesgos))
}

// Un directorio vacío no tiene nada analizable, y eso debe decirse como error,
// no devolverse como una lista vacía de riesgos. Es la distinción que faltaba.
func TestSinNadaAnalizableEsError(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("la ruta de trivy que resolvemos aquí es la de Windows")
	}
	trivy := filepath.Join(os.Getenv("LOCALAPPDATA"), "CodeGuard", "engines", "trivy.exe")
	if _, err := os.Stat(trivy); err != nil {
		t.Skip("trivy no está instalado en esta máquina")
	}
	asegurarBaseTrivy(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	vacio := t.TempDir()
	if err := os.WriteFile(filepath.Join(vacio, "leeme.txt"), []byte("nada que escanear\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := escanear(ctx, trivy, vacio, "vacío"); err == nil {
		t.Fatal("un escaneo sin objetivos se está reportando como limpio; " +
			"así fue como la auditoría entera pasó meses sin mirar nada")
	} else if !strings.Contains(err.Error(), "analizable") {
		t.Errorf("el error no explica el motivo: %v", err)
	}
}
