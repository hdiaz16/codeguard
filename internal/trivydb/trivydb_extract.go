package trivydb

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

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
