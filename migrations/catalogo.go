package migrations

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
)

// Migracion es una entrada del catálogo: el DDL embebido con su identidad.
type Migracion struct {
	Nombre string
	SQL    string
	// Checksum es sha256 del SQL NORMALIZADO a LF, en hex. La normalización
	// no es decorativa: sin ella, dos checkouts del mismo commit (autocrlf
	// distinto) embeben bytes distintos y un build honesto denunciaría
	// divergencia de esquema donde solo hay finales de línea (turno 92).
	// .gitattributes fija eol=lf además — cinturón y tirantes.
	Checksum string
}

// Catalogo devuelve las migraciones embebidas: parseadas, ORDENADAS por su
// número y validadas. Es EL catálogo — el migrador local (store.Migrate) y el
// central (sync.migrarCentral) consumen esta función y ninguno vuelve a
// listar/ordenar por su cuenta: tenían DOS criterios de orden (número extraído
// vs sort.Strings) que coincidían de casualidad por los tres dígitos, y esa
// clase de suerte es la que un día se acaba sin ruido.
func Catalogo() ([]Migracion, error) {
	entries, err := fs.ReadDir(FS, ".")
	if err != nil {
		return nil, err
	}
	numeros := map[uint64]string{}
	var out []Migracion
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		n, err := numeroDe(e.Name())
		if err != nil {
			return nil, fmt.Errorf("migración con nombre inválido: %w", err)
		}
		if previo, ya := numeros[n]; ya {
			// Dos archivos con el mismo número es ambigüedad de ORDEN: cuál
			// corre primero dependería del nombre, y el esquema resultante de
			// la lotería. Se rechaza el catálogo entero.
			return nil, fmt.Errorf("dos migraciones con el número %d: %s y %s", n, previo, e.Name())
		}
		numeros[n] = e.Name()
		raw, err := fs.ReadFile(FS, e.Name())
		if err != nil {
			return nil, err
		}
		sql := strings.ReplaceAll(string(raw), "\r\n", "\n")
		h := sha256.Sum256([]byte(sql))
		out = append(out, Migracion{Nombre: e.Name(), SQL: sql, Checksum: hex.EncodeToString(h[:])})
	}
	sort.Slice(out, func(i, j int) bool {
		ni, _ := numeroDe(out[i].Nombre)
		nj, _ := numeroDe(out[j].Nombre)
		return ni < nj
	})
	return out, nil
}

func numeroDe(nombre string) (uint64, error) {
	fin := 0
	for fin < len(nombre) && nombre[fin] >= '0' && nombre[fin] <= '9' {
		fin++
	}
	if fin == 0 {
		return 0, fmt.Errorf("%q no empieza por número", nombre)
	}
	return strconv.ParseUint(nombre[:fin], 10, 64)
}
