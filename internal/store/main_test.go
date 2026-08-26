package store

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// TestMain vigila que ningún test del paquete deje bases de datos en el
// directorio del código.
//
// Nace de un caso real y caro: dsnSQLite escapaba con url.PathEscape las
// rutas que llevaban '#', y como ese escape también convierte '/' en '%2F',
// SQLite acababa creando la base en el directorio de trabajo con un nombre
// como «%2FUsers%2F…%2Fcodeguard.db». Se acumularon 34 archivos y 5 MB
// durante meses SIN QUE NADIE LO VIERA, porque «*.db» está en .gitignore y
// `git status` no los enseñaba, y porque el test que los generaba pasaba en
// verde (comprobaba los pragmas, no la ubicación).
//
// Un test que escribe fuera de t.TempDir() es un defecto aunque pase. Esta
// guarda lo convierte en un fallo ruidoso el mismo día que ocurra.
func TestMain(m *testing.M) {
	antes := sqliteEnElPaquete()
	codigo := m.Run()

	var nuevos []string
	for f := range sqliteEnElPaquete() {
		if !antes[f] {
			nuevos = append(nuevos, f)
		}
	}
	if len(nuevos) > 0 {
		sort.Strings(nuevos)
		fmt.Fprintf(os.Stderr,
			"\nFUGA: los tests dejaron %d archivo(s) de SQLite en el directorio del paquete.\n"+
				"Alguna prueba abrió una base fuera de t.TempDir(), o el DSN volvió a torcer la ruta.\n",
			len(nuevos))
		for _, f := range nuevos {
			fmt.Fprintf(os.Stderr, "  %s\n", f)
		}
		if codigo == 0 {
			codigo = 1
		}
	}
	os.Exit(codigo)
}

// sqliteEnElPaquete lista los archivos de SQLite del directorio actual (el
// del paquete cuando corre `go test`). El patrón cubre la base y sus
// sidecars de WAL, y también los nombres percent-encoded del bug histórico,
// que terminan igual en «.db».
func sqliteEnElPaquete() map[string]bool {
	out := map[string]bool{}
	for _, patron := range []string{"*.db", "*.db-wal", "*.db-shm"} {
		encontrados, err := filepath.Glob(patron)
		if err != nil {
			continue
		}
		for _, f := range encontrados {
			out[f] = true
		}
	}
	return out
}
