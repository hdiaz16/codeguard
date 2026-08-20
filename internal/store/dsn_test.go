package store

import (
	"os"
	"path/filepath"
	"testing"
)

// El DSN se compone concatenando la ruta con los _pragma, y el path lleva el
// nombre del usuario de Windows, donde '&', '%', '#' y el espacio son válidos.
// Se auditó como posible rotura de la cadena de conexión; SE MIDIÓ y no lo es:
// el driver separa por el primer '?' y no percent-decodifica el path, así que
// esos caracteres pasan intactos ('?' no hace falta probarlo, Windows lo
// prohíbe en un nombre). Este test fija ese comportamiento, que es lo que
// permite dejar la concatenación en paz: comprueba que la base abre Y que los
// pragmas llegaron, porque un DSN roto que abre igual pero sin foreign_keys ni
// WAL es precisamente el caso que no se notaría.
func TestBaseAbreEnRutaConCaracteresReservados(t *testing.T) {
	for _, carpeta := range []string{"con&ampersand", "50%off", "con espacio", "con#almohadilla"} {
		t.Run(carpeta, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), carpeta)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			s, err := abrir(filepath.Join(dir, "codeguard.db"), 5000)
			if err != nil {
				t.Fatalf("la base no abrió con la carpeta %q: %v", carpeta, err)
			}
			defer s.Close()

			var fk int
			if err := s.db.QueryRow(`PRAGMA foreign_keys`).Scan(&fk); err != nil {
				t.Fatal(err)
			}
			if fk != 1 {
				t.Errorf("foreign_keys = %d: el _pragma no llegó y las claves ajenas no se están aplicando", fk)
			}
			var modo string
			if err := s.db.QueryRow(`PRAGMA journal_mode`).Scan(&modo); err != nil {
				t.Fatal(err)
			}
			if modo != "wal" {
				t.Errorf("journal_mode = %q y se pidió wal: sin WAL el hook y el daemon se bloquean entre sí", modo)
			}
		})
	}
}
