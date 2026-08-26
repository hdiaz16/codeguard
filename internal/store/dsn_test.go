package store

import (
	"os"
	"path/filepath"
	"testing"
)

// El DSN se compone concatenando la ruta con los _pragma, y el path lleva el
// nombre del usuario de Windows, donde '&', '%', '#' y el espacio son válidos
// ('?' no hace falta probarlo: Windows lo prohíbe en un nombre).
//
// La versión anterior de este test solo comprobaba que la base ABRIERA y que
// los pragmas llegaran, y por eso pasó en verde durante meses sobre un bug
// real: con '#' en la ruta, dsnSQLite escapaba el path entero con
// url.PathEscape —que también escapa las barras— y SQLite abría una base
// PERFECTAMENTE VÁLIDA en el directorio de trabajo, llamada
// «%2FUsers%2F…%2Fcodeguard.db». Todos los pragmas llegaban. El archivo
// estaba en otro sitio. De ahí los 34 residuos que aparecieron en
// internal/store.
//
// La lección va fijada abajo: no basta con que abra, tiene que abrir DONDE SE
// PIDIÓ. Se comprueba la ruta exacta, que no queden sidecars sueltos y que la
// base se pueda REABRIR ahí mismo — una base que se crea en el sitio
// equivocado igual se reabre en el sitio equivocado, así que el dato que de
// verdad ancla el test es os.Stat sobre el destino.
func TestBaseAbreEnRutaConCaracteresReservados(t *testing.T) {
	carpetas := []string{
		"con&ampersand",
		"50%off",
		"con espacio",
		"con#almohadilla",
		"acentuación-ñ",
	}
	for _, carpeta := range carpetas {
		t.Run(carpeta, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), carpeta)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			destino := filepath.Join(dir, "codeguard.db")

			s, err := abrir(destino, 5000)
			if err != nil {
				t.Fatalf("la base no abrió con la carpeta %q: %v", carpeta, err)
			}

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
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}

			// LO QUE FALTABA: el archivo tiene que existir EXACTAMENTE en la
			// ruta pedida. Sin esto, una base creada en el cwd pasa el test.
			if _, err := os.Stat(destino); err != nil {
				t.Fatalf("la base no aterrizó en %q: %v\n"+
					"el DSN convirtió la ruta absoluta en otra cosa (fue el caso de url.PathEscape con '#')", destino, err)
			}

			// Y nada debe haberse creado FUERA de esa carpeta.
			sueltos, err := filepath.Glob(filepath.Join(dir, "..", "*.db*"))
			if err != nil {
				t.Fatal(err)
			}
			if len(sueltos) > 0 {
				t.Errorf("aparecieron archivos de SQLite fuera de la carpeta pedida: %v", sueltos)
			}

			// Reabrir en la misma ruta: si la primera apertura hubiera creado
			// la base en otro sitio, aquí se vería una base recién nacida.
			s2, err := abrir(destino, 5000)
			if err != nil {
				t.Fatalf("la base no reabrió en %q: %v", destino, err)
			}
			defer s2.Close()
		})
	}
}
