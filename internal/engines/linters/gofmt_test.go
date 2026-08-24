package linters

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codeguard/internal/engines"
	"codeguard/internal/gitdiff"
)

func correrGoFmt(t *testing.T, dir string, rutas ...string) []string {
	t.Helper()
	var files []gitdiff.ChangedFile
	for _, r := range rutas {
		files = append(files, gitdiff.ChangedFile{Path: r, Status: "M"})
	}
	fs, err := GoFmt{}.Run(context.Background(), engines.Input{RepoRoot: dir, Files: files})
	if err != nil {
		t.Fatalf("GoFmt.Run: %v", err)
	}
	var marcados []string
	for _, f := range fs {
		marcados = append(marcados, f.File)
	}
	return marcados
}

// UN ARCHIVO DEL CAMBIO QUE NADIE PUDO LEER NO ES UN ARCHIVO BIEN FORMATEADO.
//
// gofmt no lanza ningún proceso —formatea con go/format dentro de este binario—
// así que no puede sufrir la avería del resto de los motores: no hay herramienta
// externa que falte ni salida que parsear mal. Pero tenía su propia versión, más
// pequeña y del mismo tipo: los archivos que no podía leer se saltaban con un
// `continue` mudo, y el resultado era indistinguible de «lo revisé y está bien».
//
// Se distingue el único silencio legítimo —el archivo se borró entre el diff y el
// análisis— del resto: permisos, bloqueo por otro proceso, error de E/S. En esos
// el archivo SÍ está y SÍ entra en el cambio.
//
// El caso se provoca con un directorio con nombre de .go porque es la forma
// portable de conseguir un error de lectura que no sea "no existe": en Windows
// os.Chmod no quita el permiso de lectura al propietario, así que un archivo sin
// permisos no serviría para probar esto.
func TestUnArchivoIlegibleNoPasaPorBienFormateado(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bien.go"), []byte("package p\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "ilegible.go"), 0o755); err != nil {
		t.Fatal(err)
	}

	fs, err := GoFmt{}.Run(context.Background(), engines.Input{
		RepoRoot: dir,
		Files: []gitdiff.ChangedFile{
			{Path: "bien.go", Status: "M"},
			{Path: "ilegible.go", Status: "M"},
		},
	})
	if err == nil {
		t.Fatalf("gofmt no pudo leer un archivo del cambio y devolvió %d hallazgos SIN error: "+
			"eso llega al panel como capa revisada, y el formato de ese archivo no lo miró "+
			"nadie", len(fs))
	}
	if !strings.Contains(err.Error(), "ilegible.go") {
		t.Errorf("el error tiene que decir QUÉ archivo se quedó sin revisar: %v", err)
	}
}

// Y el control: el archivo que de verdad desapareció entre el diff y el análisis
// no es ninguna avería. Sin esto, la comprobación de arriba se podría "arreglar"
// devolviendo error ante cualquier lectura fallida, y entonces cualquier commit
// que borre un .go —un rename, un archivo movido— quedaría con la capa de formato
// degradada para siempre.
func TestUnArchivoBorradoSigueSiendoSilencioLegitimo(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "queda.go"), []byte("package p\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	fs, err := GoFmt{}.Run(context.Background(), engines.Input{
		RepoRoot: dir,
		Files: []gitdiff.ChangedFile{
			{Path: "queda.go", Status: "M"},
			{Path: "sefue.go", Status: "M"}, // en el diff, ya no en el disco
		},
	})
	if err != nil {
		t.Fatalf("un archivo borrado entre el diff y el análisis no tiene formato que "+
			"revisar: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("nada que marcar aquí, y se marcaron %d: %+v", len(fs), fs)
	}
}

// En Windows, git deja CRLF en el disco por autocrlf. Sin normalizar antes de
// comparar, un repo recien clonado bloqueaba TODOS los commits que tocaran Go:
// `gofmt -w` los corregia, git los revertia al siguiente checkout, y el dev
// quedaba en un bucle. Y rompia la promesa central del agente: en el CI pasaba
// y en local no.
func TestCRLFNoCuentaComoMalFormateado(t *testing.T) {
	dir := t.TempDir()
	escribir := func(nombre, contenido string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, nombre), []byte(contenido), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Correcto salvo por los CRLF: no debe marcarse.
	escribir("bien.go", "package p\r\n\r\nfunc F() int {\r\n\treturn 1\r\n}\r\n")
	// De verdad mal formateado (la sangria), ademas de CRLF: debe marcarse.
	escribir("mal.go", "package p\r\n\r\nfunc  F( ) int {\r\nreturn 1\r\n}\r\n")
	// Mal formateado sin CRLF: debe marcarse.
	escribir("lf.go", "package p\n\nfunc  F( ) int {\nreturn 1\n}\n")
	// No parsea: eso es asunto del compilador/govet, no del formato.
	escribir("roto.go", "package p\n\nfunc {\n")

	marcados := correrGoFmt(t, dir, "bien.go", "mal.go", "lf.go", "roto.go")
	if len(marcados) != 2 {
		t.Fatalf("esperaba exactamente mal.go y lf.go, se marcaron: %v", marcados)
	}
	esta := map[string]bool{}
	for _, m := range marcados {
		esta[m] = true
	}
	if !esta["mal.go"] || !esta["lf.go"] {
		t.Errorf("faltan los mal formateados de verdad: %v", marcados)
	}
	if esta["bien.go"] {
		t.Error("un archivo correcto con CRLF no puede bloquear")
	}
	if esta["roto.go"] {
		t.Error("un archivo que no parsea es asunto del compilador, no de gofmt")
	}
}
