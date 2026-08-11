package linters

import (
	"context"
	"os"
	"path/filepath"
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
