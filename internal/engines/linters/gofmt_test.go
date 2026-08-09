package linters

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// En Windows, git deja CRLF en el disco por autocrlf, y `gofmt -l` marca por
// eso cualquier archivo Go. Sin distinguirlo, un repo recien clonado bloqueaba
// TODOS los commits que tocaran Go: `gofmt -w` los corregia, git los revertia
// al siguiente checkout, y el dev quedaba en un bucle. Y rompia la promesa
// central del agente: en el CI pasaba y en local no.
func TestCRLFNoCuentaComoMalFormateado(t *testing.T) {
	dir := t.TempDir()

	bienConCRLF := filepath.Join(dir, "bien.go")
	contenido := "package p\r\n\r\nfunc F() int {\r\n\treturn 1\r\n}\r\n"
	if err := os.WriteFile(bienConCRLF, []byte(contenido), 0o644); err != nil {
		t.Fatal(err)
	}
	if !soloFinalesDeLinea(context.Background(), dir, bienConCRLF) {
		t.Error("un archivo correcto con CRLF debe reconocerse como solo finales de linea")
	}

	// El mismo archivo, pero de verdad mal formateado: la sangria esta mal.
	malConCRLF := filepath.Join(dir, "mal.go")
	malo := "package p\r\n\r\nfunc  F( ) int {\r\nreturn 1\r\n}\r\n"
	if err := os.WriteFile(malConCRLF, []byte(malo), 0o644); err != nil {
		t.Fatal(err)
	}
	if soloFinalesDeLinea(context.Background(), dir, malConCRLF) {
		t.Error("un archivo mal formateado NO puede excusarse por los finales de linea")
	}

	// Sin CRLF no hay nada que excusar: si gofmt lo marco, esta mal.
	soloLF := filepath.Join(dir, "lf.go")
	if err := os.WriteFile(soloLF, []byte("package p\n\nfunc  F( ) int {\nreturn 1\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if soloFinalesDeLinea(context.Background(), dir, soloLF) {
		t.Error("un archivo sin CRLF nunca debe excusarse")
	}
}
