package govulncheck

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"codeguard/internal/engines"
	"codeguard/internal/gitdiff"
)

// Capturado de govulncheck v1.6.0 sobre un módulo real con golang.org/x/text
// v0.3.5 (recortado: quedan las fichas OSV relevantes y los hallazgos tal
// cual). GO-2021-0113 llega en sus tres niveles —módulo, paquete y símbolo—;
// GO-2022-1059 sólo en módulo y paquete (presente pero nunca llamada), y
// GO-2026-4970 es la stdlib importada sin tocar el símbolo vulnerable. Sólo
// el primero debe convertirse en hallazgo.
const capturaReal = `{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck","scanner_version":"v1.6.0","db":"https://vuln.go.dev"}}
{"progress":{"message":"Scanning your code and 43 packages across 1 dependent module for known vulnerabilities..."}}
{"osv":{"id":"GO-2021-0113","summary":"Out-of-bounds read in golang.org/x/text/language","affected":[{"package":{"name":"golang.org/x/text","ecosystem":"Go"}}]}}
{"osv":{"id":"GO-2022-1059","summary":"Denial of service via crafted Accept-Language header in golang.org/x/text/language","affected":[{"package":{"name":"golang.org/x/text","ecosystem":"Go"}}]}}
{"finding":{"osv":"GO-2021-0113","fixed_version":"v0.3.7","trace":[{"module":"golang.org/x/text","version":"v0.3.5"}]}}
{"finding":{"osv":"GO-2022-1059","fixed_version":"v0.3.8","trace":[{"module":"golang.org/x/text","version":"v0.3.5"}]}}
{"finding":{"osv":"GO-2026-4970","fixed_version":"v1.26.5","trace":[{"module":"stdlib","version":"v1.26.3"}]}}
{"finding":{"osv":"GO-2026-4970","fixed_version":"v1.26.5","trace":[{"module":"stdlib","version":"v1.26.3","package":"os"}]}}
{"finding":{"osv":"GO-2021-0113","fixed_version":"v0.3.7","trace":[{"module":"golang.org/x/text","version":"v0.3.5","package":"golang.org/x/text/language"}]}}
{"finding":{"osv":"GO-2022-1059","fixed_version":"v0.3.8","trace":[{"module":"golang.org/x/text","version":"v0.3.5","package":"golang.org/x/text/language"}]}}
{"finding":{"osv":"GO-2021-0113","fixed_version":"v0.3.7","trace":[{"module":"golang.org/x/text","version":"v0.3.5","package":"golang.org/x/text/language","function":"Parse","position":{"filename":"language/parse.go","offset":1121,"line":33,"column":6}},{"module":"fixturevuln","package":"fixturevuln","function":"main","position":{"filename":"main.go","offset":105,"line":10,"column":28}}]}}
`

func TestSoloElSimboloAlcanzadoEsHallazgo(t *testing.T) {
	fs, err := interpretar([]byte(capturaReal), ".", false)
	if err != nil {
		t.Fatalf("interpretar: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("de 7 hallazgos crudos sólo el de nivel símbolo debe quedar; quedaron %d: %+v", len(fs), fs)
	}
	f := fs[0]
	if f.RuleKey != "GO-2021-0113" {
		t.Errorf("RuleKey = %q, esperaba GO-2021-0113", f.RuleKey)
	}
	if f.File != "main.go" || f.Line != 10 {
		t.Errorf("posición = %s:%d, esperaba main.go:10 (el marco del código propio, no el de la dependencia)", f.File, f.Line)
	}
	if !strings.Contains(f.Message, "golang.org/x/text/language.Parse") {
		t.Errorf("el mensaje debe nombrar el símbolo llamado: %q", f.Message)
	}
	if !strings.Contains(f.Message, "Out-of-bounds read") {
		t.Errorf("el mensaje debe llevar el resumen del OSV: %q", f.Message)
	}
	if !strings.Contains(f.FixHint, "v0.3.5 a v0.3.7") {
		t.Errorf("FixHint = %q, esperaba la versión corregida", f.FixHint)
	}
	if f.Blocking {
		t.Error("con BlockReachable=false (local) no debe bloquear")
	}
	if f.Fingerprint == "" {
		t.Error("falta el fingerprint")
	}
}

func TestEnCIBloquea(t *testing.T) {
	fs, err := interpretar([]byte(capturaReal), ".", true)
	if err != nil {
		t.Fatalf("interpretar: %v", err)
	}
	if len(fs) != 1 || !fs[0].Blocking {
		t.Fatalf("en CI el hallazgo alcanzable debe bloquear: %+v", fs)
	}
}

func TestMonorepoPrefijaElModulo(t *testing.T) {
	fs, err := interpretar([]byte(capturaReal), "backend", false)
	if err != nil {
		t.Fatalf("interpretar: %v", err)
	}
	if len(fs) != 1 || fs[0].File != "backend/main.go" {
		t.Fatalf("la posición debe llevar el prefijo del módulo: %+v", fs)
	}
}

func TestStdlibSugiereActualizarGo(t *testing.T) {
	// Forma real del flujo, con la stdlib alcanzada a nivel símbolo.
	payload := `{"osv":{"id":"GO-2026-5856","summary":"Ejemplo stdlib"}}
{"finding":{"osv":"GO-2026-5856","fixed_version":"v1.26.5","trace":[{"module":"stdlib","version":"v1.26.3","package":"net/http","function":"Serve","position":{"filename":"server.go","line":300}},{"module":"m","package":"m","function":"main","position":{"filename":"cmd/api/main.go","line":12}}]}}
`
	fs, err := interpretar([]byte(payload), ".", false)
	if err != nil {
		t.Fatalf("interpretar: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("esperaba 1 hallazgo, hay %d", len(fs))
	}
	if !strings.Contains(fs[0].FixHint, "toolchain de Go a 1.26.5") {
		t.Errorf("para stdlib el remedio es actualizar Go, no una dependencia: %q", fs[0].FixHint)
	}
}

func TestSalidaIlegible(t *testing.T) {
	if _, err := interpretar([]byte(`{"finding": {rota`), ".", false); err == nil {
		t.Fatal("una salida ilegible debe degradar el motor, no callar")
	}
}

// ── selección de módulos ─────────────────────────────────────────────────────

func repoDePrueba(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{".", "backend", "frontend"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// go.mod en la raíz y en backend/; frontend/ es TS puro.
	for _, dir := range []string{".", "backend"} {
		if err := os.WriteFile(filepath.Join(root, dir, "go.mod"), []byte("module x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestModulosSubeAlGoModMasCercano(t *testing.T) {
	e := &Engine{}
	in := engines.Input{RepoRoot: repoDePrueba(t), Files: []gitdiff.ChangedFile{
		{Path: "backend/internal/api/handler.go", Status: "M"},
		{Path: "cmd/tool/main.go", Status: "M"},
		{Path: "frontend/app.ts", Status: "M"},
		{Path: "backend/borrado.go", Status: "D"},
	}}
	got := e.modulos(in)
	want := []string{".", "backend"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("modulos = %v, esperaba %v (el .ts no aporta módulo y el borrado no cuenta)", got, want)
	}
}

func TestSoloManifiestosIgnoraCodigoGo(t *testing.T) {
	e := &Engine{SoloManifiestos: true}
	root := repoDePrueba(t)
	soloCodigo := engines.Input{RepoRoot: root, Files: []gitdiff.ChangedFile{
		{Path: "cmd/tool/main.go", Status: "M"},
	}}
	if e.Applies(soloCodigo) {
		t.Fatal("en el hook, un cambio de código sin tocar dependencias no debe correr govulncheck")
	}
	conManifiesto := engines.Input{RepoRoot: root, Files: []gitdiff.ChangedFile{
		{Path: "backend/go.sum", Status: "M"},
	}}
	if !e.Applies(conManifiesto) {
		t.Fatal("un go.sum tocado sí debe correrlo")
	}
}

// ── integración de punta a punta ─────────────────────────────────────────────

// TestIntegracionModuloVulnerable corre el binario real (sandbox incluido)
// sobre un módulo que requiere golang.org/x/text v0.3.5 y llama a
// language.Parse. GO-2021-0113 (Parse) debe aparecer; GO-2022-1059 vive en la
// misma dependencia pero nunca se llama, y NO debe aparecer — esa asimetría
// es exactamente lo que este motor aporta sobre trivy.
func TestIntegracionModuloVulnerable(t *testing.T) {
	if testing.Short() {
		t.Skip("integración: usa red y tarda varios segundos")
	}
	if _, err := exec.LookPath("govulncheck"); err != nil {
		t.Skip("govulncheck no está en PATH")
	}
	dir := t.TempDir()
	escribir := func(nombre, contenido string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, nombre), []byte(contenido), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	escribir("go.mod", "module fixturevuln\n\ngo 1.21\n\nrequire golang.org/x/text v0.3.5\n")
	escribir("main.go", `package main

import (
	"fmt"

	"golang.org/x/text/language"
)

func main() {
	tag, err := language.Parse("es-MX")
	fmt.Println(tag, err)
}
`)
	tidy := exec.Command("go", "mod", "tidy")
	tidy.Dir = dir
	if out, err := tidy.CombinedOutput(); err != nil {
		t.Fatalf("go mod tidy: %v\n%s", err, out)
	}

	e := &Engine{BlockReachable: true}
	fs, err := e.Run(context.Background(), engines.Input{
		RepoRoot: dir,
		Files:    []gitdiff.ChangedFile{{Path: "go.mod", Status: "M"}},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var ids []string
	for _, f := range fs {
		ids = append(ids, f.RuleKey)
	}
	if !slices.Contains(ids, "GO-2021-0113") {
		t.Errorf("falta GO-2021-0113 (language.Parse SÍ se llama); hallazgos: %v", ids)
	}
	if slices.Contains(ids, "GO-2022-1059") {
		t.Errorf("GO-2022-1059 está presente en la dependencia pero nunca se llama: reportarla es el ruido que este motor promete filtrar; hallazgos: %v", ids)
	}
}
