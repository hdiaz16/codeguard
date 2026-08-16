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
	// Forma real del flujo, con la stdlib alcanzada a nivel símbolo. La cabecera
	// `config` va porque el flujo de verdad SIEMPRE abre con ella, y el motor la
	// exige: es su prueba de que quien escribió esto fue govulncheck y no una
	// herramienta cualquiera que salió con 0.
	payload := `{"config":{"scanner_name":"govulncheck","scanner_version":"v1.6.0"}}
{"osv":{"id":"GO-2026-5856","summary":"Ejemplo stdlib"}}
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
// PRESENTARSE NO ES ESCANEAR, y lo puso el validador midiendo: el mensaje
// `config` con el que govulncheck abre su flujo es byte a byte IDÉNTICO en la
// corrida sana y en las averiadas (289 bytes, mismos campos). Así que una
// comprobación que se apoye en «hay cabecera» no prueba nada.
//
// En sus escenarios el motor ya rechazaba por el código de salida, pero el caso
// que queda —presentarse, salir con 0 y callar— no lo cubría nadie.
func TestPresentarseSinEscanearNoEsUnModuloLimpio(t *testing.T) {
	soloCabecera := `{"config":{"scanner_name":"govulncheck","scanner_version":"v1.6.0"}}` + "\n"

	fs, err := interpretar([]byte(soloCabecera), ".", false)
	if err == nil {
		t.Fatalf("un flujo con la cabecera y nada más no es un escaneo, y devolvió %d "+
			"hallazgos sin error: eso llega al panel como capa revisada", len(fs))
	}
	if !strings.Contains(err.Error(), "no escaneó") {
		t.Errorf("el error debe decir que no escaneó, no que no se presentó: %v", err)
	}
	// Y el motivo tiene que distinguir las dos averías, porque mandan a mirar
	// sitios distintos.
	if !strings.Contains(err.Error(), "se presentó, pero no escaneó") {
		t.Errorf("con cabecera presente, el motivo tiene que decirlo: %v", err)
	}

	_, err = interpretar(nil, ".", false)
	if err == nil {
		t.Fatal("stdout vacío tampoco es un módulo limpio")
	}
	if !strings.Contains(err.Error(), "ni siquiera se presentó") {
		t.Errorf("sin cabecera, el motivo tiene que decir que no era govulncheck: %v", err)
	}
}

// EL CONTROL DEL ARREGLO DEL SILENCIO, con la herramienta de verdad.
//
// El motor ya no acepta un flujo sin la cabecera `config`, y esa exigencia se
// apoya en una medida —govulncheck abre siempre presentándose, incluso sobre un
// módulo limpio, donde escribió 393 983 bytes— pero una medida no es una prueba
// de que el código la lea bien. Si el nombre del campo estuviera mal escrito, o
// la cabecera cambiara de forma en una versión futura, TODOS los módulos limpios
// pasarían a "capa degradada" y en local nadie lo notaría enseguida: govulncheck
// sólo corre cuando cambian los manifiestos.
//
// El test de integración que ya existía usa un módulo VULNERABLE, así que pasa
// por el camino con hallazgos; el limpio, que es el que produce cero, no lo
// ejercitaba nadie.
func TestIntegracionModuloLimpioNoSeDegrada(t *testing.T) {
	if testing.Short() {
		t.Skip("integración: usa red y tarda varios segundos")
	}
	if _, err := exec.LookPath("govulncheck"); err != nil {
		t.Skip("govulncheck no está en PATH")
	}
	dir := t.TempDir()
	for nombre, contenido := range map[string]string{
		"go.mod":  "module fixturelimpio\n\ngo 1.21\n",
		"main.go": "package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(\"hola\") }\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, nombre), []byte(contenido), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	fs, err := (&Engine{}).Run(context.Background(), engines.Input{
		RepoRoot: dir,
		Files:    []gitdiff.ChangedFile{{Path: "go.mod", Status: "M"}},
	})
	if err != nil {
		t.Fatalf("govulncheck analizó un módulo sin dependencias y el motor se declaró "+
			"incapaz. Con esto, todo módulo limpio queda como capa degradada: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("un módulo sin dependencias no tiene vulnerabilidades, y salieron %d: %+v",
			len(fs), fs)
	}
}

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

// Una vulnerabilidad alcanzada por varios caminos es UN hallazgo, no varios.
//
// govulncheck emite un hallazgo de nivel símbolo por cada ruta de llamada, así
// que en el backend de un repo real 9 vulnerabilidades se convertían en 28
// hallazgos — mientras la propia herramienta decía "your code is affected by 8".
// Inflar el problema por tres no lo hace más urgente, lo hace menos creíble; y
// el remedio de todas las rutas es el mismo, subir el módulo una vez.
func TestVariasRutasALaMismaVulnerabilidadSonUnHallazgo(t *testing.T) {
	// Misma OSV alcanzada desde dos sitios distintos del código propio, con la
	// cabecera con la que govulncheck abre siempre su flujo.
	payload := `{"config":{"scanner_name":"govulncheck","scanner_version":"v1.6.0"}}
{"osv":{"id":"GO-2026-0001","summary":"Fallo en el parser"}}
{"finding":{"osv":"GO-2026-0001","fixed_version":"v1.2.3","trace":[{"module":"ejemplo.com/lib","version":"v1.0.0","package":"ejemplo.com/lib","function":"Parse","position":{"filename":"lib/parse.go","line":10}},{"module":"m","package":"m","function":"Segundo","position":{"filename":"internal/b.go","line":50}}]}}
{"finding":{"osv":"GO-2026-0001","fixed_version":"v1.2.3","trace":[{"module":"ejemplo.com/lib","version":"v1.0.0","package":"ejemplo.com/lib","function":"Parse","position":{"filename":"lib/parse.go","line":10}},{"module":"m","package":"m","function":"Primero","position":{"filename":"cmd/a.go","line":20}}]}}
`
	fs, err := interpretar([]byte(payload), ".", false)
	if err != nil {
		t.Fatalf("interpretar: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("dos rutas hacia la MISMA vulnerabilidad son un hallazgo, llegaron %d: %+v", len(fs), fs)
	}
	// Se conserva la primera en orden estable (archivo, línea) para que la
	// huella no baile entre corridas.
	if fs[0].File != "cmd/a.go" || fs[0].Line != 20 {
		t.Errorf("debía anclarse en la primera ruta en orden estable, llegó %s:%d", fs[0].File, fs[0].Line)
	}
	if !strings.Contains(fs[0].Message, "desde 2 sitios") {
		t.Errorf("el mensaje debe decir cuántas rutas hay para que nadie crea que se le escapó una: %q", fs[0].Message)
	}
}
