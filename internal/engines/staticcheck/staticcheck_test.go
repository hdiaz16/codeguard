package staticcheck

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"codeguard/internal/engines"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
)

// dirCaptura es el directorio del módulo de juguete sobre el que se capturaron
// los payloads de abajo. Los paths de location llegan ABSOLUTOS, en la forma
// que tuviera el directorio de trabajo (aquí la larga, porque PowerShell
// canonicaliza el cwd); interpretar los recorta contra las bases que reciba.
const dirCaptura = `C:\Users\dev\AppData\Local\Temp\claude\C--Users-dev-proyecto\21867769-946e-43a7-a2eb-657c824f2799\scratchpad\toymod`

// Capturado de staticcheck 2026.1 (v0.7.0) con `staticcheck -f json ./ ./sub`
// sobre un módulo de juguete, tal cual: un objeto por línea, con la severidad
// por defecto ("error" para todo problema real) y el path absoluto repetido en
// location y end. SA4006 y S1002 viven en main.go; S1003 en el subpaquete
// sub/ — ese es el que prueba que el recorte conserva la ruta interna.
const capturaReal = `{"code":"SA4006","severity":"error","location":{"file":"C:\\Users\\dev\\AppData\\Local\\Temp\\claude\\C--Users-dev-proyecto\\21867769-946e-43a7-a2eb-657c824f2799\\scratchpad\\toymod\\main.go","line":6,"column":2},"end":{"file":"C:\\Users\\dev\\AppData\\Local\\Temp\\claude\\C--Users-dev-proyecto\\21867769-946e-43a7-a2eb-657c824f2799\\scratchpad\\toymod\\main.go","line":6,"column":13},"message":"this value of x is never used"}
{"code":"S1002","severity":"error","location":{"file":"C:\\Users\\dev\\AppData\\Local\\Temp\\claude\\C--Users-dev-proyecto\\21867769-946e-43a7-a2eb-657c824f2799\\scratchpad\\toymod\\main.go","line":10,"column":5},"end":{"file":"C:\\Users\\dev\\AppData\\Local\\Temp\\claude\\C--Users-dev-proyecto\\21867769-946e-43a7-a2eb-657c824f2799\\scratchpad\\toymod\\main.go","line":10,"column":15},"message":"should omit comparison to bool constant, can be simplified to ok"}
{"code":"S1003","severity":"error","location":{"file":"C:\\Users\\dev\\AppData\\Local\\Temp\\claude\\C--Users-dev-proyecto\\21867769-946e-43a7-a2eb-657c824f2799\\scratchpad\\toymod\\sub\\sub.go","line":7,"column":9},"end":{"file":"C:\\Users\\dev\\AppData\\Local\\Temp\\claude\\C--Users-dev-proyecto\\21867769-946e-43a7-a2eb-657c824f2799\\scratchpad\\toymod\\sub\\sub.go","line":7,"column":35},"message":"should use strings.Contains(s, \"x\") instead"}
`

// Capturado con `-fail SA` en la misma corrida: lo que queda fuera del
// conjunto -fail baja a "warning". La invocación del motor no usa -fail, pero
// la forma es real y el mapeo tiene que respetarla.
const capturaWarning = `{"code":"SA4006","severity":"warning","location":{"file":"C:\\Users\\dev\\AppData\\Local\\Temp\\claude\\C--Users-dev-proyecto\\21867769-946e-43a7-a2eb-657c824f2799\\scratchpad\\toymod\\main.go","line":6,"column":2},"end":{"file":"C:\\Users\\dev\\AppData\\Local\\Temp\\claude\\C--Users-dev-proyecto\\21867769-946e-43a7-a2eb-657c824f2799\\scratchpad\\toymod\\main.go","line":6,"column":13},"message":"this value of x is never used"}
`

// Capturado con //lint:ignore en el código y `-show-ignored`: la supresión
// del propio desarrollador se respeta descartando el problema.
const capturaIgnorada = `{"code":"S1002","severity":"ignored","location":{"file":"C:\\Users\\dev\\AppData\\Local\\Temp\\claude\\C--Users-dev-proyecto\\21867769-946e-43a7-a2eb-657c824f2799\\scratchpad\\toymod\\main.go","line":8,"column":5},"end":{"file":"C:\\Users\\dev\\AppData\\Local\\Temp\\claude\\C--Users-dev-proyecto\\21867769-946e-43a7-a2eb-657c824f2799\\scratchpad\\toymod\\main.go","line":8,"column":15},"message":"should omit comparison to bool constant, can be simplified to ok"}
`

// Capturado sobre un módulo con un error de sintaxis: el fallo de compilación
// NO llega por stderr ni con código mayor que 1 — llega como pseudo-problema
// "compile" con salida 1, el mismo código de "encontré algo".
const capturaCompile = `{"code":"compile","severity":"error","location":{"file":"","line":0,"column":0},"end":{"file":"","line":0,"column":0},"message":"# toybroken\n.\\main.go:5:1: syntax error: unexpected }, expected expression"}
`

func TestErroresBloqueanYNormalizanPaths(t *testing.T) {
	fs, err := interpretar([]byte(capturaReal), ".", dirCaptura)
	if err != nil {
		t.Fatalf("interpretar: %v", err)
	}
	if len(fs) != 3 {
		t.Fatalf("esperaba 3 hallazgos, hay %d: %+v", len(fs), fs)
	}
	f := fs[0]
	if f.RuleKey != "SA4006" || f.Engine != "staticcheck" {
		t.Errorf("RuleKey/Engine = %q/%q, esperaba SA4006/staticcheck", f.RuleKey, f.Engine)
	}
	if f.File != "main.go" || f.Line != 6 {
		t.Errorf("posición = %s:%d, esperaba main.go:6 (el path absoluto debe quedar relativo al repo)", f.File, f.Line)
	}
	if f.Severity != finding.Error || !f.Blocking {
		t.Errorf("severidad error debe bloquear (política §7, como govet): %+v", f)
	}
	if f.Message != "this value of x is never used" {
		t.Errorf("Message = %q", f.Message)
	}
	if !strings.Contains(f.Why, "SSA") {
		t.Errorf("el porqué debe explicar que el bug se demuestra sobre el SSA: %q", f.Why)
	}
	if !strings.Contains(f.FixHint, "SA4006") {
		t.Errorf("el FixHint debe llevar a la ficha de la regla: %q", f.FixHint)
	}
	if f.Fingerprint == "" {
		t.Error("falta el fingerprint")
	}
	if fs[2].File != "sub/sub.go" {
		t.Errorf("el recorte debe conservar la ruta interna al módulo: %q", fs[2].File)
	}
}

func TestMonorepoPrefijaElModulo(t *testing.T) {
	fs, err := interpretar([]byte(capturaReal), "backend", dirCaptura)
	if err != nil {
		t.Fatalf("interpretar: %v", err)
	}
	if len(fs) != 3 || fs[0].File != "backend/main.go" || fs[2].File != "backend/sub/sub.go" {
		t.Fatalf("con el módulo en un subdirectorio los paths deben llevar su prefijo: %+v", fs)
	}
}

func TestWarningAvisaSinBloquear(t *testing.T) {
	fs, err := interpretar([]byte(capturaWarning), ".", dirCaptura)
	if err != nil {
		t.Fatalf("interpretar: %v", err)
	}
	if len(fs) != 1 || fs[0].Severity != finding.Warning || fs[0].Blocking {
		t.Fatalf("un warning avisa sin bloquear: %+v", fs)
	}
}

func TestIgnoradoSeDescarta(t *testing.T) {
	fs, err := interpretar([]byte(capturaIgnorada), ".", dirCaptura)
	if err != nil {
		t.Fatalf("interpretar: %v", err)
	}
	if len(fs) != 0 {
		t.Fatalf("un problema suprimido con //lint:ignore no debe reportarse: %+v", fs)
	}
}

func TestCompilacionRotaDegrada(t *testing.T) {
	_, err := interpretar([]byte(capturaCompile), ".", dirCaptura)
	if err == nil || !strings.Contains(err.Error(), "no pudo compilar") {
		t.Fatalf("sin programa no hay SSA: el motor debe degradarse con el detalle, no callar ni bloquear; err = %v", err)
	}
}

func TestSalidaIlegible(t *testing.T) {
	if _, err := interpretar([]byte(`{"code": {rota`), ".", dirCaptura); err == nil {
		t.Fatal("una salida ilegible debe degradar el motor, no callar")
	}
}

// ── selección de módulos y paquetes ──────────────────────────────────────────

func repoDePrueba(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"backend", "frontend"} {
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

func TestModulosAgrupaPorModuloYPaquete(t *testing.T) {
	e := &Engine{}
	in := engines.Input{RepoRoot: repoDePrueba(t), Files: []gitdiff.ChangedFile{
		{Path: "main.go", Status: "A"},
		{Path: "cmd/tool/main.go", Status: "M"},
		{Path: "backend/main.go", Status: "M"},
		{Path: "backend/internal/api/handler.go", Status: "M"},
		{Path: "backend/internal/api/otro.go", Status: "M"}, // mismo paquete: no duplica
		{Path: "frontend/app.ts", Status: "M"},
		{Path: "backend/borrado.go", Status: "D"},
	}}
	got := e.modulos(in)
	want := map[string][]string{
		".":       {"./", "./cmd/tool"},
		"backend": {"./", "./internal/api"},
	}
	if len(got) != len(want) {
		t.Fatalf("modulos = %v, esperaba %v", got, want)
	}
	for mod, pkgs := range want {
		g := got[mod]
		if len(g) != len(pkgs) {
			t.Fatalf("paquetes de %s = %v, esperaba %v", mod, g, pkgs)
		}
		for i := range pkgs {
			if g[i] != pkgs[i] {
				t.Fatalf("paquetes de %s = %v, esperaba %v", mod, g, pkgs)
			}
		}
	}
	if !e.Applies(in) {
		t.Fatal("con archivos .go y go.mod alcanzable el motor aplica")
	}
}

func TestSinGoModNoAplica(t *testing.T) {
	root := t.TempDir() // sin ningún go.mod
	e := &Engine{}
	in := engines.Input{RepoRoot: root, Files: []gitdiff.ChangedFile{
		{Path: "script.go", Status: "M"},
	}}
	if e.Applies(in) {
		t.Fatal("un .go suelto sin go.mod alcanzable no da módulo que analizar")
	}
}

// ── integración de punta a punta ─────────────────────────────────────────────

// TestIntegracionCazaBugsDemostrables corre el binario real (sandbox incluido)
// sobre un monorepo de juguete: la raíz con SA4006 (valor asignado y jamás
// leído) y backend/ —módulo propio— con S1002 (comparación redundante con
// true). Ambos deben aparecer con severidad error y bloqueando, y el del
// módulo anidado con su prefijo — el caso monorepo que govet no soporta.
func TestIntegracionCazaBugsDemostrables(t *testing.T) {
	if testing.Short() {
		t.Skip("integración: compila los módulos y tarda varios segundos")
	}
	if _, err := exec.LookPath("staticcheck"); err != nil {
		t.Skip("staticcheck no está en PATH")
	}
	root := t.TempDir()
	escribir := func(nombre, contenido string) {
		t.Helper()
		ruta := filepath.Join(root, filepath.FromSlash(nombre))
		if err := os.MkdirAll(filepath.Dir(ruta), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(ruta, []byte(contenido), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	escribir("go.mod", "module raiz\n\ngo 1.21\n")
	escribir("main.go", `package main

import "fmt"

func main() {
	x := calc()
	x = 2
	fmt.Println(x)
}

func calc() int { return 1 }
`)
	escribir("backend/go.mod", "module backend\n\ngo 1.21\n")
	escribir("backend/main.go", `package main

import "fmt"

func main() {
	ok := true
	if ok == true {
		fmt.Println("si")
	}
}
`)

	e := &Engine{}
	fs, err := e.Run(context.Background(), engines.Input{
		RepoRoot: root,
		Files: []gitdiff.ChangedFile{
			{Path: "main.go", Status: "M"},
			{Path: "backend/main.go", Status: "M"},
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	porRegla := map[string]finding.Finding{}
	for _, f := range fs {
		porRegla[f.RuleKey] = f
	}
	sa, okSA := porRegla["SA4006"]
	if !okSA || sa.File != "main.go" || sa.Line != 6 {
		t.Errorf("falta SA4006 en main.go:6 (x se asigna y jamás se lee); hallazgos: %+v", fs)
	}
	s1, okS1 := porRegla["S1002"]
	if !okS1 || s1.File != "backend/main.go" {
		t.Errorf("falta S1002 con el prefijo del módulo anidado; hallazgos: %+v", fs)
	}
	for _, f := range fs {
		if f.Severity != finding.Error || !f.Blocking || !f.Verified || f.Fingerprint == "" {
			t.Errorf("cada hallazgo debe ser error bloqueante, verificado y con fingerprint: %+v", f)
		}
	}
}

// EL CONTROL DEL ARREGLO DEL SILENCIO, y el que más falta hacía.
//
// staticcheck limpio no escribe NADA y sale con 0 (medido: 0 bytes). Eso es
// indistinguible de un impostor que no hizo nada, así que ante ese silencio el
// motor le pregunta a la herramienta quién es. Y ahí está el riesgo de este
// arreglo, que es el inverso del fallo que cierra: si el patrón que reconoce la
// respuesta estuviera mal escrito, TODOS los commits limpios de Go verían su capa
// de staticcheck en naranja, cada vez, sin que ninguna otra prueba lo notara —
// los dos tests de integración que ya había ejercitan módulos con hallazgos y uno
// que no compila; ninguno pasa por el caso limpio.
//
// Tiene que correr con el binario de VERDAD: con un doble, la respuesta a
// -version la escribiría yo, y probaría mi propia expectativa contra sí misma.
func TestIntegracionModuloLimpioSigueSiendoLimpio(t *testing.T) {
	if testing.Short() {
		t.Skip("integración: compila el módulo y tarda unos segundos")
	}
	if _, err := exec.LookPath("staticcheck"); err != nil {
		t.Skip("staticcheck no está en PATH")
	}
	root := t.TempDir()
	escribir := func(nombre, contenido string) {
		t.Helper()
		ruta := filepath.Join(root, filepath.FromSlash(nombre))
		if err := os.MkdirAll(filepath.Dir(ruta), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(ruta, []byte(contenido), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	escribir("go.mod", "module limpio\n\ngo 1.21\n")
	escribir("main.go", "package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(sumar(1, 2)) }\n\n"+
		"func sumar(a, b int) int { return a + b }\n")

	fs, err := (&Engine{}).Run(context.Background(), engines.Input{
		RepoRoot: root,
		Files:    []gitdiff.ChangedFile{{Path: "main.go", Status: "M"}},
	})
	if err != nil {
		t.Fatalf("staticcheck analizó un módulo limpio y el motor se declaró incapaz.\n"+
			"Con esto, cada commit limpio de Go pinta la capa en naranja: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("un módulo limpio no tiene hallazgos, y salieron %d: %+v", len(fs), fs)
	}
}

// TestIntegracionCompilacionRotaDegrada: un módulo que no compila no produce
// hallazgos a medias — el motor entero se degrada con el detalle y el error
// real lo señalan gofmt/govet.
func TestIntegracionCompilacionRotaDegrada(t *testing.T) {
	if testing.Short() {
		t.Skip("integración: compila el módulo y tarda unos segundos")
	}
	if _, err := exec.LookPath("staticcheck"); err != nil {
		t.Skip("staticcheck no está en PATH")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module roto\n\ngo 1.21\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n\nfunc main() {\n\tx :=\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e := &Engine{}
	_, err := e.Run(context.Background(), engines.Input{
		RepoRoot: root,
		Files:    []gitdiff.ChangedFile{{Path: "main.go", Status: "M"}},
	})
	if err == nil || !strings.Contains(err.Error(), "no pudo compilar") {
		t.Fatalf("sin compilar no hay SSA: Run debe degradar con mensaje claro; err = %v", err)
	}
}
