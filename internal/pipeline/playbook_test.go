package pipeline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codeguard/internal/config"
	"codeguard/internal/gitdiff"
)

func repoTemporal(t *testing.T, archivos map[string]string) *config.Config {
	t.Helper()
	dir := t.TempDir()
	for ruta, contenido := range archivos {
		abs := filepath.Join(dir, filepath.FromSlash(ruta))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte(contenido), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return &config.Config{RepoRoot: dir}
}

func cambios(rutas ...string) []gitdiff.ChangedFile {
	out := make([]gitdiff.ChangedFile, 0, len(rutas))
	for _, r := range rutas {
		out = append(out, gitdiff.ChangedFile{Path: r, Status: "M"})
	}
	return out
}

func TestLockfileAusenteBloquea(t *testing.T) {
	// El fixture declara una dependencia real a propósito: sin ninguna, no hay
	// nada que fijar y la regla ya no aplica (ver TestSinDependenciasNoExigeLockfile).
	cfg := repoTemporal(t, map[string]string{"package.json": `{"name":"x","dependencies":{"left-pad":"^1.3.0"}}`})
	fs := revisarLockfiles(cfg, cambios("package.json"))
	if len(fs) != 1 {
		t.Fatalf("se esperaba 1 hallazgo, hubo %d", len(fs))
	}
	if !fs[0].Blocking {
		t.Error("un proyecto sin lockfile debe bloquear: las dependencias no están fijadas")
	}
	if fs[0].RuleKey != "lockfile-ausente" {
		t.Errorf("regla %q", fs[0].RuleKey)
	}
}

// Un manifiesto sin dependencias externas no puede tener lockfile: `go mod
// tidy` corre limpio y no genera go.sum. Exigirlo era un bloqueo sin salida —
// el dev cumple la instrucción, el hallazgo sigue ahí, y sólo le queda el
// bypass. Sin dependencias tampoco hay riesgo: no hay versión que resolver.
func TestSinDependenciasNoExigeLockfile(t *testing.T) {
	casos := map[string]map[string]string{
		"go.mod sólo stdlib":       {"go.mod": "module x/y\n\ngo 1.26.3\n"},
		"package.json sin deps":    {"package.json": `{"name":"x","scripts":{"build":"tsc"}}`},
		"package.json deps vacías": {"package.json": `{"name":"x","dependencies":{}}`},
	}
	for nombre, archivos := range casos {
		cfg := repoTemporal(t, archivos)
		var ruta string
		for r := range archivos {
			ruta = r
		}
		if fs := revisarLockfiles(cfg, cambios(ruta)); len(fs) != 0 {
			t.Errorf("%s: no debía haber hallazgos, hubo %d: %s", nombre, len(fs), fs[0].Message)
		}
	}
}

// Pero un require sí exige go.sum: ahí la protección es real.
func TestGoModConRequiresSiExigeLockfile(t *testing.T) {
	casos := map[string]string{
		"require en bloque": "module x\n\ngo 1.26.3\n\nrequire (\n\tgithub.com/spf13/cobra v1.10.2\n)\n",
		"require en línea":  "module x\n\ngo 1.26.3\n\nrequire github.com/spf13/cobra v1.10.2\n",
		"require comentado en bloque vacío": "module x\n\nrequire (\n\t// github.com/x/y v1.0.0\n)\n" +
			"\nrequire github.com/spf13/cobra v1.10.2\n",
	}
	for nombre, contenido := range casos {
		cfg := repoTemporal(t, map[string]string{"go.mod": contenido})
		fs := revisarLockfiles(cfg, cambios("go.mod"))
		if len(fs) != 1 || !fs[0].Blocking {
			t.Errorf("%s: se esperaba 1 hallazgo bloqueante, hubo %d", nombre, len(fs))
		}
	}
}

func TestLockfileDesincronizadoSoloAvisa(t *testing.T) {
	cfg := repoTemporal(t, map[string]string{
		"package.json":      `{"name":"x"}`,
		"package-lock.json": `{}`,
	})
	fs := revisarLockfiles(cfg, cambios("package.json"))
	if len(fs) != 1 {
		t.Fatalf("se esperaba 1 hallazgo, hubo %d", len(fs))
	}
	if fs[0].Blocking {
		t.Error("un lockfile desfasado avisa, no bloquea")
	}
	if !strings.Contains(fs[0].Message, "package-lock.json") {
		t.Errorf("el mensaje debe nombrar el lockfile: %q", fs[0].Message)
	}
}

func TestLockfileActualizadoNoDiceNada(t *testing.T) {
	cfg := repoTemporal(t, map[string]string{
		"package.json":      `{"name":"x"}`,
		"package-lock.json": `{}`,
	})
	if fs := revisarLockfiles(cfg, cambios("package.json", "package-lock.json")); len(fs) != 0 {
		t.Errorf("no debía haber hallazgos, hubo %d: %s", len(fs), fs[0].Message)
	}
}

// El manifiesto puede no estar en la raíz; el lockfile se busca al lado.
func TestLockfileEnSubdirectorio(t *testing.T) {
	cfg := repoTemporal(t, map[string]string{
		"servicios/api/go.mod": "module x",
		"servicios/api/go.sum": "",
	})
	fs := revisarLockfiles(cfg, cambios("servicios/api/go.mod"))
	if len(fs) != 1 || fs[0].Blocking {
		t.Fatalf("se esperaba un aviso por go.sum sin tocar, hubo %d hallazgos", len(fs))
	}
	fs = revisarLockfiles(cfg, cambios("servicios/api/go.mod", "servicios/api/go.sum"))
	if len(fs) != 0 {
		t.Errorf("con el go.sum tocado no debía avisar")
	}
}

func TestTamanoDelCambio(t *testing.T) {
	if fs := revisarTamano(&gitdiff.Diff{Lines: 399}, cambios("a.go")); len(fs) != 0 {
		t.Error("por debajo del límite no debe decir nada")
	}
	fs := revisarTamano(&gitdiff.Diff{Lines: 900}, cambios("a.go"))
	if len(fs) != 1 {
		t.Fatalf("se esperaba 1 hallazgo, hubo %d", len(fs))
	}
	if fs[0].Blocking {
		t.Error("el tamaño del cambio avisa, nunca bloquea: partirlo es decisión del autor")
	}
	if !strings.Contains(fs[0].Message, "900") {
		t.Errorf("el mensaje debe decir el tamaño real: %q", fs[0].Message)
	}
}

func TestComplejidadGoCuentaCaminos(t *testing.T) {
	src := []byte(`package p

func simple() int { return 1 }

func ramificada(x int) int {
	if x > 0 && x < 10 {
		for i := 0; i < x; i++ {
			if i%2 == 0 {
				return i
			}
		}
	}
	switch x {
	case 1:
		return 1
	case 2:
		return 2
	}
	return 0
}
`)
	fns := complejidadGo("p.go", src)
	got := map[string]int{}
	for _, f := range fns {
		got[f.Nombre] = f.Complejidad
	}
	if got["simple"] != 1 {
		t.Errorf("una función sin ramas tiene complejidad 1, dio %d", got["simple"])
	}
	// 1 base + if + && + for + if + 2 case = 7
	if got["ramificada"] != 7 {
		t.Errorf("complejidad de ramificada: %d, se esperaba 7", got["ramificada"])
	}
}

func TestComplejidadGoIgnoraCodigoRoto(t *testing.T) {
	if fns := complejidadGo("p.go", []byte("package p\nfunc x( {")); len(fns) != 0 {
		t.Error("código a medio escribir no es asunto de esta regla")
	}
}

func TestComplejidadNoCuentaPalabrasEnTextos(t *testing.T) {
	src := []byte(`function saludar(nombre) {
  const msg = "if for while case catch && ||";
  // if for while
  return msg + nombre;
}
`)
	fns := complejidadLlaves(src)
	if len(fns) != 1 {
		t.Fatalf("se esperaba 1 función, hubo %d", len(fns))
	}
	if fns[0].Complejidad != 1 {
		t.Errorf("las palabras dentro de cadenas y comentarios no bifurcan; dio %d", fns[0].Complejidad)
	}
}

func TestComplejidadLlavesCuentaRamas(t *testing.T) {
	src := []byte(`function decidir(a, b) {
  if (a && b) {
    for (let i = 0; i < a; i++) {
      if (i > 2) { return i; }
    }
  }
  return 0;
}
`)
	fns := complejidadLlaves(src)
	if len(fns) != 1 {
		t.Fatalf("se esperaba 1 función, hubo %d", len(fns))
	}
	// 1 base + if + && + for + if = 5
	if fns[0].Complejidad != 5 {
		t.Errorf("complejidad %d, se esperaba 5", fns[0].Complejidad)
	}
	if fns[0].Nombre != "decidir" {
		t.Errorf("nombre %q", fns[0].Nombre)
	}
}

func TestComplejidadAvisaSoloPorEncimaDelUmbral(t *testing.T) {
	// 20 ifs seguidos: muy por encima de cualquier umbral razonable.
	var b strings.Builder
	b.WriteString("package p\n\nfunc enorme(x int) int {\n")
	for i := 0; i < 20; i++ {
		b.WriteString("\tif x > 0 { x-- }\n")
	}
	b.WriteString("\treturn x\n}\n")

	cfg := repoTemporal(t, map[string]string{"grande.go": b.String()})
	fs := revisarComplejidad(cfg, cambios("grande.go"))
	if len(fs) != 1 {
		t.Fatalf("se esperaba 1 aviso, hubo %d", len(fs))
	}
	if fs[0].Blocking {
		t.Error("la complejidad avisa, nunca bloquea")
	}

	cfg.MaxComplexity = 100
	if fs := revisarComplejidad(cfg, cambios("grande.go")); len(fs) != 0 {
		t.Error("con el umbral subido no debía avisar")
	}
}
