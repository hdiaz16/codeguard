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
	cfg := repoTemporal(t, map[string]string{"package.json": `{"name":"x"}`})
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
