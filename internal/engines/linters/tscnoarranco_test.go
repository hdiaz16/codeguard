package linters

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"codeguard/internal/engines"
	"codeguard/internal/gitdiff"
)

// EL CONTROL DEL OTRO LADO, CON TypeScript DE VERDAD.
//
// El motor exige ahora que tsc escriba algo: con --extendedDiagnostics imprime su
// bloque de estadísticas incluso sobre un proyecto impecable (medido con
// TypeScript 5.9.3: 768 bytes y código 0, donde con los argumentos anteriores
// había 0 bytes). Ese "escribió algo" es lo que separa «compilé y no hay errores»
// de «no compilé nada».
//
// Y aquí está el riesgo del arreglo, que es el simétrico del fallo que cierra: si
// esa exigencia fuera falsa —porque la versión de tsc del equipo no admita la
// bandera, o porque el bloque no salga por stdout—, TODOS los proyectos limpios
// de TypeScript verían su capa de tipos degradada en cada commit. Y eso no lo
// caza ningún test con dobles: el impostor lo escribo yo, así que probaría mi
// propia expectativa contra sí misma. Hace falta el compilador real.
//
// Necesita un proyecto con typescript instalado, así que se apunta con
// CODEGUARD_TOY_TS y se salta sola donde no lo haya (misma convención que las
// pruebas de eslint y mypy).
func TestConTypeScriptRealUnProyectoLimpioSigueLimpio(t *testing.T) {
	if testing.Short() {
		t.Skip("integración: lanza el compilador de TypeScript real")
	}
	raiz := os.Getenv("CODEGUARD_TOY_TS")
	if raiz == "" {
		t.Skip("apunta CODEGUARD_TOY_TS a un proyecto con node_modules y typescript")
	}
	if _, err := os.Stat(filepath.Join(raiz, "node_modules", ".bin", "tsc.cmd")); err != nil {
		t.Skipf("en %s no hay un typescript instalado que ejercitar: %v", raiz, err)
	}

	in := engines.Input{
		RepoRoot: raiz,
		Files:    []gitdiff.ChangedFile{{Path: "src/bien.ts", Status: "M"}},
	}
	if !(Tsc{}).Applies(in) {
		t.Fatal("control: el proyecto de juguete tiene tsconfig y un .ts tocado")
	}

	hallazgos, err := (Tsc{}).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("tsc compiló un proyecto limpio y el motor se declaró incapaz.\n"+
			"Con esto, cada commit limpio de TypeScript pinta la capa de tipos en naranja: %v", err)
	}
	if len(hallazgos) != 0 {
		t.Errorf("un proyecto bien tipado no tiene hallazgos, y salieron %d: %+v",
			len(hallazgos), hallazgos)
	}
}

// Y la otra mitad del control: el bloque de estadísticas no se puede comer los
// diagnósticos.
//
// Añadir --extendedDiagnostics mete en la salida cientos de bytes que ANTES no
// estaban, y el parseo es línea a línea sobre esa misma salida. Además el código
// de salida cambia con la bandera (medido: un error de tipos sale con 2 sin ella y
// con 1 con ella), así que si el motor dependiera del código concreto, dejaría de
// ver los errores. Un arreglo del silencio que perdiera los hallazgos habría
// cambiado un fallo por otro peor.
func TestConTypeScriptRealLosErroresDeTiposSiguenSaliendo(t *testing.T) {
	if testing.Short() {
		t.Skip("integración: lanza el compilador de TypeScript real")
	}
	raiz := os.Getenv("CODEGUARD_TOY_TS")
	if raiz == "" {
		t.Skip("apunta CODEGUARD_TOY_TS a un proyecto con node_modules y typescript")
	}
	if _, err := os.Stat(filepath.Join(raiz, "node_modules", ".bin", "tsc.cmd")); err != nil {
		t.Skipf("en %s no hay un typescript instalado que ejercitar: %v", raiz, err)
	}

	// Un archivo propio, con nombre reconocible, y se borra al terminar: el
	// proyecto de juguete es de quien lo instaló y tiene que quedar como estaba.
	rel := "src/control_codeguard.ts"
	ruta := filepath.Join(raiz, filepath.FromSlash(rel))
	if err := os.WriteFile(ruta, []byte("export const mal: string = 5;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(ruta) })

	hallazgos, err := (Tsc{}).Run(context.Background(), engines.Input{
		RepoRoot: raiz,
		Files:    []gitdiff.ChangedFile{{Path: rel, Status: "M"}},
	})
	if err != nil {
		t.Fatalf("el proyecto compila y tiene UN error de tipos: eso son hallazgos, "+
			"no una avería del motor: %v", err)
	}
	var visto bool
	for _, h := range hallazgos {
		if h.File == rel {
			visto = true
			if !h.Blocking {
				t.Error("un error de tipos bloquea (§7)")
			}
			if h.Line != 1 {
				t.Errorf("línea = %d, se esperaba 1", h.Line)
			}
		}
	}
	if !visto {
		t.Errorf("el error de tipos de %s no llegó a hallazgo. El bloque de estadísticas de "+
			"--extendedDiagnostics se está comiendo el parseo. Hallazgos: %+v", rel, hallazgos)
	}
}

// EL VERDE SILENCIOSO: tsc que NO compiló nada y el commit sale con ✓.
//
// Medido en la máquina de Héctor con un repo real (demo-checkout): sin
// node_modules, el motor cae a `npx --no-install tsc`, y en esa máquina eso
// resuelve a un paquete de npm llamado `tsc` que NO ES TypeScript — un stub que
// imprime "This is not the tsc command you are looking for" y sale con código 1.
//
// El parser no encuentra ni un diagnóstico en ese banner, así que devolvía CERO
// hallazgos… que es exactamente lo mismo que devuelve un proyecto impecable.
// Resultado: un `return centavos` donde la función promete string entró al
// repositorio con "formato/lint/tipos/reglas/migraciones ✓". La capa de tipos
// no miró nada y el panel dijo que estaba limpia.
//
// Es la peor clase de fallo para este producto, porque el silencio que produce
// es idéntico al del éxito. Y no lo cazaba nadie: `runTool` tolera la salida
// distinta de cero A PROPÓSITO —los linters salen con error cuando encuentran
// cosas— así que el error del stub se leía como "corrió y no encontró nada".
//
// La regla que lo distingue, y que es cierta para tsc de verdad:
//   - proyecto limpio  → sale 0            → sin diagnósticos, limpio. Correcto.
//   - proyecto con errores → sale ≠0       → CON diagnósticos, hallazgos.
//   - tsc que no arranca   → sale ≠0       → SIN diagnósticos: no se puede decir
//     que esté limpio, porque nadie lo miró.
func TestUnTscQueNoCompilaNoPuedeReportarLimpio(t *testing.T) {
	raiz := t.TempDir()
	dir := filepath.Join(raiz, "web")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for nombre, contenido := range map[string]string{
		"tsconfig.json": `{"compilerOptions":{"strict":true}}`,
		"src/api.ts":    "export function f(n: number): string { return n; }\n",
	} {
		ruta := filepath.Join(dir, filepath.FromSlash(nombre))
		if err := os.MkdirAll(filepath.Dir(ruta), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(ruta, []byte(contenido), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	in := engines.Input{
		RepoRoot: raiz,
		Files:    []gitdiff.ChangedFile{{Path: "web/src/api.ts", Status: "M"}},
	}
	e := Tsc{}
	if !e.Applies(in) {
		t.Fatal("control: el proyecto tiene tsconfig y un .ts tocado, tsc aplica")
	}

	hallazgos, err := e.Run(context.Background(), in)

	// El único resultado prohibido es el de hoy: cero hallazgos Y sin error.
	// Eso es "revisé y está limpio" sobre un archivo con un error de tipos de
	// manual, y es lo que dejó pasar el commit.
	if err == nil && len(hallazgos) == 0 {
		t.Error("tsc devolvió LIMPIO sobre un archivo con un error de tipos evidente.\n" +
			"O compiló y encontró el error (hallazgos > 0), o no pudo compilar y hay que\n" +
			"decirlo (error != nil). Decir que está limpio sin haber mirado es la única\n" +
			"respuesta que este producto no se puede permitir: el ✓ verde se lee igual\n" +
			"que el de un proyecto de verdad revisado.")
	}
	if err != nil {
		t.Logf("tsc no pudo correr y lo dice, que es lo correcto: %v", err)
	}
}
