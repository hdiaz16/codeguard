package linters

// Un fallo de CARGA no puede parecerse a un repo limpio.
//
// `go vet` sale distinto de cero por dos motivos que no tienen nada que ver:
// porque encontró algo (lo normal, y por eso runTool descarta el código de
// salida) y porque no pudo cargar los paquetes. En el segundo caso NO analiza
// nada —ni siquiera los paquetes que sí compilaban— y el motor devolvía cero
// hallazgos: el informe daba la capa por revisada.
//
// Se descubrió midiendo un repo real: `go vet ./...` señalaba un Sprintf mal
// formado y el agente decía «govet: 0 hallazgos», porque otro directorio del
// diff tenía dos paquetes distintos en la misma carpeta. staticcheck, ante
// exactamente el mismo repo, sí se declaraba degradado.

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

func repoGo(t *testing.T) (string, func(rel, contenido string)) {
	t.Helper()
	root := t.TempDir()
	escribir := func(rel, contenido string) {
		t.Helper()
		abs := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte(contenido), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	escribir("go.mod", "module prueba\n\ngo 1.21\n")
	return root, escribir
}

func TestGoVetNoDaLimpioCuandoNoPudoCargar(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("sin toolchain de Go no hay nada que cargar")
	}
	root, escribir := repoGo(t)

	// Dos paquetes distintos en el MISMO directorio: go los rechaza al cargar.
	// Es el caso real que lo destapó — un directorio con fixtures de varios
	// paquetes dentro del diff.
	escribir("roto/uno.go", "package uno\n\nfunc Uno() int { return 1 }\n")
	escribir("roto/dos.go", "package dos\n\nfunc Dos() int { return 2 }\n")

	in := engines.Input{RepoRoot: root, Files: []gitdiff.ChangedFile{
		{Path: "roto/uno.go", Status: "M"},
		{Path: "roto/dos.go", Status: "M"},
	}}

	fs, err := (GoVet{}).Run(context.Background(), in)
	if err == nil {
		t.Errorf("go vet no pudo cargar los paquetes y el motor devolvió %d hallazgos SIN error.\n"+
			"Eso llega al informe como una capa revisada y limpia, que es la peor mentira "+
			"posible: el usuario commitea creyendo que pasó por govet.", len(fs))
	} else if !strings.Contains(err.Error(), "no pudo analizar") {
		t.Errorf("el error no explica que no se pudo analizar: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("con un fallo de carga no puede haber hallazgos, y devolvió %d", len(fs))
	}
}

// La distinción "no analizó" vs "analizó y encontró varias cosas" se decide
// línea a línea, no sobre el texto entero.
//
// La comprobación vivía como una regex anclada (^…$, sin (?m)) aplicada a la
// salida COMPLETA, y en Go el punto no casa con el salto de línea: sólo daba
// verdadero si toda la salida era UNA sola línea de diagnóstico. En cuanto vet
// reportaba dos hallazgos —o antecedía el bloque con la cabecera "# paquete"—,
// la salida era perfectamente válida y el motor la declaraba fallo de carga:
// hallazgos reales perdidos y una compuerta bloqueante disparándose en falso.
func TestHallazgosVetDistingueDiagnosticosDeFalloDeCarga(t *testing.T) {
	casos := []struct {
		nombre   string
		informe  string // stdout: el JSON de vet, que es su prueba de haber analizado
		motivos  string // stderr: los paquetes que no pudo cargar, y el ruido del toolchain
		hallazgo int
		quiereEr bool
		motivo   string // trozo que el error tiene que contener; vacío = "no pudo analizar"
	}{
		{
			nombre:   "dos diagnósticos en dos líneas",
			motivos:  "a.go:10:2: msg uno\nb.go:20:3: msg dos",
			hallazgo: 2,
		},
		{
			nombre:   "cabecera de paquete antes del diagnóstico",
			motivos:  "# ejemplo.com/paquete\na.go:10:2: msg",
			hallazgo: 1,
		},
		{
			nombre:   "un solo diagnóstico",
			motivos:  "a.go:10:2: msg",
			hallazgo: 1,
		},
		{
			// AQUÍ ESTABA LA PUERTA ABIERTA, y este caso la defendía.
			//
			// Decía que la salida vacía es un repo limpio, y era verdad de `go
			// vet` a secas: analiza, no encuentra nada y no imprime. El problema
			// es que una herramienta que NO ES vet y no hace nada produce ese
			// mismo vacío, y el motor no tenía forma de elegir bien.
			//
			// Con -json ya no hay empate: vet limpio escribe `{}`. Callar por los
			// dos canales no es un resultado que vet pueda dar.
			nombre:   "callar por los dos canales ya NO es un repo limpio",
			quiereEr: true,
			motivo:   "no escribió NADA",
		},
		{
			nombre:  "el `{}` de vet es el repo limpio de verdad",
			informe: "{}",
		},
		{
			nombre:   "fallo de carga en una línea",
			motivos:  "go: error loading module requirements",
			quiereEr: true,
		},
		{
			nombre:   "fallo de carga en varias líneas",
			motivos:  "# ejemplo.com/paquete\nfound packages uno (uno.go) and dos (dos.go) in /tmp/roto",
			quiereEr: true,
		},
		{
			// La descarga fallida conserva la ubicación del import y por eso
			// parece un diagnóstico de vet. Pero describe el egress-hint, no una
			// construcción del código: no debe publicarse como finding.Error en
			// SARIF ni quedar marcada como "verificada".
			nombre: "fallo de red con ruta y línea es infraestructura",
			motivos: "cmd/daemon/main.go:14:2: github.com/wailsapp/wails/v3@v3.0.0-beta.5: " +
				"Get \"https://proxy.golang.org/github.com/wailsapp/wails/v3/@v/v3.0.0-beta.5.zip\": " +
				"proxyconnect tcp: dial tcp 127.0.0.1:9: connectex: No connection could be made",
			quiereEr: true,
			motivo:   "fallo de infraestructura",
		},
		{
			// El falso positivo que la mezcla de canales causaba: `go:
			// downloading` va por stderr y no es un diagnóstico, así que la
			// comprobación anterior lo tomaba por un fallo de carga y degradaba la
			// capa sobre un módulo que vet había analizado perfectamente.
			nombre:  "el ruido del toolchain en stderr no invalida el análisis",
			informe: "{}",
			motivos: "go: downloading github.com/ejemplo/x v1.4.0",
		},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			fs, err := hallazgosVet(t.TempDir(), c.informe, c.motivos, []string{"./x"})
			if c.quiereEr {
				if err == nil {
					t.Fatalf("una salida que vet no pudo analizar tiene que degradar la capa, "+
						"y devolvió %d hallazgos sin error", len(fs))
				}
				// El motivo tiene que estar EN el error: es lo único que le queda
				// a quien luego tenga que diagnosticarlo desde el log.
				esperado := c.motivo
				if esperado == "" {
					esperado = "no pudo analizar"
				}
				if !strings.Contains(err.Error(), esperado) {
					t.Errorf("el error no explica el motivo (%q): %v", esperado, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("vet SÍ analizó y el motor se declaró roto: %v", err)
			}
			if len(fs) != c.hallazgo {
				t.Fatalf("se esperaban %d hallazgos y salieron %d", c.hallazgo, len(fs))
			}
		})
	}
}

// El File de un hallazgo tiene que ser una ruta que se pueda ABRIR.
//
// Desde que la señal de "no pudo cargar" se deriva del bucle de parseo, los
// errores de COMPILACIÓN entran por la misma puerta que los diagnósticos —que
// es lo correcto: un repo que no compila no es un repo limpio—. Pero traen un
// formato distinto: `go vet` antepone el nombre de la herramienta a la ruta, y
// la regex, con su `.+` glotón, se lo tragaba dentro del nombre del archivo.
//
// El resultado era File = "vet.exe: tipo/a.go". Eso no lo abre ningún editor,
// no casa con la baseline (el fingerprint incluye la ruta) y no coincide con
// ningún archivo del diff — y el pipeline no filtra por los archivos del diff,
// `consolidate` sólo deduplica, así que llegaba tal cual al informe y al URI del
// SARIF.
//
// Las tres formas son las que emite `go vet` de verdad en Windows, capturadas
// ejecutándolo, no inventadas.
func TestElArchivoDeUnHallazgoDeVetEsUnaRutaQueSePuedeAbrir(t *testing.T) {
	casos := []struct {
		nombre string
		salida string
		quiere string
	}{
		{
			// go vet ./tipo, con `var x NoExiste`
			nombre: "el nombre de la herramienta delante de la ruta",
			salida: "# prueba/tipo\nvet.exe: tipo\\a.go:4:8: undefined: NoExiste",
			quiere: "tipo/a.go",
		},
		{
			// go vet ./imp, con un import que no resuelve. La segunda línea
			// ("go get …") no es un diagnóstico y no debe producir hallazgo.
			nombre: "import que no resuelve",
			salida: "imp\\b.go:3:8: no required module provides package ejemplo.com/x; to add it:\n" +
				"\tgo get ejemplo.com/x",
			quiere: "imp/b.go",
		},
		{
			// go vet ./app, un diagnóstico de los de siempre.
			nombre: "diagnóstico normal",
			salida: "app\\mal.go:5:44: fmt.Sprintf format %d reads arg #2, but call has 1 arg",
			quiere: "app/mal.go",
		},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			// Por stderr, que es de donde vienen de verdad: son errores de
			// compilación y de carga, y vet los escribe por ahí (medido).
			fs, err := hallazgosVet(t.TempDir(), "", c.salida, []string{"./x"})
			if err != nil {
				t.Fatalf("estas salidas SÍ traen diagnósticos: %v", err)
			}
			if len(fs) != 1 {
				t.Fatalf("se esperaba 1 hallazgo y salieron %d", len(fs))
			}
			if fs[0].File != c.quiere {
				t.Errorf("File = %q, se esperaba %q.\nUna ruta así no la abre ningún "+
					"editor, no casa con la baseline y no coincide con ningún archivo "+
					"del diff.", fs[0].File, c.quiere)
			}
		})
	}
}

// Y la consecuencia medible de lo anterior, con el toolchain de verdad: el
// hallazgo tiene que casar con el diff y con la baseline.
//
// Son las dos cosas que una ruta sucia rompe en silencio. Con File =
// "vet.exe: tipo/a.go" el hallazgo no corresponde a ningún archivo que el
// usuario tocó, y su fingerprint —que incluye la ruta— no es el que la baseline
// del equipo tiene grabado, así que un hallazgo suprimido reaparece para
// siempre sin que se pueda suprimir de nuevo.
func TestUnErrorDeCompilacionCasaConElDiffYConLaBaseline(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("sin toolchain de Go no hay nada que compilar")
	}
	root, escribir := repoGo(t)
	escribir("tipo/a.go", "package tipo\n\nfunc F() {\n\tvar x NoExiste\n\t_ = x\n}\n")

	in := engines.Input{RepoRoot: root, Files: []gitdiff.ChangedFile{
		{Path: "tipo/a.go", Status: "M"},
	}}

	fs, err := (GoVet{}).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("un error de compilación se reporta como hallazgo bloqueante, "+
			"no como motor roto: %v", err)
	}
	if len(fs) == 0 {
		t.Fatal("un paquete que no compila no es un repo limpio")
	}

	// (a) casa con el diff
	delDiff := map[string]bool{}
	for _, f := range in.Files {
		delDiff[f.Path] = true
	}
	if !delDiff[fs[0].File] {
		t.Errorf("el hallazgo apunta a %q, que no es ninguno de los archivos del "+
			"diff (%v): nadie puede localizarlo ni suprimirlo", fs[0].File, in.Files)
	}

	// (b) casa con la baseline: la identidad se asigna sobre la ruta LIMPIA.
	// El parser ya no calcula huellas (las asigna finding.AsignarHuellas,
	// colectivas) y govet es de la clase «mensaje» (W6, t.128): su LEGACY v1
	// se hace del MENSAJE —lo que el binario viejo ponía en LineContent—, así
	// que una baseline vieja de tipo/a.go la sigue casando por la ventana dual.
	// La v2, en cambio, la asigna AsignarHuellas leyendo la línea REAL de la
	// fuente (por eso aquí se le pasa una de verdad, no nil: sin fuente el
	// hallazgo sería de identidad incompleta y no llevaría legacy).
	esperado := finding.Finding{
		RuleKey:     fs[0].RuleKey,
		File:        "tipo/a.go",
		LineContent: fs[0].Message, // la v1 de govet hasheaba el mensaje del diagnóstico
	}
	finding.AsignarHuellas(fs, finding.FuenteDeArchivos(root))
	if fs[0].LegacyFingerprint != esperado.ComputeFingerprint() {
		t.Errorf("la legacy no es la huella v1 de tipo/a.go: la baseline del equipo "+
			"nunca casaría con este hallazgo (File = %q)", fs[0].File)
	}
}

// LA HUELLA NO SE PUEDE MOVER, Y EL ARREGLO DEL SILENCIO LA TOCÓ DE CERCA.
//
// Los diagnósticos pasaron de leerse como texto a leerse del JSON de `go vet
// -json`, y son dos caminos distintos hacia el mismo hallazgo: el JSON trae la
// ruta ABSOLUTA en `posn` y el texto la trae relativa. Si los dos no acaban en
// la misma huella, cada repo ya enrolado despierta con su baseline inservible —
// los hallazgos aceptados como deuda vuelven a bloquear— y eso no se nota al
// programar: se nota el lunes, en el portátil de otro.
//
// ComputeFingerprint es RuleKey + archivo + LineContent, y ninguno de los tres
// puede depender de por qué canal llegó el diagnóstico.
func TestLaHuellaEsLaMismaVengaDelJSONODelTexto(t *testing.T) {
	root := t.TempDir()
	mensaje := "fmt.Sprintf format %d has arg \"x\" of wrong type string"

	// Por stdout, como lo escribe `go vet -json`: ruta absoluta en posn.
	absoluta := filepath.ToSlash(filepath.Join(root, "app", "mal.go"))
	informe := `{"prueba/app":{"printf":[{"posn":"` +
		strings.ReplaceAll(absoluta, "/", "\\\\") + `:5:44","message":"` +
		strings.ReplaceAll(mensaje, `"`, `\"`) + `"}]}}`

	delJSON, err := hallazgosVet(root, informe, "", []string{"./app"})
	if err != nil {
		t.Fatalf("el informe de vet tiene que leerse: %v", err)
	}
	// Y por stderr, como llega un error de carga: ruta relativa.
	delTexto, err := hallazgosVet(root, "", "app\\mal.go:5:44: "+mensaje, []string{"./app"})
	if err != nil {
		t.Fatalf("los motivos de vet tienen que leerse: %v", err)
	}
	if len(delJSON) != 1 || len(delTexto) != 1 {
		t.Fatalf("un diagnóstico por camino: JSON=%d texto=%d", len(delJSON), len(delTexto))
	}
	if delJSON[0].File != "app/mal.go" {
		t.Errorf("del JSON salió File = %q, y la ruta absoluta tiene que volverse "+
			"relativa al repo o no casa con nada", delJSON[0].File)
	}
	if delJSON[0].Line != 5 {
		t.Errorf("del JSON salió Line = %d, se esperaba 5", delJSON[0].Line)
	}
	if delJSON[0].Fingerprint != delTexto[0].Fingerprint {
		t.Errorf("la misma cosa da dos huellas según el canal:\n  JSON  %s (File %q)\n"+
			"  texto %s (File %q)\nCon eso, cambiar el parseo invalida la baseline de "+
			"todos los repos enrolados.",
			delJSON[0].Fingerprint, delJSON[0].File, delTexto[0].Fingerprint, delTexto[0].File)
	}
}

// Algunos runners de Windows entregan a Git y a go vet dos nombres absolutos
// distintos para el mismo checkout temporal. La normalización general no debe
// aceptar por parecido una ruta externa, pero vet sí puede demostrar cuál es
// el archivo cuando existe, tiene el mismo contenido y su sufijo es único.
func TestVetResuelveUnaRaizAlternaSoloConEvidenciaInequivoca(t *testing.T) {
	repo, escribir := repoGo(t)
	escribir("paquete/vet.go", "package paquete\n\nfunc F() {}\n")

	alias := t.TempDir()
	rutaAlias := filepath.Join(alias, "paquete", "vet.go")
	if err := os.MkdirAll(filepath.Dir(rutaAlias), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rutaAlias, []byte("package paquete\n\nfunc F() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	rutas := nuevoResolutorDeRutasVet(repo)
	if got := rutas.relativa(rutaAlias); got != "paquete/vet.go" {
		t.Fatalf("la copia exacta bajo una raíz alterna dio %q; se esperaba paquete/vet.go", got)
	}
	// Reproducción exacta del runner público: el posn de vet conservó las
	// barras escapadas de una capa JSON y cada separador llegó duplicado.
	rutaConSeparadoresDuplicados := strings.ReplaceAll(rutaAlias, `\`, `\\`)
	if got := nuevoResolutorDeRutasVet(repo).relativa(rutaConSeparadoresDuplicados); got != "paquete/vet.go" {
		t.Fatalf("la ruta JSON con separadores duplicados dio %q; se esperaba paquete/vet.go", got)
	}
	// Go 1.26 en el runner dejó además la comilla de apertura pegada a C:.
	// Una comilla no es válida en rutas Windows y hace que IsAbs no reconozca
	// la unidad; se elimina en el límite del parser, no en la normalización
	// general que comparten los demás motores.
	rutaComoLaDelRunner := `"` + rutaConSeparadoresDuplicados
	if got := nuevoResolutorDeRutasVet(repo).relativa(rutaComoLaDelRunner); got != "paquete/vet.go" {
		t.Fatalf("la ruta exacta del runner (comilla + separadores duplicados) dio %q", got)
	}

	// Mismo sufijo pero distinto contenido: no hay prueba de que sea el archivo
	// analizado y conservar la absoluta es preferible a atribuirlo mal.
	if err := os.WriteFile(rutaAlias, []byte("package paquete\n\nfunc Distinta() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := nuevoResolutorDeRutasVet(repo).relativa(rutaAlias); got != filepath.ToSlash(rutaAlias) {
		t.Fatalf("una ruta externa de contenido distinto se inventó como %q", got)
	}
}

func TestVetNoEligeCuandoDosArchivosPuedenCasar(t *testing.T) {
	repo, escribir := repoGo(t)
	contenido := "package paquete\n\nfunc F() {}\n"
	escribir("vet.go", contenido)
	escribir("paquete/vet.go", contenido)

	alias := t.TempDir()
	rutaAlias := filepath.Join(alias, "paquete", "vet.go")
	if err := os.MkdirAll(filepath.Dir(rutaAlias), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rutaAlias, []byte(contenido), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := nuevoResolutorDeRutasVet(repo).relativa(rutaAlias); got != filepath.ToSlash(rutaAlias) {
		t.Fatalf("había dos candidatos y vet eligió silenciosamente %q", got)
	}
}

// Y de punta a punta con el toolchain de verdad: un archivo con DOS problemas
// es exactamente el caso que la compuerta rota convertía en "no pudo analizar".
func TestGoVetConVariosHallazgosNoSeDeclaraRoto(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("sin toolchain de Go no hay nada que analizar")
	}
	root, escribir := repoGo(t)
	escribir("app/mal.go", "package app\n\nimport \"fmt\"\n\n"+
		"func Mal() string {\n\treturn fmt.Sprintf(\"%d %d\", 1)\n}\n\n"+
		"func Mal2() string {\n\treturn fmt.Sprintf(\"%d %d\", 2)\n}\n")

	in := engines.Input{RepoRoot: root, Files: []gitdiff.ChangedFile{
		{Path: "app/mal.go", Status: "M"},
	}}

	fs, err := (GoVet{}).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("vet analizó y reportó dos hallazgos; declararse roto los pierde: %v", err)
	}
	if len(fs) != 2 {
		t.Fatalf("se esperaban los 2 Sprintf mal formados y salieron %d", len(fs))
	}
}

// Y la otra mitad: cuando SÍ carga, los hallazgos salen. Sin esto, el arreglo
// de arriba se podría "conseguir" devolviendo siempre error.
func TestGoVetSigueCazandoLoQueDebe(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("sin toolchain de Go no hay nada que analizar")
	}
	root, escribir := repoGo(t)
	escribir("app/mal.go", "package app\n\nimport \"fmt\"\n\n"+
		"func Mal() string {\n\treturn fmt.Sprintf(\"%d %d\", 1)\n}\n")

	in := engines.Input{RepoRoot: root, Files: []gitdiff.ChangedFile{
		{Path: "app/mal.go", Status: "M"},
	}}

	fs, err := (GoVet{}).Run(context.Background(), in)
	if err != nil {
		t.Fatalf("un paquete que carga bien no debe dar error: %v", err)
	}
	if len(fs) == 0 {
		t.Fatal("go vet no reportó el Sprintf con menos argumentos que verbos: " +
			"el motor no está cazando lo suyo")
	}
	if !strings.Contains(fs[0].File, "mal.go") {
		t.Errorf("el hallazgo apunta a %q y debería ser app/mal.go", fs[0].File)
	}
	if !fs[0].Blocking {
		t.Error("govet es una compuerta que BLOQUEA (§7: lint de severidad error)")
	}
}
