package linters

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"codeguard/internal/engines"
	"codeguard/internal/finding"
)

// Tsc implementa la compuerta de compilación de tipos para TS (§7: BLOQUEA).
// Usa --incremental para que las corridas calientes queden en presupuesto
// (spike S5). En Windows el CLI de npm es npx.cmd, no un .exe — de ahí la
// resolución explícita.
//
// El tsconfig.json se busca SUBIENDO desde cada archivo tocado, no solo en la
// raíz: en el monorepo corporativo típico (backend/go.mod +
// frontend/tsconfig.json) la versión anterior no encontraba nada y la
// compuerta de tipos llevaba enrolada sin correr JAMÁS — en silencio, que es
// la clase de fallo que más caro cuesta descubrir.
type Tsc struct {
	// Cache: mismo proyecto TS (fuentes + tsconfig + lockfile) = los mismos
	// errores de tipos. tsc compila el proyecto completo aunque el cambio sea
	// de un archivo; sin esto, cada informe en un monorepo con frontend paga
	// la compilación entera.
	Cache engines.Cache
}

func (Tsc) Name() string { return "tsc" }

func (e Tsc) Applies(in engines.Input) bool { return len(e.proyectos(in)) > 0 }

// proyectos agrupa los .ts/.tsx cambiados por su tsconfig.json más cercano
// (relativo a la raíz; "." si es la propia raíz).
func (Tsc) proyectos(in engines.Input) []string {
	dirs := map[string]bool{}
	for _, f := range append(filesWithExt(in, ".ts"), filesWithExt(in, ".tsx")...) {
		if dir, ok := tsconfigDe(in.RepoRoot, f.Path); ok {
			dirs[dir] = true
		}
	}
	out := make([]string, 0, len(dirs))
	for d := range dirs {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// tsconfigDe sube desde el archivo hasta el tsconfig.json más cercano, sin
// salirse de la raíz del repo ni entrar a node_modules.
func tsconfigDe(repoRoot, rel string) (string, bool) {
	if strings.Contains(rel, "node_modules/") {
		return "", false
	}
	dir := path.Dir(rel)
	for {
		abs := filepath.Join(repoRoot, filepath.FromSlash(dir), "tsconfig.json")
		if st, err := os.Stat(abs); err == nil && !st.IsDir() {
			return dir, true
		}
		if dir == "." || dir == "/" {
			return "", false
		}
		dir = path.Dir(dir)
	}
}

// claveProyecto identifica una compilación: las fuentes TS del proyecto, su
// tsconfig y el lockfile (el estado real de node_modules más allá del
// lockfile es un punto ciego asumido y documentado).
func claveProyecto(repoRoot, dir string) string {
	huella := engines.HuellaModulo(repoRoot, dir, func(rel string) bool {
		base := strings.ToLower(path.Base(rel))
		switch base {
		case "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml":
			return true
		}
		if strings.HasPrefix(base, "tsconfig") && strings.HasSuffix(base, ".json") {
			return true
		}
		return strings.HasSuffix(base, ".ts") || strings.HasSuffix(base, ".tsx") ||
			strings.HasSuffix(base, ".mts") || strings.HasSuffix(base, ".cts")
	})
	if huella == "" {
		return ""
	}
	return "tsc:" + dir + ":" + huella
}

// formato --pretty false: src/mod7.ts(19,14): error TS2322: mensaje
var tscLine = regexp.MustCompile(`^(.+?)\((\d+),\d+\): error (TS\d+): (.+)$`)

func (e Tsc) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	var out []finding.Finding
	for _, dir := range e.proyectos(in) {
		clave := ""
		if e.Cache != nil {
			if clave = claveProyecto(in.RepoRoot, dir); clave != "" {
				if fs, ok := e.Cache.Leer([]string{clave})[clave]; ok {
					out = append(out, fs...)
					continue
				}
			}
		}
		fs, err := correrProyecto(ctx, in.RepoRoot, dir)
		if err != nil {
			return nil, err
		}
		if e.Cache != nil && clave != "" {
			e.Cache.Guardar(map[string][]finding.Finding{clave: fs})
		}
		out = append(out, fs...)
	}
	return out, nil
}

func correrProyecto(ctx context.Context, repoRoot, dir string) ([]finding.Finding, error) {
	abs := filepath.Join(repoRoot, filepath.FromSlash(dir))
	bin := "npx"
	if _, err := os.Stat(filepath.Join(abs, "node_modules", ".bin", "tsc.cmd")); err == nil {
		bin = filepath.Join(abs, "node_modules", ".bin", "tsc.cmd")
	}
	var out string
	var salioMal bool
	var err error
	// --extendedDiagnostics es lo que convierte el silencio de tsc en una
	// respuesta, y no cuesta nada. Ver la comprobación del final de esta función.
	comunes := []string{"--noEmit", "--incremental", "--pretty", "false", "--extendedDiagnostics"}
	if bin == "npx" {
		out, salioMal, err = runToolConSalida(ctx, abs, "npx.cmd", append([]string{"--no-install", "tsc"}, comunes...)...)
	} else {
		out, salioMal, err = runToolConSalida(ctx, abs, bin, comunes...)
	}
	if err != nil {
		return nil, fmt.Errorf("tsc no corrió en %s: %w", dir, err)
	}
	var findings []finding.Finding
	for _, line := range strings.Split(out, "\n") {
		m := tscLine.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		lineNo, _ := strconv.Atoi(m[2])
		// tsc reporta relativo a SU proyecto; el hallazgo viaja relativo al repo.
		file := filepath.ToSlash(m[1])
		// esAbsolutaJS y no path.IsAbs: path.IsAbs sólo mira el '/' inicial, así
		// que una ruta absoluta de Windows —"C:/repo/src/foo.ts", que tsc emite
		// según el tsconfig o cuando el archivo cae fuera del rootDir— pasaba por
		// relativa y el Join producía "frontend/C:/repo/src/foo.ts": un hallazgo
		// que apunta a un archivo inexistente, imposible de localizar y con la
		// huella calculada sobre una ruta basura. La función reconoce las dos
		// formas (C:/… y /…) sin preguntarle al SO, y ya la usan eslint.go y
		// java.go — que pide expresamente reutilizarla en vez de hacer otra copia.
		if dir != "." && !esAbsolutaJS(file) {
			file = path.Join(dir, file)
		}
		f := finding.Finding{
			Engine:      "tsc",
			RuleKey:     m[3],
			Pillar:      finding.Quality,
			Severity:    finding.Error,
			Blocking:    true,
			File:        file,
			Line:        lineNo,
			Message:     m[4],
			Why:         "Un error de tipos es un error de compilación: el CI lo rechazará igual.",
			FixHint:     "Corrige el tipo señalado; el mensaje de tsc indica el tipo esperado y el recibido.",
			Verified:    true,
			Source:      finding.Deterministic,
			LineContent: m[3] + " " + m[4],
		}
		f.ComputeFingerprint()
		findings = append(findings, f)
	}
	// Salió mal y no dijo por qué: entonces no compiló, y no se puede afirmar
	// que el proyecto esté limpio.
	//
	// tsc de verdad sólo tiene dos comportamientos: si el proyecto está limpio
	// sale con 0, y si tiene errores sale distinto de cero Y los enumera. Salir
	// distinto de cero sin un solo diagnóstico no es ninguno de los dos — es que
	// no llegó a compilar: falta el paquete, el tsconfig no es válido, o `npx`
	// resolvió a otra cosa. Medido en una máquina real: `npx --no-install tsc`
	// resolvía a un paquete de npm que no es TypeScript, imprimía un banner y
	// salía con 1. Devolver "cero hallazgos" ahí ponía un ✓ verde sobre un
	// archivo que nadie había mirado, y el ✓ se lee igual que el de un proyecto
	// revisado de verdad.
	//
	// Devolver error NO bloquea el commit (§14): lo que hace es marcar la capa
	// como degradada, que es exactamente lo que ocurrió — la capa de tipos no
	// revisó nada, y quien mira el panel tiene derecho a saberlo.
	if salioMal && len(findings) == 0 {
		return nil, fmt.Errorf("tsc salió con error en %s y no reportó ni un diagnóstico: "+
			"no llegó a compilar (¿falta el paquete typescript en node_modules, o `npx tsc` "+
			"resuelve a otra herramienta?). Salida: %s", dir, primeraLineaUtil(out))
	}

	// LA MITAD QUE FALTABA: SALIR BIEN Y CALLAR.
	//
	// La comprobación de arriba cerró el caso medido —el impostor que escupe un
	// banner y sale con 1— y dejó abierto el simétrico, que es peor porque no
	// deja rastro: salir con 0 sin escribir nada. Con los argumentos anteriores
	// eso era EXACTAMENTE lo que hacía un proyecto limpio (medido: 0 bytes,
	// código 0), así que el motor no tenía forma de distinguir «compilé el
	// proyecto y no hay errores de tipos» de «no compilé nada».
	//
	// --extendedDiagnostics lo resuelve sin lanzar ningún proceso extra y sin
	// preguntarle a nadie quién es: tsc escribe siempre su bloque de estadísticas
	// —Files, Lines of Library, tiempos—, también cuando no encuentra ni un
	// error. Medido con TypeScript 5.9.3 sobre un proyecto limpio: 768 bytes y
	// código 0, donde antes había 0 bytes.
	//
	// Se exige "escribió ALGO" y no "escribió Files:" a propósito: las etiquetas
	// de ese bloque son mensajes de diagnóstico de tsc y se traducen con --locale,
	// así que buscar la palabra inglesa haría que un equipo con tsc en español
	// viera su capa de tipos degradada en cada commit limpio. El bloque existe en
	// todos los idiomas; la palabra concreta, no.
	if len(strings.TrimSpace(out)) == 0 {
		return nil, fmt.Errorf("tsc terminó con éxito en %s y no escribió NADA, ni siquiera el "+
			"bloque de --extendedDiagnostics que imprime siempre —hasta cuando el proyecto está "+
			"limpio—. Eso no lo hace tsc: lo hace otra cosa que se llama tsc. La capa de tipos "+
			"NO revisó este cambio (¿`npx tsc` resuelve a otro paquete, o el typescript de "+
			"node_modules está a medias?)", dir)
	}
	return findings, nil
}

// codigosANSI son las secuencias de color de la terminal. Se quitan porque este
// texto NO va a una terminal: va al panel y al log.
var codigosANSI = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

// primeraLineaUtil saca del ruido la primera línea que de verdad diga algo.
//
// "Con contenido" no basta y lo aprendí enseñándoselo a Héctor: el stub que
// destapó todo esto imprime primero una BARRA DE COLOR —espacios entre códigos
// ANSI— y el motivo de la degradación salía como `Salida: [41m        [0m`.
// Un mensaje de avería ilegible es casi tan inútil como no tenerlo: quien lo
// lee sigue sin saber qué le pasa a su repo.
//
// Así que se limpian los códigos y se exige al menos una letra o un dígito. Lo
// que quiero es la línea que un humano leería, no la primera que no esté vacía.
func primeraLineaUtil(s string) string {
	for _, l := range strings.Split(codigosANSI.ReplaceAllString(s, ""), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || !strings.ContainsFunc(l, func(r rune) bool {
			return unicode.IsLetter(r) || unicode.IsDigit(r)
		}) {
			continue
		}
		const tope = 160
		if len(l) > tope {
			return l[:tope] + "…"
		}
		return l
	}
	return "sin mensaje"
}
