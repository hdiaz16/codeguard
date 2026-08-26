package staticcheck

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"codeguard/internal/engines"
	"codeguard/internal/engines/contrato"
	"codeguard/internal/engines/proc"
	"codeguard/internal/finding"
)

type Engine struct {
	Binary string
	// Cache: módulo sin cambios (incluido staticcheck.conf) + mismos paquetes
	// pedidos + mismo binario = mismos hallazgos.
	// La clave lleva la lista de paquetes porque el análisis es del
	// subconjunto tocado, no de ./... — otro subconjunto es otro resultado.
	Cache engines.Cache
}

func (e *Engine) Name() string { return "staticcheck" }

func (e *Engine) Applies(in engines.Input) bool { return len(e.modulos(in)) > 0 }

// modulos agrupa los archivos .go cambiados por su módulo (el go.mod más
// cercano subiendo directorios, que en un monorepo no está en la raíz) y
// devuelve, por módulo, los patrones de paquete a analizar relativos a ese
// go.mod. Se analizan SOLO los paquetes tocados, no ./... completo:
// staticcheck compila lo que analiza y en el hook el presupuesto son 30 s
// compartidos entre todos los motores.
func (e *Engine) modulos(in engines.Input) map[string][]string {
	porModulo := map[string]map[string]bool{}
	for _, f := range in.Files {
		if f.Status == "D" || !strings.HasSuffix(strings.ToLower(f.Path), ".go") {
			continue
		}
		mod, ok := moduloDe(in.RepoRoot, f.Path)
		if !ok {
			continue
		}
		// El paquete es el directorio del archivo, relativo al go.mod.
		rel := path.Dir(f.Path)
		if mod != "." {
			if rel == mod {
				rel = "."
			} else {
				rel = strings.TrimPrefix(rel, mod+"/")
			}
		}
		pkg := "./"
		if rel != "." {
			pkg = "./" + rel
		}
		if porModulo[mod] == nil {
			porModulo[mod] = map[string]bool{}
		}
		porModulo[mod][pkg] = true
	}
	out := make(map[string][]string, len(porModulo))
	for mod, set := range porModulo {
		pkgs := make([]string, 0, len(set))
		for p := range set {
			pkgs = append(pkgs, p)
		}
		sort.Strings(pkgs)
		out[mod] = pkgs
	}
	return out
}

// moduloDe sube desde el archivo hasta el go.mod más cercano, sin salirse de
// la raíz del repo.
func moduloDe(repoRoot, rel string) (string, bool) {
	dir := path.Dir(rel)
	for {
		abs := filepath.Join(repoRoot, filepath.FromSlash(dir), "go.mod")
		if st, err := os.Stat(abs); err == nil && !st.IsDir() {
			return dir, true
		}
		if dir == "." || dir == "/" {
			return "", false
		}
		dir = path.Dir(dir)
	}
}

// ── la salida -f json ───────────────────────────────────────────────────────
// staticcheck -f json emite UN objeto por línea con el problema y su posición.
// Los paths de location llegan ABSOLUTOS, construidos sobre el directorio de
// trabajo TAL CUAL lo recibió el proceso: con alias 8.3 (HECTOR~1) si el cwd
// venía así, largos si venía completo. La severidad depende del flag
// -fail: con la invocación por defecto todo problema real llega como "error";
// "ignored" marca los suprimidos con //lint:ignore. Un error de compilación
// NO llega por stderr: llega como un pseudo-problema con code "compile" y el
// proceso sale con 1 — el mismo código con el que sale cuando encuentra algo
// (señal legítima, como semgrep). Un código mayor que 1 sí es fallo operativo.

type problema struct {
	Code     string   `json:"code"`
	Severity string   `json:"severity"`
	Location posicion `json:"location"`
	End      posicion `json:"end"`
	Message  string   `json:"message"`
}

type posicion struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}

func (e *Engine) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	bin := e.Binary
	if bin == "" {
		bin = "staticcheck"
	}
	mods := e.modulos(in)
	dirs := make([]string, 0, len(mods))
	for d := range mods {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	// Se resuelve UNA vez por corrida, no por módulo: es un Stat, pero no hay
	// razón para repetirlo por cada go.mod del repo.
	idBinario := identidadBinario(bin)
	var out []finding.Finding
	for _, dir := range dirs {
		clave := claveModulo(in.RepoRoot, dir, mods[dir], idBinario)
		if e.Cache != nil && clave != "" {
			if fs, ok := e.Cache.Leer([]string{clave})[clave]; ok {
				out = append(out, fs...)
				continue
			}
		}
		fs, err := e.correrModulo(ctx, bin, in.RepoRoot, dir, mods[dir])
		if err != nil {
			return nil, err
		}
		if e.Cache != nil && clave != "" {
			dir := dir
			e.Cache.Guardar([]engines.Cacheable{{
				Clave:    clave,
				Vigente:  engines.VigenciaDeClave(clave, func() string { return claveModulo(in.RepoRoot, dir, mods[dir], idBinario) }),
				Findings: fs,
			}})
		}
		out = append(out, fs...)
	}
	return out, nil
}

// identidadBinario devuelve algo que cambia cuando cambia el binario, para que
// entre en la clave del caché.
//
// Hace falta porque staticcheck estrena y retira comprobaciones entre versiones:
// servir el resultado guardado tras un `go install -u` sería reportar los
// hallazgos del analizador anterior, que es el mismo fallo que java.go describe
// para PMD y google-java-format. Pero ahí la versión se lee del NOMBRE de la
// herramienta y aquí el binario se resuelve del PATH sin versión en la ruta, así
// que se usa la identidad del archivo —ruta, tamaño y fecha— en vez de invocar
// `-version`: java.go:134 rechaza expresamente pagar «un proceso extra por
// informe sólo para preguntarla», y este es el motor más lento del conjunto.
// Es el mismo recurso que usa contrato.go:102 para su memoria de veredictos.
//
// Vacía si no se puede determinar, y entonces no se cachea: una clave sin tamaño
// ni fecha no puede cumplir lo que promete —cambiar cuando cambia el binario—, y
// preferimos analizar de nuevo antes que servir lo guardado a ciegas. El fallo
// real de un binario ausente o roto lo reporta correrModulo con su centinela;
// aquí sólo se decide no fiarse del caché.
func identidadBinario(bin string) string {
	ruta := bin
	if !filepath.IsAbs(ruta) {
		p, err := exec.LookPath(bin)
		if err != nil {
			return ""
		}
		ruta = p
	}
	info, err := os.Stat(ruta)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s\x00%d\x00%d", ruta, info.Size(), info.ModTime().UnixNano())
}

// claveModulo identifica un análisis: el contenido del módulo (los .go y
// manifiestos rastreados — la compilación depende de todos, no solo de los
// tocados), los paquetes pedidos y el binario que va a analizarlos. Vacía = no
// cacheable.
func (e *Engine) correrModulo(ctx context.Context, bin, repoRoot, dir string, paquetes []string) ([]finding.Finding, error) {
	args := append([]string{"-f", "json"}, paquetes...)
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = filepath.Join(repoRoot, filepath.FromSlash(dir))
	cmd.Env = proc.EntornoDeMotor("staticcheck", proc.PerfilGo) // declara RedDenegada: compila el modulo OFFLINE, sin GOPROXY en el camino del commit
	salida, runErr := proc.Correr(ctx, cmd, proc.MaxSalida)
	if salida.Recortada {
		return nil, fmt.Errorf("staticcheck devolvió más de %d MB de salida", proc.MaxSalida>>20)
	}
	if runErr != nil {
		var exit *exec.ExitError
		// Salir con 1 es "encontré algo": la respuesta está en el JSON de
		// stdout. Cualquier otra cosa —no arrancó, código mayor que 1— es
		// fallo operativo y el motor se degrada.
		if !errors.As(runErr, &exit) || exit.ExitCode() != 1 {
			detalle := ""
			if len(salida.Stderr) > 0 {
				detalle = ": " + recorte(salida.Stderr)
			}
			// %w: el orquestador clasifica la degradación con errors.Is, así
			// que el centinela (binario ausente, plazo agotado) tiene que
			// llegar entero. Con %v se perdía y todo salía como ":error".
			return nil, fmt.Errorf("staticcheck falló en %s: %w%s", dir, runErr, detalle)
		}
	}
	// EL SILENCIO, QUE ERA DOS COSAS A LA VEZ.
	//
	// Todo lo que staticcheck tiene que decir va por stdout como JSON, una línea
	// por diagnóstico —incluidos los fallos de compilación, que llegan con
	// code:"compile" (medido, hasta el "directory not found" de un paquete
	// inexistente)—. Así que stdout vacío significa que no dijo nada, y hasta aquí
	// eso caía en `interpretar`, salía por io.EOF en la primera vuelta y devolvía
	// (nil, nil): «analizado y limpio».
	//
	// Son DOS situaciones distintas y ninguna de las dos es «limpio»:
	mudo := len(bytes.TrimSpace(salida.Stdout)) == 0
	if mudo && runErr != nil {
		// (a) salió con 1, que en staticcheck significa EXACTAMENTE «encontré
		// algo», y no dijo qué. Una herramienta que anuncia hallazgos y no los
		// escribe no está limpia: está averiada. No hace falta preguntar nada
		// más, y por eso este caso no paga la prueba de identidad.
		detalle := ""
		if len(salida.Stderr) > 0 {
			detalle = ": " + recorte(salida.Stderr)
		}
		return nil, fmt.Errorf("staticcheck salió con 1 en %s —que es su forma de decir "+
			"«encontré algo»— y no escribió NI UN diagnóstico%s. No se puede llamar limpio a "+
			"eso: lo que encontró se perdió", dir, detalle)
	}
	if mudo {
		// (b) salió con 0 sin escribir nada, que en la herramienta de verdad SÍ
		// es «módulo limpio» (medido: 0 bytes y código 0). Aquí la salida no
		// puede resolverlo —el silencio bueno y el del impostor son el mismo
		// vacío— así que se le pregunta quién es. Sólo lo paga el análisis que no
		// encontró nada, y sólo la primera vez por binario.
		if err := contrato.Identidad(ctx, contrato.Version("staticcheck", bin, "-version",
			diceSerStaticcheck,
			"Comprueba qué resuelve `staticcheck` en tu PATH, o reinstálalo con `codeguard repair`.",
		)); err != nil {
			return nil, err
		}
		return nil, nil
	}

	// Para recortar los paths absolutos hay que probar las dos formas del
	// directorio del módulo: staticcheck reporta el path tal como ve su
	// directorio de trabajo, y en Windows ese puede ser un alias 8.3
	// (HECTOR~1 en vez del nombre completo) o su forma canónica larga,
	// según quién arrancara el proceso.
	bases := []string{cmd.Dir}
	if canon, err := filepath.EvalSymlinks(cmd.Dir); err == nil && canon != cmd.Dir {
		bases = append(bases, canon)
	}
	return interpretar(salida.Stdout, dir, bases...)
}
