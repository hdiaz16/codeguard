// Package govulncheck adapta el analizador de alcanzabilidad de Go (F1b del
// plan Motor avanzado). Trivy responde "¿está el CVE en tu go.sum?";
// govulncheck construye el grafo de llamadas y responde la pregunta que
// importa: "¿tu código EJECUTA la función vulnerable?". Aquí sólo se reportan
// los hallazgos con símbolo alcanzado — la mera presencia ya la dice trivy, y
// repetirla con otro nombre sería ruido.
//
// El binario lo construye el toolchain de Go del desarrollador (go install),
// así que no entra en motores.json: sus fuentes las verifica GOSUMDB, igual
// que pip verifica los motores de Python.
package govulncheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"codeguard/internal/engines"
	"codeguard/internal/engines/proc"
	"codeguard/internal/finding"
)

type Engine struct {
	Binary string
	// BlockReachable: true en CI (política §7, como el CVE crítico de trivy):
	// una vulnerabilidad cuyo código de verdad se llama bloquea allí; en local
	// avisa, porque la base de vulnerabilidades local puede estar vieja.
	BlockReachable bool
	// SoloManifiestos: true en el camino del hook. El análisis recorre el
	// módulo completo (segundos, no milisegundos), así que en local sólo corre
	// cuando cambian las dependencias (go.mod/go.sum) — el momento en que la
	// alcanzabilidad suele cambiar. El CI corre con cualquier .go tocado.
	SoloManifiestos bool
	// Cache: módulo sin cambios = mismos hallazgos, sin re-analizar. La clave
	// lleva el día UTC porque el análisis consulta la base de vulnerabilidades
	// del día: un acierto de ayer escondería los CVEs publicados hoy.
	Cache engines.Cache
}

func (e *Engine) Name() string { return "govulncheck" }

func (e *Engine) Applies(in engines.Input) bool { return len(e.modulos(in)) > 0 }

// modulos devuelve los directorios de módulo (relativos a la raíz; "." si es
// la propia raíz) que este cambio obliga a analizar. La detección es por
// archivos CAMBIADOS: de cada uno se sube hasta el go.mod más cercano, que en
// un monorepo (backend/go.mod + frontend/) no está en la raíz.
func (e *Engine) modulos(in engines.Input) []string {
	dirs := map[string]bool{}
	for _, f := range in.Files {
		if f.Status == "D" {
			continue
		}
		base := strings.ToLower(path.Base(f.Path))
		esManifiesto := base == "go.mod" || base == "go.sum"
		if e.SoloManifiestos && !esManifiesto {
			continue
		}
		if !esManifiesto && !strings.HasSuffix(base, ".go") {
			continue
		}
		if dir, ok := moduloDe(in.RepoRoot, f.Path); ok {
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

// ── el flujo -json ──────────────────────────────────────────────────────────
// govulncheck -json emite una secuencia de objetos: config, progress, osv (la
// ficha completa de cada vulnerabilidad mencionada) y finding. Cada hallazgo
// llega en niveles de precisión crecientes: módulo (está en tus dependencias),
// paquete (importas el paquete afectado) y símbolo (tu código llama a la
// función vulnerable — traza con función y posición). Sólo el último prueba
// alcanzabilidad. El flujo siempre sale con código 0; un código distinto es
// fallo operativo, no "encontré algo".

type envoltura struct {
	OSV     *fichaOSV `json:"osv"`
	Finding *hallazgo `json:"finding"`
	// Config es el primer mensaje del flujo, y aquí no está por sus datos: está
	// porque es la PRUEBA de que quien escribió esto es govulncheck. Ver
	// interpretar.
	Config *configDelEscaner `json:"config"`
}

// configDelEscaner es la cabecera con la que govulncheck se presenta:
//
//	{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck",
//	           "scanner_version":"v1.6.0","db":"https://vuln.go.dev", …}}
type configDelEscaner struct {
	Nombre  string `json:"scanner_name"`
	Version string `json:"scanner_version"`
}

type fichaOSV struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
}

type hallazgo struct {
	OSV          string  `json:"osv"`
	FixedVersion string  `json:"fixed_version"`
	Trace        []marco `json:"trace"`
}

type marco struct {
	Module   string    `json:"module"`
	Version  string    `json:"version"`
	Package  string    `json:"package"`
	Function string    `json:"function"`
	Position *posicion `json:"position"`
}

type posicion struct {
	Filename string `json:"filename"`
	Line     int    `json:"line"`
}

func (e *Engine) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	bin := e.Binary
	if bin == "" {
		bin = "govulncheck"
	}
	var out []finding.Finding
	for _, dir := range e.modulos(in) {
		clave := e.claveModulo(in.RepoRoot, dir)
		if e.Cache != nil && clave != "" {
			if fs, ok := e.Cache.Leer([]string{clave})[clave]; ok {
				out = append(out, fs...)
				continue
			}
		}
		fs, err := e.correrModulo(ctx, bin, in.RepoRoot, dir)
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

// claveModulo identifica un análisis completo: el contenido del módulo (los
// .go y manifiestos rastreados) más el día UTC — la frescura de la base de
// vulnerabilidades es parte del resultado. Vacía = no cacheable.
func (e *Engine) claveModulo(repoRoot, dir string) string {
	huella := engines.HuellaModulo(repoRoot, dir, esGoOManifiesto)
	if huella == "" {
		return ""
	}
	return "govulncheck:" + huella + ":" + time.Now().UTC().Format("2006-01-02")
}

func esGoOManifiesto(rel string) bool {
	base := strings.ToLower(path.Base(rel))
	return base == "go.mod" || base == "go.sum" || strings.HasSuffix(base, ".go")
}

func (e *Engine) correrModulo(ctx context.Context, bin, repoRoot, dir string) ([]finding.Finding, error) {
	cmd := exec.CommandContext(ctx, bin, "-json", "./...")
	cmd.Dir = filepath.Join(repoRoot, filepath.FromSlash(dir))
	cmd.Env = proc.Entorno()
	salida, runErr := proc.Correr(ctx, cmd, proc.MaxSalida)
	if runErr != nil {
		var exit *exec.ExitError
		detalle := ""
		if errors.As(runErr, &exit) && len(salida.Stderr) > 0 {
			detalle = ": " + recorte(salida.Stderr)
		}
		// %w y no %v: el centinela (binario ausente, plazo agotado) tiene que
		// llegar entero al orquestador, que clasifica con errors.Is.
		return nil, fmt.Errorf("govulncheck falló en %s: %w%s", dir, runErr, detalle)
	}
	if salida.Recortada {
		return nil, fmt.Errorf("govulncheck devolvió más de %d MB de salida", proc.MaxSalida>>20)
	}
	return interpretar(salida.Stdout, dir, e.BlockReachable)
}

// interpretar lee el flujo de govulncheck, y ADEMÁS exige que el flujo exista.
//
// EL SILENCIO QUE ERA UN ✓ VERDE. Un módulo sin vulnerabilidades no produce
// ninguna envoltura "finding", así que el bucle salía por io.EOF en la primera
// vuelta y el motor devolvía (nil, nil): «analizado, sin CVEs alcanzables». Con
// stdout VACÍO daba exactamente lo mismo, y stdout vacío es lo que deja una
// herramienta que no analizó nada.
//
// Aquí la señal no había que inventarla ni preguntarla: govulncheck ABRE su flujo
// presentándose. Medido sobre un módulo limpio con una sola dependencia:
//
//	393 983 bytes, código 0, y el primer mensaje es
//	{"config":{…,"scanner_name":"govulncheck","scanner_version":"v1.6.0",…}}
//
// Stdout vacío con código 0 es IMPOSIBLE en la herramienta de verdad. Y como la
// cabecera trae su nombre, la misma comprobación que demuestra que analizó
// demuestra que quien analizó era govulncheck — sin lanzar un proceso extra para
// preguntárselo, que es lo que hay que hacer con las herramientas que no dejan
// esta huella.
func interpretar(raw []byte, dir string, bloquea bool) ([]finding.Finding, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	resumen := map[string]string{}
	var crudos []hallazgo
	var seIdentifico bool
	var mensajes int
	for {
		var env envoltura
		if err := dec.Decode(&env); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("salida de govulncheck ilegible: %v", err)
		}
		mensajes++
		if env.Config != nil && strings.EqualFold(env.Config.Nombre, "govulncheck") {
			seIdentifico = true
		}
		if env.OSV != nil {
			resumen[env.OSV.ID] = env.OSV.Summary
		}
		if env.Finding != nil {
			crudos = append(crudos, *env.Finding)
		}
	}

	// Y aquí se cobra la cabecera: sin ella, no hubo análisis que interpretar.
	//
	// Esto es lo que separa «el módulo no tiene CVEs alcanzables» de «lo que
	// corrió no era govulncheck». Las dos cosas producen cero hallazgos, y hasta
	// ahora las dos llegaban al panel como una capa revisada y en verde.
	// Y se exigen mensajes DESPUÉS de la cabecera, no sólo la cabecera.
	//
	// El matiz lo puso el validador, midiendo: el mensaje `config` es byte a byte
	// IDÉNTICO en la corrida sana y en las averiadas —289 bytes, mismos campos—
	// así que presentarse no prueba haber escaneado. En sus escenarios eso no
	// cambiaba nada, porque todos salían con código distinto de cero y este motor
	// ya los rechaza más arriba. Pero la corrección es gratis y cierra el caso que
	// no hemos visto: presentarse, salir con 0 y no decir nada más.
	//
	// Un escaneo de verdad habla mucho: sobre un módulo limpio con una sola
	// dependencia son ~394 KB (SBOM, progreso, osv). El número exacto varía con el
	// módulo y con la versión, así que no se compara con ninguna cifra: se exige
	// que haya ALGO además de la presentación.
	if !seIdentifico || mensajes < 2 {
		return nil, fmt.Errorf("govulncheck no escaneó %s: su flujo abre presentándose "+
			"({\"config\":{\"scanner_name\":\"govulncheck\",…}}) y sigue con el SBOM y el "+
			"progreso —cientos de kilobytes incluso sobre un módulo limpio—, y aquí llegaron "+
			"%d bytes con %d mensaje(s)%s. Sin escaneo no hay «sin vulnerabilidades»: "+
			"comprueba qué resuelve `govulncheck` en tu PATH o reinstálalo con "+
			"`codeguard repair`", dir, len(raw), mensajes, sinPresentarse(seIdentifico))
	}

	// UNA vulnerabilidad, UN hallazgo — aunque el código la alcance por varias
	// rutas.
	//
	// govulncheck emite un hallazgo de nivel símbolo por cada camino de llamada
	// distinto, así que una sola CVE aparece tantas veces como sitios la
	// alcancen. En el backend del portal eso convertía 9 vulnerabilidades en 28
	// hallazgos, y el desarrollador leía "28 vulnerabilidades" cuando la propia
	// herramienta decía "your code is affected by 8". Inflar el problema por 3
	// no lo hace más urgente: lo hace menos creíble.
	//
	// Y el remedio es el mismo para todas las rutas de una CVE: subir el módulo
	// UNA vez. Veintiocho hallazgos que piden lo mismo son veintisiete
	// distracciones, y veintisiete huellas de más en la baseline.
	//
	// Se conserva la primera ruta en orden estable —archivo y línea— para que
	// la huella no baile entre corridas, y el mensaje dice cuántas hay.
	rutasPorOSV := map[string]int{}
	for _, h := range crudos {
		if len(h.Trace) > 0 && h.Trace[0].Function != "" {
			rutasPorOSV[h.OSV]++
		}
	}
	sort.SliceStable(crudos, func(a, b int) bool {
		ua, ub := marcoUsuario(crudos[a].Trace), marcoUsuario(crudos[b].Trace)
		if ua == nil || ub == nil {
			return ua != nil
		}
		if ua.Position.Filename != ub.Position.Filename {
			return ua.Position.Filename < ub.Position.Filename
		}
		return ua.Position.Line < ub.Position.Line
	})

	var out []finding.Finding
	vistas := map[string]bool{}
	for _, h := range crudos {
		// Nivel módulo o paquete: presencia sin llamada — territorio de trivy.
		if len(h.Trace) == 0 || h.Trace[0].Function == "" {
			continue
		}
		if vistas[h.OSV] {
			continue // otra ruta hacia la MISMA vulnerabilidad
		}
		vistas[h.OSV] = true
		vuln := h.Trace[0]
		simbolo := vuln.Package + "." + vuln.Function

		file, line := path.Join(dir, "go.mod"), 1
		if u := marcoUsuario(h.Trace); u != nil {
			rel := filepath.ToSlash(u.Position.Filename)
			if !path.IsAbs(rel) && dir != "." {
				rel = path.Join(dir, rel)
			}
			file, line = rel, u.Position.Line
		}
		otras := ""
		if n := rutasPorOSV[h.OSV]; n > 1 {
			otras = fmt.Sprintf(" (alcanzada desde %d sitios; se arregla una sola vez)", n)
		}

		fix := "Sin versión corregida publicada todavía; evalúa mitigar o sustituir la dependencia."
		switch {
		case h.FixedVersion == "":
		case vuln.Module == "stdlib":
			fix = fmt.Sprintf("Actualiza el toolchain de Go a %s.", strings.TrimPrefix(h.FixedVersion, "v"))
		default:
			fix = fmt.Sprintf("Actualiza %s de %s a %s.", vuln.Module, vuln.Version, h.FixedVersion)
		}

		f := finding.Finding{
			Engine:      "govulncheck",
			RuleKey:     h.OSV,
			Pillar:      finding.Security,
			Severity:    finding.Error,
			Blocking:    bloquea,
			File:        file,
			Line:        line,
			Message:     fmt.Sprintf("%s alcanzable: el código llama a %s (%s@%s)%s. %s", h.OSV, simbolo, vuln.Module, vuln.Version, otras, resumen[h.OSV]),
			Why:         "Cadena de suministro (OWASP A03 2025) con prueba de alcanzabilidad: no es sólo que la dependencia tenga un CVE — el grafo de llamadas demuestra que este código ejecuta la función vulnerable.",
			FixHint:     fix,
			Verified:    true,
			Source:      finding.Deterministic,
			LineContent: vuln.Module + "@" + vuln.Version + " " + simbolo,
		}
		f.ComputeFingerprint()
		out = append(out, f)
	}
	return out, nil
}

// sinPresentarse separa las dos formas de fallar esta comprobación, porque
// mandan a mirar sitios distintos: sin cabecera, lo que corrió no era
// govulncheck; con cabecera y nada más, era él y no llegó a escanear.
func sinPresentarse(seIdentifico bool) string {
	if seIdentifico {
		return " (se presentó, pero no escaneó nada)"
	}
	return " (ni siquiera se presentó: lo que corrió no es govulncheck)"
}

// marcoUsuario es el último marco de la traza con posición: la traza va de la
// función vulnerable (en la dependencia) hacia afuera, así que el último marco
// posicionado es el punto del código propio desde el que se llega a ella.
func marcoUsuario(trace []marco) *marco {
	for i := len(trace) - 1; i >= 0; i-- {
		if trace[i].Position != nil {
			return &trace[i]
		}
	}
	return nil
}

func recorte(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}
