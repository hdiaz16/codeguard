package govulncheck

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"codeguard/internal/engines"
	"codeguard/internal/finding"
)

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

// preguntárselo, que es lo que hay que hacer con las herramientas que no dejan
// esta huella.
func interpretar(raw []byte, repoRoot, dir string, bloquea bool) ([]finding.Finding, error) {
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
		// Se ordena por la ruta YA anclada al repo: ordenar por la absoluta
		// cruda haría que «la primera ruta» dependiera del $HOME de cada
		// máquina, y con ella bailaría la huella del hallazgo elegido.
		fa := rutaEnRepo(repoRoot, dir, ua.Position.Filename)
		fb := rutaEnRepo(repoRoot, dir, ub.Position.Filename)
		if fa != fb {
			return fa < fb
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
			// Sin ruta anclable al repo (la posición cae fuera, p. ej. en el
			// caché de módulos) se conserva el go.mod del módulo: es una
			// referencia estable, y mejor eso que una absoluta que no lo es.
			if rel := rutaEnRepo(repoRoot, dir, u.Position.Filename); rel != "" {
				file, line = rel, u.Position.Line
			}
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
// rutaEnRepo ancla al repo la posición que emite govulncheck. La herramienta las
// da ABSOLUTAS del sistema de archivos, y dejarlas así rompe tres cosas: la
// huella (ComputeFingerprint incluye File) deja de coincidir entre la máquina
// del dev y el CI —o sea que la baseline no suprime lo mismo, que es justo lo
// que existe para hacer—, se filtra el $HOME en los reportes, y el hallazgo
// queda desalineado con los demás motores, que reportan relativo al repo.
// Devuelve "" cuando la absoluta cae FUERA del repo (el marco apunta al caché de
// módulos y no a código propio); el llamador cae entonces al go.mod del módulo.
func rutaEnRepo(repoRoot, dir, nombre string) string {
	rel := filepath.ToSlash(nombre)
	if path.IsAbs(rel) {
		r, err := filepath.Rel(repoRoot, filepath.FromSlash(rel))
		if err != nil {
			return "" // volúmenes distintos en Windows, por ejemplo
		}
		r = filepath.ToSlash(r)
		if r == ".." || strings.HasPrefix(r, "../") {
			return ""
		}
		return r
	}
	if dir != "." {
		return path.Join(dir, rel)
	}
	return rel
}

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
