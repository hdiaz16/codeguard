// Package gitleaks adapta el escáner de secretos (etapa 1, BLOQUEANTE, OFFLINE).
package gitleaks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"codeguard/internal/engines"
	"codeguard/internal/engines/proc"
	"codeguard/internal/finding"
	"codeguard/internal/gitref"
)

type Engine struct {
	// Binary es la ruta al ejecutable; si está vacío se busca en PATH.
	Binary string
	// Mode: "staged" (hook) o "range" (ci, requiere Base/Head).
	Mode string
	Base string
	Head string
}

func (e *Engine) Name() string { return "gitleaks" }

func (e *Engine) Applies(engines.Input) bool { return true }

// ErrUnavailable distingue "gitleaks no pudo correr" (fail-closed con mensaje
// de reparación, sección 14) de "corrió y no encontró nada".
var ErrUnavailable = errors.New("gitleaks no disponible")

// rango arma el "base..head" de --log-opts sólo si ambos extremos siguen
// siendo referencias y no se han convertido en opciones de git por el camino
// (H009: gitleaks parte --log-opts por espacios y le da cada trozo a `git
// log`). El criterio vive en internal/gitref, que es el mismo que aplica
// gitdiff antes de leer el diff: una sola frontera, no dos que se separen.
//
// La política de qué hacer cuando falla sí es de aquí: se envuelve en
// ErrUnavailable para que el pipeline BLOQUEE fail-closed (§14) en vez de dar
// el escaneo por bueno. gitref no sabe nada de eso, y así debe seguir.
func (e *Engine) rango() (string, error) {
	r, err := gitref.ValidarRango(e.Base, e.Head)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return r, nil
}

type leak struct {
	RuleID      string `json:"RuleID"`
	Description string `json:"Description"`
	File        string `json:"File"`
	StartLine   int    `json:"StartLine"`
	EndLine     int    `json:"EndLine"`
	Match       string `json:"Match"`
}

// coloresDeConsola son las secuencias ANSI con que gitleaks pinta su registro.
// Se quitan antes de leerlo porque el nivel viene envuelto en ellas
// (`\x1b[32mINF\x1b[0m`) y sin quitarlas ningún campo es igual a "ERR".
var coloresDeConsola = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

// erroresDeGitleaks devuelve las líneas de su registro con nivel ERR o FTL, que
// son las que dicen que algo no llegó a mirarse.
//
// Se comparan CAMPOS y no subcadenas: buscar "ERR" en el texto lo encontraría
// dentro de una ruta o de un mensaje cualquiera, y un falso positivo aquí bloquea
// todos los commits del repo. Se devuelven como mucho tres: el motivo cabe en un
// mensaje, el volcado entero no.
func erroresDeGitleaks(stderr []byte) []string {
	var fallos []string
	for _, linea := range strings.Split(string(coloresDeConsola.ReplaceAll(stderr, nil)), "\n") {
		linea = strings.TrimSpace(linea)
		if linea == "" {
			continue
		}
		for _, campo := range strings.Fields(linea) {
			// WRN no cuenta: "WRN leaks found: 1" es el camino con hallazgos.
			if campo != "ERR" && campo != "FTL" {
				continue
			}
			if len(fallos) < 3 {
				fallos = append(fallos, linea)
			} else {
				return fallos
			}
			break
		}
	}
	return fallos
}

func (e *Engine) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	bin := e.Binary
	if bin == "" {
		bin = "gitleaks"
	}
	if _, err := exec.LookPath(bin); err != nil {
		return nil, fmt.Errorf("%w: %v — ejecuta `codeguard repair`", ErrUnavailable, err)
	}

	// ── Pasada 1: gitleaks sobre el repo, tal cual ──────────────────────
	// `protect` está deprecado desde 8.19: se usa `gitleaks git` (spec §5 etapa 1).
	args := []string{"git", "--redact", "--report-format", "json", "--report-path", "", "--exit-code", "9"}
	switch e.Mode {
	case "staged":
		args = append(args, "--pre-commit", "--staged")
	case "range":
		rango, err := e.rango()
		if err != nil {
			return nil, err
		}
		args = append(args, "--log-opts", rango)
	default:
		return nil, fmt.Errorf("%w: modo desconocido %q", ErrUnavailable, e.Mode)
	}
	args = append(args, in.RepoRoot)

	leaks, err := e.correr(ctx, bin, in.RepoRoot, args)
	if err != nil {
		return nil, err
	}

	// ── Pasada 2: la misma tijera, pero fuera del alcance del repo ──────
	reescaneados, err := e.reescaneoNeutral(ctx, bin, in)
	if err != nil {
		return nil, err
	}

	return hallazgos(append(leaks, reescaneados...)), nil
}

// correr lanza una corrida de gitleaks y devuelve lo que encontró, o el porqué
// de que su silencio no valga (contrato de los motores: hallazgos o el porqué).
//
// args tiene que llevar el hueco de --report-path como cadena vacía; el
// temporal se crea aquí para que ninguna pasada pueda reutilizar el reporte de
// otra —que es exactamente el fallo por el que un DLL viejo dejaba pasar al
// impostor de dotnet-build con la prueba de otra corrida.
func (e *Engine) correr(ctx context.Context, bin, dir string, args []string) ([]leak, error) {
	report, err := os.CreateTemp("", "codeguard-gitleaks-*.json")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	// Sólo se necesita el NOMBRE del temporal; gitleaks lo reescribe. El
	// cierre y el borrado son de limpieza: su fallo no cambia el análisis.
	_ = report.Close()
	defer func() { _ = os.Remove(report.Name()) }()

	args = append([]string(nil), args...)
	hueco := -1
	for i, a := range args {
		if a == "--report-path" && i+1 < len(args) {
			hueco = i + 1
			break
		}
	}
	if hueco < 0 {
		return nil, fmt.Errorf("%w: corrida mal armada, sin --report-path", ErrUnavailable)
	}
	args[hueco] = report.Name()

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	cmd.Env = proc.Entorno()
	salida, runErr := proc.Correr(ctx, cmd, proc.MaxSalida)
	out := salida.Combinada()

	var exitErr *exec.ExitError
	switch {
	case runErr == nil:
		// Código 0 = gitleaks terminó y no encontró nada. NO se devuelve aquí:
		// hay que leer el reporte igual que en el caso con hallazgos. El porqué
		// está en el bloque de abajo, que es el arreglo.
	case errors.As(runErr, &exitErr) && exitErr.ExitCode() == 9:
		// exit 9 = hallazgos (lo fijamos con --exit-code); cualquier otro código es error real
	default:
		return nil, fmt.Errorf("%w: %v: %s", ErrUnavailable, runErr, out)
	}

	// EL REPORTE, Y NO EL CÓDIGO DE SALIDA, ES LA PRUEBA DE QUE GITLEAKS MIRÓ.
	//
	// Hasta aquí el camino del código 0 devolvía (nil, nil) sin abrir nada, y eso
	// hacía indistinguibles dos cosas: «gitleaks escaneó el índice y no hay
	// secretos» y «lo que corrió no era gitleaks, y terminó contento». La segunda
	// apaga la ÚNICA compuerta bloqueante del producto —la que decide si una
	// credencial sale del portátil— y la apaga pintando verde.
	//
	// No es una avería imaginada: es la misma clase que se cobró a govet y a tsc
	// el mismo día, y el arnés de internal/daemon la reproduce sustituyendo la
	// herramienta por un impostor que sale con 0 sin escribir una palabra.
	//
	// La señal estaba delante todo el tiempo: gitleaks escribe --report-path
	// SIEMPRE, también cuando no encuentra nada. Medido con 8.30.1 sobre un
	// índice limpio: sale 0 y deja `[]` —tres bytes— en el archivo. Y el temporal
	// lo creamos nosotros vacío unas líneas más arriba, así que una herramienta
	// que salga con 0 sin escribir deja cero bytes ahí, y cero bytes no son JSON.
	// Por eso no hace falta comprobar la identidad del binario por separado: el
	// reporte ES la prueba de identidad, y sale gratis.
	// Y EL RESQUICIO QUE EL REPORTE NO CIERRA, QUE ES PEOR QUE EL ORIGINAL.
	//
	// El reporte demuestra que gitleaks CORRIÓ. No demuestra que MIRARA. Lo
	// encontró el validador y está reproducido aquí: con el `.git/index`
	// corrupto, el `git diff` que gitleaks lanza por dentro falla, y gitleaks
	// **sale con 0 y escribe su reporte con `[]` dentro**. El mismo índice, con
	// git sano, daba código 9 y 529 bytes de reporte con el secreto. O sea que
	// «escaneé y no hay secretos» y «no pude leer nada» vuelven a producir bytes
	// idénticos, un nivel más abajo. Igual con un rango que no resuelve, o con una
	// ruta que no es un repo.
	//
	// Lo que sí los separa (medido en los dos casos): gitleaks CUENTA lo que le
	// pasó por stderr, con nivel.
	//
	//	limpio de verdad → INF 0 commits scanned · INF no leaks found
	//	con hallazgos    → WRN leaks found: 1              (código 9)
	//	índice corrupto  → ERR [git] fatal: index file… · ERR error="stderr is not empty"
	//
	// Así que en el camino del código 0 —el único donde el silencio se
	// interpreta como limpieza— una sola línea ERR o FTL invalida el veredicto.
	// WRN queda fuera a propósito: «leaks found» es WRN y es el camino NORMAL.
	//
	// Esto BLOQUEA el commit (ErrUnavailable, §14 fail-closed), y es lo correcto:
	// la promesa de la etapa 1 no es «busqué», es «nada sale sin escanear».
	if runErr == nil {
		if fallos := erroresDeGitleaks(salida.Stderr); len(fallos) > 0 {
			return nil, fmt.Errorf("%w: dijo que no había secretos, pero antes contó %d "+
				"error(es) propios, así que no escaneó lo que se le pidió: %s. "+
				"Un «sin secretos» de una corrida que falló no es un «sin secretos» — "+
				"comprueba el repositorio (`git status`, `git fsck`) y vuelve a intentarlo",
				ErrUnavailable, len(fallos), strings.Join(fallos, " · "))
		}
	}

	raw, err := os.ReadFile(report.Name())
	if err != nil {
		return nil, fmt.Errorf("%w: no dejó reporte que leer: %v", ErrUnavailable, err)
	}
	var leaks []leak
	if err := json.Unmarshal(raw, &leaks); err != nil {
		// El tamaño va en el mensaje porque separa las dos averías de un vistazo:
		// 0 bytes es "salió bien sin escribir nada" (no era gitleaks); con bytes
		// dentro, es un formato que no esperábamos (una versión que cambió).
		return nil, fmt.Errorf("%w: terminó con éxito pero su reporte no es el de gitleaks "+
			"(%d bytes en %s): %v — ejecuta `codeguard repair`",
			ErrUnavailable, len(raw), filepath.Base(report.Name()), err)
	}
	return leaks, nil
}

// hallazgos convierte los leaks de TODAS las pasadas en hallazgos, quitando los
// repetidos.
//
// Las dos pasadas se solapan a propósito —el mismo secreto en un archivo normal
// lo ven las dos— y las dos numeran la línea REAL del archivo (medido: un token
// en la línea 4 sale como StartLine 4 por los dos caminos), así que regla +
// archivo + línea identifica el mismo secreto sin falsos duplicados. Se queda
// el primero, que es el de la pasada 1: ésa lleva la descripción de las reglas
// PROPIAS del repo cuando las hay, y es la que el dev reconoce.
func hallazgos(leaks []leak) []finding.Finding {
	vistos := make(map[string]bool, len(leaks))
	findings := make([]finding.Finding, 0, len(leaks))
	for _, l := range leaks {
		archivo := filepath.ToSlash(l.File)
		clave := l.RuleID + "\x00" + archivo + "\x00" + strconv.Itoa(l.StartLine)
		if vistos[clave] {
			continue
		}
		vistos[clave] = true
		f := finding.Finding{
			Engine:   "gitleaks",
			RuleKey:  l.RuleID,
			Pillar:   finding.Security,
			Severity: finding.Error,
			Blocking: true,
			File:     archivo,
			Line:     l.StartLine,
			EndLine:  l.EndLine,
			Message:  "Secreto detectado: " + l.Description,
			Why: "Un secreto commiteado queda en el historial de git para siempre. " +
				"Borrarlo del historial NO invalida la credencial: hay que rotarla primero.",
			FixHint:     "1) Rota la credencial en el proveedor. 2) Saca el valor a una variable de entorno o al gestor de secretos. 3) Vuelve a commitear.",
			Verified:    true,
			Source:      finding.Deterministic,
			LineContent: l.Match, // ya viene redactado por --redact
		}
		f.ComputeFingerprint()
		findings = append(findings, f)
	}
	return findings
}
