package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Este archivo es la SEGUNDA versión del contrato de huellas, diseñada en el
// consejo (turnos 71-84) para desbloquear #9 y todo arreglo futuro de huella.
//
// El defecto de v1, medido en producción (.codeguard/baseline.txt:33): la
// huella es sha256(regla+ruta+contenido-de-línea), así que CUATRO usos
// idénticos de esc() en main.js colapsan en UNA — baselinear uno suprime los
// futuros del mismo texto, un agujero en «solo lo nuevo bloquea». Y como no
// lleva versión, cualquier mejora invalida todas las baselines del mundo sin
// transición posible: el incentivo estructural era no arreglar huellas jamás.
//
// Lo que v2 cambia, y por qué así:
//   - PREFIJO textual "v2:": la versión viaja CON la identidad por las seis
//     superficies persistidas (baseline, BD, informe, cable, SARIF, caché).
//     Un canal lateral de versión es la ambigüedad silenciosa de siempre: la
//     superficie que lo pierda no falla ruidosa — adivina mal callada.
//   - ENGINE en el hash: dos motores con la misma rule_key ya no colisionan
//     (reportcmd.go lo padecía: «los fingerprints previos no dicen de qué
//     motor salieron»).
//   - ANCLA CONTEXTUAL: las líneas vecinas no vacías del contenido analizado.
//     Distingue ocurrencias idénticas por su contexto SIN meter el número de
//     línea (la exclusión de la línea es la feature que protege baselines de
//     los desplazamientos, y se conserva). El ordinal de ocurrencia se evaluó
//     y se VETÓ (turno 83): borrar la 1.ª ocurrencia aceptada hacía que una
//     ocurrencia NUEVA heredara su ordinal y quedara suprimida — un falso
//     negativo determinista, «solo lo nuevo bloquea» violado con código nuevo.
//   - REGLA DE AMBIGÜEDAD: si dos hallazgos de una corrida producen la misma
//     v2 (mismo texto Y mismo contexto), se marcan ambiguos y NINGUNO se
//     suprime ni entra a la baseline. La falla es siempre hacia bloquear:
//     editar contexto puede resucitar deuda aceptada (ruido honesto), pero
//     jamás entierra una ocurrencia nueva en silencio.
//   - ASIGNACIÓN COLECTIVA (AsignarHuellas): la ambigüedad exige ver el
//     conjunto, así que la huella se asigna UNA vez por corrida, no en cada
//     parser. Un test arquitectónico prohíbe calcular huellas fuera de este
//     paquete (el llamador 37 es como vuelven a divergir).

// VersionHuella es la versión vigente del contrato.
const VersionHuella = 2

// SunsetV1 es la fecha ("2026-11-30") en que la ventana dual muere: la
// inyecta build-dist como release+90 días (reloj inyectable — nada cableado,
// y los tests no dependen de la fecha real). Vacía = ventana ABIERTA: un
// binario de desarrollo nunca apaga solo la compatibilidad de nadie. La
// fecha NORMATIVA es esta, la del binario; la cabecera de baseline.txt es
// informativa (un baseline copiado de otro repo no fija el reloj ajeno —
// condición de Kimi, turno 76).
var SunsetV1 = ""

// VentanaDualActiva dice si el alias v1 sigue vivo. Es LA compuerta única:
// cuando devuelve false, AsignarHuellas deja de emitir LegacyFingerprint y
// con él mueren de una vez la supresión legacy (HuellasDeBusqueda), la clave
// SARIF /v1 y la columna de BD — apagar v1 no es una cacería por sitios.
// Una fecha que no parsea se trata como ventana ABIERTA y se registra: ante
// la duda, compatibilidad — cerrar por un typo re-bloquearía la deuda
// aceptada del mundo entero.
func VentanaDualActiva(hoy time.Time) bool {
	if SunsetV1 == "" {
		return true
	}
	corte, err := time.Parse("2006-01-02", SunsetV1)
	if err != nil {
		log.Printf("huellas: SunsetV1 %q no parsea — la ventana dual sigue abierta", SunsetV1)
		return true
	}
	return !hoy.After(corte)
}

// PrefijoV2 es el prefijo textual de las huellas del contrato vigente.
const PrefijoV2 = "v2:"

// ParseHuella clasifica un token de huella almacenado. Devuelve la versión
// (1 o 2) y si el token es válido. La regla dura, aprendida del fpRe del
// informe que moría en silencio: LO DESCONOCIDO NO SE CASA COMO NADA — un
// "v3:..." futuro, un hex en mayúsculas o un token recortado devuelven
// ok=false, y el consumidor debe avisar y NO suprimir, jamás adivinar.
func ParseHuella(token string) (version int, ok bool) {
	if resto, con := strings.CutPrefix(token, PrefijoV2); con {
		if esHex64(resto) {
			return 2, true
		}
		return 0, false
	}
	if esHex64(token) {
		return 1, true
	}
	return 0, false
}

func esHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// FuenteDeLineas entrega las líneas del contenido ANALIZADO de una ruta
// relativa, para calcular el ancla contextual. Puede ser nil (sin fuente no
// hay ancla: la huella sigue siendo válida, solo distingue menos). Si el
// worktree cambió durante el análisis, el aviso del bug #8 ya lo declara —
// esta fuente lee lo mismo que leyeron los motores.
type FuenteDeLineas func(rel string) []string

// FuenteDeArchivos es LA fuente estándar: lee del worktree bajo repoRoot,
// confinada al repo (las rutas vienen de los motores y del modelo; el hábito
// no se negocia). La comparten pipeline, sombra y hook para que la MISMA
// ocurrencia produzca la MISMA huella venga por el camino que venga — dos
// fuentes distintas serían dos identidades distintas del mismo hallazgo.
// El ancla solo entra al hash: leer vecinas de una línea sensible no expone
// nada — sha256 no tiene vuelta.
func FuenteDeArchivos(repoRoot string) FuenteDeLineas {
	return func(rel string) []string {
		full := filepath.Clean(filepath.Join(repoRoot, filepath.FromSlash(rel)))
		if !strings.HasPrefix(full, filepath.Clean(repoRoot)+string(filepath.Separator)) {
			return nil
		}
		raw, err := os.ReadFile(full)
		if err != nil {
			return nil
		}
		return strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")
	}
}

// AsignarHuellas calcula la huella v2 y la legacy v1 de cada hallazgo, UNA
// sola vez y para el conjunto entero — es EL único sitio del producto que
// asigna identidad (los parsers ya no llaman a ComputeFingerprint; la
// migración por tandas está en la bitácora 2026-08-22).
//
// El orden de entrada no importa: la ambigüedad se decide por igualdad de
// huella, no por posición. Los hallazgos que ya traían huella la pierden
// aquí a propósito: un acierto de caché re-hidratado debe re-derivar con el
// contrato vigente, no arrastrar el de la corrida que lo escribió. El ancla
// es transferible entre rutas que comparten contenido (contenido idéntico ⇒
// vecinas idénticas ⇒ ancla idéntica), que es la propiedad de la que
// dependen las entradas de caché compartidas.
func AsignarHuellas(fs []Finding, fuente FuenteDeLineas) {
	porArchivo := map[string][]string{}
	lineasDe := func(rel string) []string {
		if fuente == nil {
			return nil
		}
		if l, ya := porArchivo[rel]; ya {
			return l
		}
		l := fuente(rel)
		porArchivo[rel] = l
		return l
	}
	conLegacy := VentanaDualActiva(time.Now())
	grupos := map[string][]*Finding{}
	for i := range fs {
		f := &fs[i]
		lineas := lineasDe(f.File)
		// Clase Linea sin LineContent (los motores «mensaje»/híbridos que ya
		// no ponen el mensaje): la línea real se lee AQUÍ, centralmente, de la
		// misma fuente que el ancla (W6, t.128). Si no se puede leer (archivo
		// borrado, línea fuera de rango), el hallazgo pasa a NoDisponible: no
		// se suprime ni entra en baseline, pero queda visible.
		if f.Identidad == IdentidadLinea && f.LineContent == "" {
			if linea, ok := lineaReal(lineas, f.Line); ok {
				f.LineContent = linea
			} else {
				f.Identidad = IdentidadNoDisponible
				f.NoSuprimible = true
			}
		}
		f.Fingerprint = huellaV2(f, anclaDe(lineas, f.Line))
		f.LegacyFingerprint = ""
		if conLegacy && !f.NoSuprimible {
			f.LegacyFingerprint = huellaV1(f.RuleKey, f.File, contenidoLegacy(f))
		}
		f.HuellaAmbigua = false
		// Un hallazgo no suprimible no entra en la detección de ambigüedad ni
		// agrupa: ya es no-suprimible, la ambigüedad no le añade nada.
		if !f.NoSuprimible {
			grupos[f.Fingerprint] = append(grupos[f.Fingerprint], f)
		}
	}
	for _, g := range grupos {
		if len(g) > 1 {
			for _, f := range g {
				f.HuellaAmbigua = true
			}
		}
	}
}

// huellaV2: el dominio del hash lleva la versión DENTRO además del prefijo
// textual — un v3 futuro cambia el dominio y ningún v2 colisiona con él ni
// por accidente.
func huellaV2(f *Finding, ancla string) string {
	h := sha256.Sum256([]byte("v2\x00" + f.Engine + "\x00" + f.RuleKey + "\x00" +
		filepath.ToSlash(f.File) + "\x00" + strings.TrimSpace(f.LineContent) + "\x00" + ancla))
	return PrefijoV2 + hex.EncodeToString(h[:])
}

// huellaV1 reproduce EXACTAMENTE el algoritmo viejo (ComputeFingerprint):
// es el alias de transición que permite que una baseline v1 siga suprimiendo
// durante la ventana dual. Nunca es identidad primaria.
func huellaV1(rule, file, contenido string) string {
	h := sha256.Sum256([]byte(rule + "\x00" + filepath.ToSlash(file) + "\x00" + strings.TrimSpace(contenido)))
	return hex.EncodeToString(h[:])
}

// contenidoLegacy devuelve el insumo que la versión v1 usaba como
// "contenido" para este motor. Para casi todos es el LineContent actual; los
// motores cuya disciplina cambia en v2 (mensaje→línea real) registran aquí su
// reconstrucción EXACTA en el mismo commit que migra su parser — cada entrada
// se verifica contra la huella que el binario viejo producía, no se asume.
func contenidoLegacy(f *Finding) string {
	switch f.Engine {
	case "llm":
		// v1 hasheaba el mensaje del modelo (shadow_verify ponía
		// LineContent: lf.Message — H202); en v2 LineContent es la línea
		// real. El mensaje sigue en f.Message, así que la v1 se reproduce
		// exacta. Verificado en TestLaLegacyDelLLMReproduceLaHuellaVieja.
		return f.Message
	case "eslint", "govet", "staticcheck", "mypy", "biome", "dotnet-format":
		// W6 (t.128): estos seis motores hasheaban el MENSAJE en v1 (su parser
		// ponía LineContent = mensaje); en v2 LineContent es la línea real del
		// archivo. El mensaje sigue en f.Message, así que la v1 se reproduce
		// EXACTA durante la ventana dual — verificado por motor contra la
		// huella del binario viejo (fixture por motor).
		return f.Message
	case "ruff", "tsc", "dotnet-build", "pmd":
		// W6 (t.128), los cuatro HÍBRIDOS: su v1 hasheaba «<regla> <mensaje>»
		// (el parser ponía LineContent = RuleKey + " " + Message —medido en
		// ruff.go, tsc.go, dotnetbuild_parser.go, javalint_parser.go—); en v2
		// LineContent es la línea real. Ambos insumos siguen en el hallazgo
		// (RuleKey y Message), así que la v1 se reproduce EXACTA durante la
		// ventana — verificado por motor contra la huella del binario viejo.
		return f.RuleKey + " " + f.Message
	}
	return f.LineContent
}

// lineaReal devuelve la línea n (1-indexada), recortada, y si se pudo leer.
// Es la MISMA fuente que anclaDe, para que la línea y su contexto sean
// coherentes.
func lineaReal(lineas []string, n int) (string, bool) {
	if n < 1 || n > len(lineas) {
		return "", false
	}
	return strings.TrimSpace(lineas[n-1]), true
}

// anclaDe compone el ancla: la línea vecina no vacía anterior y la siguiente,
// recortadas, separadas por \x00. Sin líneas (fuente nil, archivo ilegible,
// hallazgo de archivo/módulo entero) el ancla es vacía y la huella vale
// igual — solo distingue menos, que es exactamente lo que había en v1.
func anclaDe(lineas []string, n int) string {
	if len(lineas) == 0 || n < 1 || n > len(lineas) {
		return ""
	}
	antes := ""
	for i := n - 2; i >= 0; i-- {
		if l := strings.TrimSpace(lineas[i]); l != "" {
			antes = l
			break
		}
	}
	despues := ""
	for i := n; i < len(lineas); i++ {
		if l := strings.TrimSpace(lineas[i]); l != "" {
			despues = l
			break
		}
	}
	if antes == "" && despues == "" {
		return ""
	}
	return antes + "\x00" + despues
}

// HuellasDeBusqueda arma el conjunto con el que un mapa de supresiones se
// consulta durante la ventana dual: la v2 siempre, y la legacy v1 si existe.
// Vive aquí para que el pipeline, el informe y el historial pregunten LO
// MISMO — la mecánica de la ventana en un solo sitio (condición de Kimi,
// turno 76). Devuelve orden estable para logs reproducibles.
func (f *Finding) HuellasDeBusqueda() []string {
	out := []string{f.Fingerprint}
	if f.LegacyFingerprint != "" && f.LegacyFingerprint != f.Fingerprint {
		out = append(out, f.LegacyFingerprint)
	}
	sort.Strings(out)
	return out
}
