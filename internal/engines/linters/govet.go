package linters

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"codeguard/internal/engines"
	"codeguard/internal/finding"
	"codeguard/internal/textutil"
)

// GoVet implementa la compuerta de lint de errores para Go (§7: lint severidad
// error BLOQUEA). Corre sobre los paquetes que contienen archivos tocados.
type GoVet struct {
	// Cache: mismo contenido del módulo y mismos paquetes pedidos = mismos
	// hallazgos. La clave es la del MÓDULO y no la del archivo porque `go vet`
	// typechequea el paquete entero: el veredicto sobre un archivo depende de
	// todos sus hermanos.
	//
	// Faltaba, y era el motor sin caché que más costaba: `go vet` compila los
	// paquetes tocados. En el repo de verificación tardaba 1,5 s en frío contra
	// los 4 ms de gofmt, y lo pagaba cada commit aunque no hubiera cambiado un
	// solo byte del módulo. staticcheck —que hace exactamente lo mismo, sobre
	// los mismos paquetes— sí lo tenía desde el principio.
	Cache engines.Cache
}

func (GoVet) Name() string { return "govet" }

func (GoVet) Applies(in engines.Input) bool {
	if len(filesWithExt(in, ".go")) == 0 {
		return false
	}
	_, err := os.Stat(filepath.Join(in.RepoRoot, "go.mod"))
	return err == nil
}

// formato: path.go:12:3: mensaje
var vetLine = regexp.MustCompile(`^(.+\.go):(\d+):(?:\d+:)?\s*(.+)$`)

func (e GoVet) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	pkgs := map[string]bool{}
	for _, f := range filesWithExt(in, ".go") {
		dir := filepath.Dir(filepath.FromSlash(f.Path))
		pkgs["./"+filepath.ToSlash(dir)] = true
	}
	// Ordenados: la lista entra en la clave del caché, y un orden de mapa haría
	// que la misma corrida produjera claves distintas cada vez — un caché que
	// nunca acierta y que además parece que funciona.
	paquetes := make([]string, 0, len(pkgs))
	for p := range pkgs {
		paquetes = append(paquetes, p)
	}
	sort.Strings(paquetes)

	clave := claveVet(in.RepoRoot, paquetes)
	if e.Cache != nil && clave != "" {
		if fs, ok := e.Cache.Leer([]string{clave})[clave]; ok {
			return fs, nil
		}
	}

	// -json no es cosmético: es lo que convierte el silencio de vet en una
	// respuesta. Ver hallazgosVet.
	args := append([]string{"vet", "-json"}, paquetes...)
	stdout, stderr, err := runToolSeparado(ctx, "govet", in.RepoRoot, "go", args...)
	if err != nil {
		return nil, fmt.Errorf("go vet no corrió: %w", err)
	}
	findings, err := hallazgosVet(in.RepoRoot, stdout, stderr, paquetes)
	if err != nil {
		return nil, err
	}

	if e.Cache != nil && clave != "" {
		e.Cache.Guardar([]engines.Cacheable{{
			Clave:    clave,
			Vigente:  engines.VigenciaDeClave(clave, func() string { return claveVet(in.RepoRoot, paquetes) }),
			Findings: findings,
		}})
	}
	return findings, nil
}

// hallazgosVet parsea la salida de `go vet` y distingue "analizó y esto es lo
// que encontró" de "no llegó a analizar".
//
// Un fallo de CARGA no es un repo limpio, y hasta aquí lo parecía.
//
// runTool se traga el código de salida a propósito: los linters salen distinto
// de cero justamente cuando encuentran algo. Pero `go vet` también sale
// distinto de cero cuando no consigue cargar los paquetes —dos paquetes
// distintos en un mismo directorio, un import roto, un módulo mal resuelto— y
// entonces NO ANALIZA NADA, ni siquiera los paquetes que sí compilaban. El
// motor devolvía "0 hallazgos" y el informe daba la capa por revisada.
//
// Medido: un repo con `go vet ./...` señalando un Sprintf mal formado daba
// govet: 0 en el agente, porque otro directorio del diff no cargaba.
// staticcheck, ante exactamente el mismo repo, sí se declaraba degradado; dos
// motores con el mismo problema y respuestas opuestas.
//
// La señal es fiable: cuando vet encuentra algo, alguna línea suya casa con
// vetLine. Si no casó ninguna y aun así escribió algo, lo que escribió es un
// error de carga.
//
// Esa señal se deriva del PROPIO bucle de parseo y no de una comprobación
// aparte. Antes eran dos mecanismos respondiendo la misma pregunta: el bucle
// aplicaba la regex línea a línea (bien) y la compuerta se la aplicaba a la
// salida entera (mal — está anclada con ^/$ y sin (?m), y en Go el punto no
// casa con el salto de línea, así que sólo daba verdadero si TODA la salida era
// una única línea de diagnóstico). Con dos hallazgos, o con la cabecera
// "# paquete" delante, vet había analizado perfectamente y el motor se
// declaraba incapaz: hallazgos perdidos y compuerta bloqueante en falso.
// EL SILENCIO DE VET, QUE ERA LA ÚLTIMA PUERTA ABIERTA.
//
// El arreglo anterior cerró un caso —vet escribe algo que no es un
// diagnóstico— y dejó abiertos los dos que importaban más, porque miraba la
// salida y la salida de un vet limpio está VACÍA. Con el módulo intacto, `go
// vet` no imprime nada y sale con 0; una herramienta que no es vet y no hace
// nada tampoco imprime nada. Los dos silencios eran el mismo byte, así que el
// motor no podía elegir bien: y elegía "limpio". Medido con el arnés de
// internal/daemon: govet caía con el impostor mudo tanto si salía con 1 como si
// salía con 0.
//
// La salida NO da la respuesta. -json sí, y sale gratis (medido aquí):
//
//	paquete limpio      → stdout `{}`              · stderr vacío     · código 0
//	con diagnósticos    → stdout el JSON           · stderr vacío     · código 0
//	no compila          → stdout VACÍO             · stderr el motivo · código 1
//	uno roto y otro no  → stdout el JSON del bueno · stderr del roto
//
// Con eso, el silencio deja de ser ambiguo: **vet limpio escribe `{}`**. No
// escribir NADA por ninguno de los dos canales no es un resultado que vet pueda
// producir, y por tanto lo que corrió no era vet.
//
// Y hay un segundo arreglo de regalo, que era un falso positivo del anterior:
// juntando los canales, el ruido normal del toolchain (`go: downloading …`, que
// va por stderr) no casaba con ningún diagnóstico y govet se declaraba INCAPAZ
// sobre un módulo que había analizado perfectamente. Ahora la prueba de que
// analizó está en stdout, y el stderr se lee por lo que es.
//
// Los errores de compilación siguen entrando como HALLAZGOS BLOQUEANTES y no
// como avería, que es lo correcto: un repo que no compila no es un repo limpio,
// y además así conservan la ruta utilizable que les dio rutaDelDiagnostico.
func hallazgosVet(repoRoot, stdout, stderr string, paquetes []string) ([]finding.Finding, error) {
	informe := strings.TrimSpace(stdout)
	motivos := strings.TrimSpace(stderr)

	if informe == "" && motivos == "" {
		return nil, fmt.Errorf("go vet analizó %s y no escribió NADA: ni el `{}` que deja "+
			"cuando está limpio, ni un motivo por el que no pudo. Eso no lo produce go vet, "+
			"así que el `go` que corrió no es el que crees — comprueba tu PATH",
			strings.Join(paquetes, " "))
	}

	var findings []finding.Finding

	// El informe de stdout es la palabra de vet sobre lo que SÍ pudo analizar.
	if informe != "" {
		fs, err := hallazgosDelJSONDeVet(repoRoot, informe)
		if err != nil {
			// Un JSON que no entendemos incluye el JSON A MEDIAS de una salida
			// recortada. Es deliberado que eso sea avería y no "lo que se pudo
			// leer": un análisis parcial se cachea bajo la clave del contenido y
			// se serviría después como si estuviera completo.
			return nil, fmt.Errorf("go vet analizó %s pero no entiendo su informe: %v — %s",
				strings.Join(paquetes, " "), err, recorteVet(informe))
		}
		findings = append(findings, fs...)
	}

	// Y el stderr trae los paquetes que NO pudo cargar. Cuando vet no llegó a
	// escribir informe, esos motivos son la única respuesta que hay: si tampoco
	// se pueden leer, es avería, exactamente como antes.
	if motivos != "" {
		fs := hallazgosDelTextoDeVet(repoRoot, motivos)
		if len(fs) == 0 && informe == "" {
			return nil, fmt.Errorf("go vet no pudo analizar %s: %s",
				strings.Join(paquetes, " "), recorteVet(motivos))
		}
		findings = append(findings, fs...)
	}
	return findings, nil
}

// diagVet es un diagnóstico del informe de `go vet -json`. La forma del informe
// es {paquete: {analizador: [diagnóstico...]}}.
type diagVet struct {
	Posn    string `json:"posn"`
	Message string `json:"message"`
}

// posn viene "ruta:línea:columna" con la ruta ABSOLUTA. Se corta por la derecha
// porque en Windows la ruta lleva la unidad con sus propios dos puntos.
var vetPosn = regexp.MustCompile(`^(.*):(\d+):\d+$`)

// hallazgosDelJSONDeVet convierte el informe en hallazgos.
//
// La huella se conserva byte a byte respecto al parseo de texto anterior, y no
// es un detalle: ComputeFingerprint es RuleKey + archivo + LineContent, así que
// mover cualquiera de los tres desharía las baselines de todos los repos ya
// enrolados —un hallazgo aceptado como deuda volvería a bloquear—. Por eso
// RuleKey sigue siendo "govet" en vez del nombre del analizador, que el JSON
// ahora regala: ese cambio se puede hacer, pero es una migración de baselines,
// no un efecto colateral de este arreglo.
func hallazgosDelJSONDeVet(repoRoot, informe string) ([]finding.Finding, error) {
	// `go vet -json` NO escribe UN objeto: escribe un FLUJO, uno por cada
	// variante de paquete que analiza. Un solo directorio con archivos de test
	// ya produce dos —el paquete y su paquete de test— y sale así:
	//
	//	{}
	//	{}
	//
	// json.Unmarshal sobre eso falla con "invalid character '{' after top-level
	// value", y el motor lo trataba como «no entiendo su informe», o sea avería.
	// Resultado: en CUALQUIER módulo con tests, go vet quedaba degradado y no
	// analizaba nada — y se veía como una línea "capas no revisadas:
	// govet:error" que es fácil leer como un tropiezo pasajero.
	//
	// Se descubrió porque la compuerta de este propio repo lo dijo al commitear,
	// no leyendo el código: la medición que fijó el contrato de govet se había
	// hecho sobre UN paquete, donde el flujo tiene un solo elemento y la
	// diferencia entre «objeto» y «flujo de un objeto» no se ve.
	//
	// Con json.Decoder en bucle se leen todos y se funden. Un flujo cortado a
	// medias sigue siendo error, que es lo que debe ser: media respuesta se
	// cachearía como si fuera entera.
	porPaquete := map[string]map[string][]diagVet{}
	dec := json.NewDecoder(strings.NewReader(informe))
	for {
		var uno map[string]map[string][]diagVet
		if err := dec.Decode(&uno); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		for paquete, porAnalizador := range uno {
			if porPaquete[paquete] == nil {
				porPaquete[paquete] = map[string][]diagVet{}
			}
			for analizador, diags := range porAnalizador {
				porPaquete[paquete][analizador] = append(porPaquete[paquete][analizador], diags...)
			}
		}
	}
	// Ordenado por paquete y analizador: el recorrido de un mapa es aleatorio y
	// haría que el mismo análisis diera los hallazgos en otro orden cada vez.
	paquetes := make([]string, 0, len(porPaquete))
	for p := range porPaquete {
		paquetes = append(paquetes, p)
	}
	sort.Strings(paquetes)

	var findings []finding.Finding
	for _, p := range paquetes {
		analizadores := make([]string, 0, len(porPaquete[p]))
		for a := range porPaquete[p] {
			analizadores = append(analizadores, a)
		}
		sort.Strings(analizadores)
		for _, a := range analizadores {
			for _, d := range porPaquete[p][a] {
				ruta, linea := repartirPosn(repoRoot, d.Posn)
				findings = append(findings, hallazgoVet(ruta, linea, d.Message))
			}
		}
	}
	return findings, nil
}

// hallazgosDelTextoDeVet lee los motivos de stderr: los paquetes que no
// cargaron, en el formato de siempre (`vet.exe: p\a.go:3:26: undefined: X`).
// Las líneas que no son diagnósticos —la cabecera `# paquete`, o el ruido del
// toolchain— se ignoran.
func hallazgosDelTextoDeVet(repoRoot, motivos string) []finding.Finding {
	var findings []finding.Finding
	for _, line := range strings.Split(motivos, "\n") {
		m := vetLine.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		lineNo, _ := strconv.Atoi(m[2])
		findings = append(findings, hallazgoVet(rutaDelDiagnostico(repoRoot, m[1]), lineNo, m[3]))
	}
	return findings
}

// repartirPosn separa "ruta:línea:columna" y devuelve la ruta relativa al repo.
func repartirPosn(repoRoot, posn string) (string, int) {
	m := vetPosn.FindStringSubmatch(strings.TrimSpace(posn))
	if m == nil {
		// Sin posición utilizable, la ruta cruda es mejor que una inventada.
		return relTo(repoRoot, strings.TrimSpace(posn)), 0
	}
	linea, _ := strconv.Atoi(m[2])
	return relTo(repoRoot, m[1]), linea
}

// hallazgoVet arma el hallazgo en UN solo sitio, que es lo que garantiza que el
// informe JSON y los motivos de stderr produzcan huellas idénticas.
func hallazgoVet(ruta string, linea int, mensaje string) finding.Finding {
	f := finding.Finding{
		Engine:   "govet",
		RuleKey:  "govet",
		Pillar:   finding.Quality,
		Severity: finding.Error,
		Blocking: true,
		File:     ruta,
		Line:     linea,
		Message:  mensaje,
		Why:      "go vet solo reporta construcciones que son errores con alta certeza.",
		FixHint:  "Corrige el patrón señalado; go vet no produce falsos positivos intencionales.",
		Verified: true,
		Source:   finding.Deterministic,
	}
	return f
}

// rutaDelDiagnostico saca el nombre del archivo de la parte izquierda de una
// línea de vet, y lo devuelve relativo a la raíz del repo.
//
// `go vet` antepone el nombre de la herramienta cuando lo que reporta es un
// error de COMPILACIÓN en vez de un diagnóstico: `vet.exe: tipo\a.go:4:8:
// undefined: NoExiste`. Como la regex captura esa mitad con un `.+` glotón, el
// prefijo acababa DENTRO del nombre del archivo. Y "vet.exe: tipo/a.go" no lo
// abre ningún editor, no coincide con ningún archivo del diff, y no casa con la
// baseline porque el fingerprint incluye la ruta — o sea que un hallazgo
// suprimido reaparece y ya no hay forma de volver a suprimirlo. Nada de eso se
// nota: el pipeline no filtra por los archivos del diff (`consolidate` sólo
// deduplica), así que la ruta sucia llega entera al informe y al URI del SARIF.
//
// Empezó a pasar cuando la señal de "no pudo cargar" se derivó del propio bucle
// de parseo: los errores de compilación tienen la misma FORMA que un
// diagnóstico y desde entonces entran por la misma puerta. Que entren es lo
// correcto —un repo que no compila no es un repo limpio—; lo que faltaba es
// que entraran con una ruta utilizable.
//
// El corte es por el ÚLTIMO ": ". En Windows ningún nombre de archivo ni de
// directorio puede contener ':', y el único de una ruta es el de la unidad, que
// nunca va seguido de un espacio: por eso `vet.exe: C:\repo\a.go` deja
// `C:\repo\a.go` intacto. CodeGuard sólo se distribuye para Windows; el día que
// haya build de Linux esto necesita otra regla, porque allí ": " sí cabe dentro
// de un nombre de archivo.
//
// relTo hace el último tramo y no se reinventa aquí: ya sabe quedarse con la
// ruta tal cual cuando no cae dentro de la raíz, en vez de escupir el "../.."
// que devolvería filepath.Rel a secas.
func rutaDelDiagnostico(repoRoot, izquierda string) string {
	if i := strings.LastIndex(izquierda, ": "); i >= 0 {
		izquierda = izquierda[i+len(": "):]
	}
	return relTo(repoRoot, strings.TrimSpace(izquierda))
}

// claveVet identifica un análisis: el contenido del módulo —todos sus .go y
// manifiestos rastreados, porque la compilación depende de todos y no sólo de
// los tocados— más los paquetes pedidos. Vacía = no cacheable.
//
// Es la misma clave que usa staticcheck, y por el mismo motivo: las dos
// herramientas typechequean paquetes enteros, así que cachear por archivo daría
// aciertos falsos en cuanto un hermano cambie.
func claveVet(repoRoot string, paquetes []string) string {
	huella := engines.HuellaModulo(repoRoot, ".", func(rel string) bool {
		base := strings.ToLower(path.Base(rel))
		return base == "go.mod" || base == "go.sum" || strings.HasSuffix(base, ".go")
	})
	if huella == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(huella + "|" + strings.Join(paquetes, ",")))
	return "govet:" + hex.EncodeToString(sum[:])
}

// recorteVet deja el mensaje de error en una línea legible: el fallo de carga
// de go vet puede traer rutas largas y varias líneas, y lo que se necesita es
// saber qué pasó, no el volcado entero.
func recorteVet(s string) string {
	if i := strings.IndexByte(s, '\n'); i > 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = textutil.TruncarRunas(s, 200) + "…"
	}
	return strings.TrimSpace(s)
}
