package semgrep

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"codeguard/internal/engines"
	"codeguard/internal/engines/proc"
	"codeguard/internal/finding"
)

type Engine struct {
	Binary string // vacío = buscar en PATH
	// Cache, si no es nil, evita correr semgrep sobre archivos cuyo contenido
	// exacto ya se analizó con este rulepack y esta config (§9, file_cache).
	Cache Cache
}

// ErrSinRulepack: el repo apunta a una versión de rulepack que no está
// instalada. Merece su propio error porque no es "semgrep falló": es la
// promesa de paridad con el CI rota, y el desarrollador necesita saberlo
// con esas palabras.
var ErrSinRulepack = errors.New("no encuentro el rulepack al que apunta este repo")

func (e *Engine) Name() string { return "semgrep" }

func (e *Engine) Applies(in engines.Input) bool {
	for _, f := range in.Files {
		if f.Status != "D" {
			return true
		}
	}
	return false
}

// maxLineaComandos acota lo que se le pasa a semgrep de una sola vez.
//
// Windows corta CreateProcess a 32767 caracteres de línea de comandos, y este
// motor pasa una ruta absoluta POR ARCHIVO. Un repo de 854 archivos genera
// 105 000 caracteres: semgrep no llega a arrancar y las 112 reglas de la casa
// quedan sin aplicar — en el análisis y, peor, en la baseline. El repo de
// pruebas del propio agente tiene 156 archivos (16 000 caracteres) y por eso
// nunca lo destapó.
//
// semgrep 1.172 no tiene ninguna opción para leer los objetivos de un archivo,
// así que la salida es trocear. 30 000 deja margen para el binario, las reglas
// y el resto de argumentos.
const maxLineaComandos = 30000

// Cache es el caché de resultados deterministas (§9). Aquí la clave es el
// sha del contenido de CADA archivo — semgrep es por archivo; los motores de
// módulo usan el mismo caché con su huella agregada.
type Cache = engines.Cache

// objetivo es un archivo a analizar: ruta absoluta para semgrep, relativa
// para atribuir hallazgos, y la huella del contenido como clave de caché.
type objetivo struct {
	abs, rel, sha string
}

// Run cumple la interfaz Engine para los llamadores que no consumen recibos de
// cobertura; el pipeline usa RunConCobertura (semgrep implementa ConCobertura),
// que es donde los objetivos parcialmente analizados degradan la capa.
func (e *Engine) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	fs, _, err := e.analizar(ctx, in)
	return fs, err
}

// Plan enumera los objetivos que semgrep promete mirar: un archivo por cada
// archivo tocado no borrado. El pipeline cruza este plan contra los recibos de
// RunConCobertura — un objetivo prometido que quede a medias rompe la garantía.
func (e *Engine) Plan(in engines.Input) []engines.Unidad {
	var out []engines.Unidad
	for _, f := range in.Files {
		if f.Status == "D" {
			continue
		}
		out = append(out, engines.Unidad{Clase: "file", Ruta: filepath.ToSlash(f.Path)})
	}
	return out
}

// RunConCobertura corre y devuelve, además de los hallazgos, un recibo por
// objetivo: completo salvo los que semgrep analizó PARCIALMENTE (PartialParsing,
// Timeout del saltador interno), que van como parciales. Así lo no mirado deja
// de leerse como limpio SIN tirar los hallazgos válidos que conviven con él —el
// motivo por el que antes esto era solo un aviso (W6 Q2 cierra ese stopgap).
func (e *Engine) RunConCobertura(ctx context.Context, in engines.Input) (engines.Resultado, error) {
	fs, parciales, err := e.analizar(ctx, in)
	if err != nil {
		return engines.Resultado{}, err
	}
	return engines.Resultado{Findings: fs, Recibos: recibos(in, parciales)}, nil
}

// recibos arma un recibo por objetivo planeado: parcial si semgrep lo dejó a
// medias, completo en el resto. Un objetivo parcial que no case con ningún
// planeado se ignora (no estaba prometido).
func recibos(in engines.Input, parciales []string) []engines.Recibo {
	parcial := make(map[string]bool, len(parciales))
	for _, p := range parciales {
		parcial[p] = true
	}
	var out []engines.Recibo
	for _, f := range in.Files {
		if f.Status == "D" {
			continue
		}
		u := engines.Unidad{Clase: "file", Ruta: filepath.ToSlash(f.Path)}
		if parcial[u.Ruta] {
			out = append(out, engines.Recibo{Unidad: u, Estado: engines.CoberturaParcial, Motivo: "analisis-parcial"})
		} else {
			out = append(out, engines.Recibo{Unidad: u, Estado: engines.CoberturaCompleta})
		}
	}
	return out
}

func (e *Engine) analizar(ctx context.Context, in engines.Input) ([]finding.Finding, []string, error) {
	bin := e.Binary
	if bin == "" {
		bin = "semgrep"
	}
	rules := filepath.Join(in.RulepackDir, "semgrep")
	if _, err := os.Stat(rules); err != nil {
		return nil, nil, fmt.Errorf("%w: %s", ErrSinRulepack, rules)
	}

	// Solo archivos tocados (sección 5, etapa 2): targets explícitos.
	var pendientes []objetivo
	for _, f := range in.Files {
		if f.Status == "D" {
			continue
		}
		pendientes = append(pendientes, objetivo{
			abs: filepath.Join(in.RepoRoot, filepath.FromSlash(f.Path)),
			rel: f.Path,
			sha: f.SHA256,
		})
	}
	if len(pendientes) == 0 {
		return nil, nil, nil
	}

	// ── Aciertos de caché: mismo contenido + mismas reglas = mismos hallazgos.
	// El caché es direccionado por CONTENIDO: dos archivos idénticos comparten
	// entrada, así que al reproducir un acierto se reescribe la ruta (y con
	// ella el fingerprint) para el archivo concreto de esta corrida.
	var findings []finding.Finding
	if e.Cache != nil {
		shas := make([]string, 0, len(pendientes))
		for _, o := range pendientes {
			if o.sha != "" {
				shas = append(shas, o.sha)
			}
		}
		aciertos := e.Cache.Leer(shas)
		var quedan []objetivo
		for _, o := range pendientes {
			fs, ok := aciertos[o.sha]
			if o.sha == "" || !ok {
				quedan = append(quedan, o)
				continue
			}
			for _, f := range fs { // copia: la entrada puede servir a dos rutas
				if f.File != o.rel {
					f.File = o.rel
				}
				findings = append(findings, f)
			}
		}
		pendientes = quedan
	}
	if len(pendientes) == 0 {
		return findings, nil, nil
	}

	objetivos := make([]string, len(pendientes))
	for i, o := range pendientes {
		objetivos[i] = o.abs
	}

	var nuevos []finding.Finding
	rotasVistas := map[string]bool{}
	parcialesVistas := map[string]bool{} // rutas relativas analizadas a medias
	for _, lote := range lotes(objetivos, maxLineaComandos) {
		hallados, rotas, parciales, err := e.correrLote(ctx, bin, rules, in, lote)
		if err != nil {
			return nil, nil, err
		}
		nuevos = append(nuevos, hallados...)
		for _, r := range rotas {
			rotasVistas[r] = true
		}
		for _, p := range parciales {
			parcialesVistas[p] = true
		}
	}
	// Las reglas rotas se reportan una vez, no una por lote.
	if len(rotasVistas) > 0 {
		ids := make([]string, 0, len(rotasVistas))
		for r := range rotasVistas {
			ids = append(ids, r)
		}
		sort.Strings(ids)
		log.Printf("semgrep: %d regla(s) del rulepack no compilan y no se aplicaron: %s",
			len(ids), strings.Join(ids, ", "))
	}
	// Con reglas rotas NO se cachea: el resultado es de un pack incompleto, y
	// servirlo mañana —cuando las reglas ya compilen— sería cobertura perdida
	// que además parece un acierto. Un archivo analizado a MEDIAS tampoco se
	// cachea: un acierto futuro serviría su «sin más hallazgos» como cobertura
	// completa y ocultaría el hueco que el recibo parcial existe para declarar.
	if e.Cache != nil && len(rotasVistas) == 0 {
		e.Cache.Guardar(porArchivo(nuevos, sinParciales(pendientes, parcialesVistas), in.RepoRoot))
	}
	// Orden estable para recibos y logs reproducibles.
	parcialesRel := make([]string, 0, len(parcialesVistas))
	for p := range parcialesVistas {
		parcialesRel = append(parcialesRel, p)
	}
	sort.Strings(parcialesRel)
	return append(findings, nuevos...), parcialesRel, nil
}

// sinParciales quita de los objetivos los que quedaron analizados a medias:
// esos no entran al caché para que la próxima corrida los vuelva a mirar y a
// declarar su hueco.
func sinParciales(objetivos []objetivo, parciales map[string]bool) []objetivo {
	if len(parciales) == 0 {
		return objetivos
	}
	out := make([]objetivo, 0, len(objetivos))
	for _, o := range objetivos {
		if !parciales[filepath.ToSlash(o.rel)] {
			out = append(out, o)
		}
	}
	return out
}

// porArchivo atribuye los hallazgos recién producidos a su archivo y devuelve
// las entradas listas para el caché, cada una con su prueba de vigencia (el
// bug #8: la clave nació en el instante del diff y el motor leyó después; si
// el disco ya no coincide, la entrada mentiría). Los archivos analizados SIN
// hallazgos entran con lista vacía. Los sin huella quedan fuera.
func porArchivo(fs []finding.Finding, analizados []objetivo, repoRoot string) []engines.Cacheable {
	shaPorRel := make(map[string]string, len(analizados))
	porSha := make(map[string][]finding.Finding, len(analizados))
	relsPorSha := make(map[string][]string, len(analizados))
	var orden []string
	for _, o := range analizados {
		if o.sha == "" {
			continue
		}
		// Dos archivos con el MISMO contenido comparten entrada, y la puebla
		// sólo el primero (los hallazgos del primero son los de cualquiera).
		// Para la VIGENCIA cuentan TODAS las rutas: el acierto futuro puede
		// servirle a cualquiera de ellas.
		relsPorSha[o.sha] = append(relsPorSha[o.sha], o.rel)
		if _, ya := porSha[o.sha]; ya {
			continue
		}
		shaPorRel[o.rel] = o.sha
		porSha[o.sha] = []finding.Finding{}
		orden = append(orden, o.sha)
	}
	for _, f := range fs {
		if sha, ok := shaPorRel[f.File]; ok {
			porSha[sha] = append(porSha[sha], f)
		}
	}
	out := make([]engines.Cacheable, 0, len(orden))
	for _, sha := range orden {
		out = append(out, engines.Cacheable{
			Clave:    sha,
			Vigente:  engines.VigenciaDeArchivos(repoRoot, relsPorSha[sha], sha),
			Findings: porSha[sha],
		})
	}
	return out
}

// lotes reparte los objetivos en grupos cuya longitud sumada cabe en el límite.
// Un objetivo que por sí solo lo excediera va en su propio lote: recortarlo
// sería dejar de analizar un archivo en silencio, que es justo lo que este
// troceado viene a impedir.
func lotes(objetivos []string, limite int) [][]string {
	var out [][]string
	actual := []string{}
	largo := 0
	for _, o := range objetivos {
		coste := len(o) + 1 // +1 por el espacio separador
		if len(actual) > 0 && largo+coste > limite {
			out = append(out, actual)
			actual, largo = []string{}, 0
		}
		actual = append(actual, o)
		largo += coste
	}
	if len(actual) > 0 {
		out = append(out, actual)
	}
	return out
}

// ajustesPropios devuelve la ruta del settings.yml que usa SÓLO CodeGuard.
//
// El directorio se crea si falta; si no se puede (disco lleno, política), se
// devuelve la ruta igual: semgrep se quejará de eso, y un aviso concreto es
// mejor que caer al archivo compartido y volver a competir por él en silencio.
func ajustesPropios() string {
	base, err := os.UserCacheDir() // %LOCALAPPDATA% en Windows
	if err != nil {
		base = os.TempDir()
	}
	dir := filepath.Join(base, "CodeGuard", "semgrep")
	_ = os.MkdirAll(dir, 0o755)
	return filepath.Join(dir, "settings.yml")
}

// correrLote invoca semgrep una vez sobre los objetivos dados y devuelve sus
// hallazgos y las reglas del pack que no compilaron.
func (e *Engine) correrLote(ctx context.Context, bin, rules string, in engines.Input, objetivos []string) (hallados []finding.Finding, reglasRotas, parciales []string, err error) {
	// --timeout 0 apaga el saltador silencioso interno de semgrep: por defecto
	// (30 s por regla-archivo, 3 estrellamientos y descarta el archivo) un
	// entorno lento hacía que el archivo plantado se SALTARA sin decirlo —
	// exit 0, JSON válido, cero resultados: «corrió y limpio» sobre un archivo
	// que nadie miró (medido en el runner de CI con -race: el e2e cazó a
	// semgrep sin ver el subprocess shell=True que tenía delante). El plazo
	// que manda es el del engine (proc.Correr + ctx): si algo de verdad
	// cuelga, la capa degrada A GRITOS en vez de mentir en silencio.
	args := append([]string{"scan", "--config", rules, "--json", "--metrics=off", "--quiet",
		"--disable-version-check", "--timeout", "0"}, objetivos...)

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = in.RepoRoot
	// Sin esto, el CLI de Python lee las reglas YAML con la codificación
	// regional de Windows (cp1252) y los mensajes con acentos salen rotos.
	//
	// SEMGREP_SETTINGS_FILE nos da un archivo PROPIO. Por defecto semgrep abre
	// y ESCRIBE ~/.semgrep/settings.yml, que no es nuestro: lo comparte con el
	// plugin del IDE, con un `semgrep` que el desarrollador corra a mano y con
	// cualquier otra herramienta que lo use. Escribir en el estado de las
	// herramientas ajenas no es asunto nuestro, y nos deja expuestos a lo que
	// otro proceso le haga a ese archivo.
	//
	// Honestidad sobre el alcance: esto es higiene, no el arreglo de un fallo
	// observado. Se llegó aquí sospechando que la contención sobre ese archivo
	// causaba un `semgrep:error` real, y el control lo desmintió — seis
	// semgrep simultáneos compartiendo settings terminaron los seis sin un solo
	// PermissionError. La causa de aquel error era otra y está arreglada en
	// gitdiff (rutas entrecomilladas por git). Se mantiene la separación porque
	// quitar un recurso mutable compartido es bueno por sí solo, no porque
	// arregle nada medido.
	cmd.Env = proc.EntornoDeMotor("semgrep", proc.PerfilPython,
		"SEMGREP_SETTINGS_FILE="+ajustesPropios())
	salida, runErr := proc.Correr(ctx, cmd, proc.MaxSalida)
	out := salida.Stdout
	// Semgrep sale con 1 cuando hay hallazgos bloqueantes; el JSON sigue siendo válido.
	if runErr != nil && len(out) == 0 {
		// %w: sin él, un semgrep ausente o un plazo agotado llegaban al
		// orquestador como un error genérico y se reportaban como fallo.
		return nil, nil, nil, fmt.Errorf("semgrep no corrió: %w", runErr)
	}
	// Un JSON recortado no se puede parsear; decirlo es mejor que un error de sintaxis.
	if salida.Recortada {
		return nil, nil, nil, fmt.Errorf("semgrep devolvió más de %d MB de salida; revisa el alcance de las reglas", proc.MaxSalida>>20)
	}

	var res sgResult
	if err := json.Unmarshal(out, &res); err != nil {
		// Si el proceso ya falló, el texto no JSON no es un problema de parser:
		// es el diagnóstico (por ejemplo, el semgrep-core nativo de Windows
		// devuelve "<ERROR: missing output>" cuando falla su socketpair). Antes
		// descartábamos exit status y stderr y sólo decíamos "invalid character
		// '<'", que oculta justamente la causa accionable.
		if runErr != nil {
			detalle := strings.TrimSpace(string(out))
			if stderr := strings.TrimSpace(string(salida.Stderr)); stderr != "" {
				if detalle != "" {
					detalle += "; "
				}
				detalle += stderr
			}
			if detalle == "" {
				detalle = "sin stdout ni stderr"
			}
			return nil, nil, nil, fmt.Errorf("semgrep falló (%w) y no produjo JSON: %s", runErr, truncar(detalle, 500))
		}
		return nil, nil, nil, fmt.Errorf("salida de semgrep ilegible: %v", err)
	}
	// Antes de mirar un solo hallazgo: ¿llegó semgrep a analizar? Un JSON válido
	// con cero resultados es indistinguible de un repo limpio salvo por aquí.
	if e := res.fatal(); e != nil {
		return nil, nil, nil, fmt.Errorf("semgrep no llegó a analizar (%s): %s",
			e.Type, truncar(e.Message, 300))
	}
	// Objetivos que semgrep dejó sin analizar (Timeout, OutOfMemory, sintaxis
	// del objetivo…): la capa degrada CON nombres en vez de servir un «limpio»
	// sobre archivos que nadie miró. Ver noAnalizados.
	if omitidos := res.noAnalizados(); len(omitidos) > 0 {
		primero := omitidos[0]
		donde := primero.Path
		if donde == "" {
			donde = truncar(primero.Message, 120)
		}
		return nil, nil, nil, fmt.Errorf("semgrep dejó %d objetivo(s) sin analizar (%s: %s): degradar y decirlo gana a un limpio falso",
			len(omitidos), primero.Type, donde)
	}
	// Análisis parcial (PartialParsing y afines, nivel warn): parte del archivo
	// quedó sin mirar. Ya NO viaja como aviso: se declara como RECIBO parcial de
	// ese objetivo (W6 Q2), y el orquestador degrada la capa CON el nombre del
	// archivo SIN tirar los hallazgos válidos que conviven con él —el motivo por
	// el que esto era solo un aviso hasta ahora (en portal-cliente un parcial
	// convivía con 45 hallazgos válidos). Los recibos y los hallazgos son
	// canales separados: lo mirado se conserva, lo no mirado deja de ser limpio.
	for _, p := range res.parciales() {
		if p.Path == "" {
			// Sin ruta no hay objetivo al que colgarle el recibo; al log, que es
			// mejor que perderlo.
			log.Printf("semgrep: análisis parcial sin ruta (%s): %s", p.Type, truncar(p.Message, 200))
			continue
		}
		parciales = append(parciales, relDe(in.RepoRoot, p.Path))
	}

	findings := make([]finding.Finding, 0, len(res.Results))
	for _, r := range res.Results {
		sev := finding.Warning
		if strings.EqualFold(r.Extra.Severity, "ERROR") {
			sev = finding.Error
		}
		pillar := finding.Quality
		switch strings.ToLower(r.Extra.Metadata.Pillar) {
		case "security":
			pillar = finding.Security
		case "data":
			pillar = finding.Data
		}
		rel, err := filepath.Rel(in.RepoRoot, r.Path)
		if err != nil {
			rel = r.Path
		}
		f := finding.Finding{
			Engine:  "semgrep",
			RuleKey: shortRuleID(r.CheckID),
			Pillar:  pillar,
			// Política de compuertas §7: semgrep ERROR bloquea, WARNING avisa.
			Severity:    sev,
			Blocking:    sev == finding.Error,
			File:        filepath.ToSlash(rel),
			Line:        r.Start.Line,
			EndLine:     r.End.Line,
			Message:     r.Extra.Message,
			Why:         r.Extra.Metadata.Why,
			FixHint:     r.Extra.Metadata.FixHint,
			Verified:    true,
			Source:      finding.Deterministic,
			LineContent: firstLine(r.Extra.Lines),
		}
		findings = append(findings, f)
	}
	return findings, res.reglasRotas(), parciales, nil
}

// relDe normaliza a ruta relativa con '/' la ruta (absoluta, con '\' en
// Windows) que semgrep pone en un error de objetivo. Si no cae dentro del repo,
// se deja tal cual: mejor una ruta rara que perder el objetivo.
func relDe(repoRoot, ruta string) string {
	if r, err := filepath.Rel(repoRoot, ruta); err == nil && !strings.HasPrefix(r, "..") {
		return filepath.ToSlash(r)
	}
	return filepath.ToSlash(ruta)
}
