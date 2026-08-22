package semgrep

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"codeguard/internal/engines"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
)

// Los tres payloads de abajo son salidas REALES de semgrep 1.x capturadas
// contra este mismo repo. El primero es el que estuvo mintiendo durante toda la
// vida del proyecto.

// Escaneo abortado: una raíz inválida y semgrep no analiza NADA. El JSON es
// válido y results viene vacío, así que sin mirar errors es indistinguible de
// un repo impecable. Ocurría porque `git ls-files` entrecomilla y escapa las
// rutas con acentos, y ese literal se pasaba como target.
const salidaEscaneoAbortado = `{
  "results": [],
  "errors": [
    {"code": 2, "level": "error", "type": "SemgrepError",
     "message": "Invalid scanning root: C:\\repo\\\"docs\\Telemetr\\303\\255a.md\""}
  ]
}`

// Escaneo sano: corrió de verdad. Trae errores, pero ninguno invalida el
// resultado — cinco reglas del pack no compilan (patrones inválidos para C# y
// Go) y tres archivos se pasaron de tiempo. Nótese que "Rule parse error"
// también llega con level "error": por eso el discriminador es el tipo.
const salidaConAvisos = `{
  "results": [
    {"check_id": "rulepacks.2026.08.2.semgrep.go-dinero-float",
     "path": "internal/config/config.go",
     "start": {"line": 106}, "end": {"line": 106},
     "extra": {"message": "Importe monetario en float64.", "severity": "ERROR",
               "lines": "\tPriceInPerMTok  float64", "metadata": {"pillar": "data"}}}
  ],
  "errors": [
    {"code": 2, "level": "error", "type": "Rule parse error",
     "rule_id": "rulepacks.2026.08.2.semgrep.log-dato-sensible",
     "message": "Invalid pattern for C#"},
    {"code": 2, "level": "error", "type": "Rule parse error",
     "rule_id": "rulepacks.2026.08.2.semgrep.pii-en-telemetria",
     "message": "Invalid pattern for C#"},
    {"code": 2, "level": "warn", "type": "Timeout",
     "message": "Timeout in cmd/daemon/frontend/3d-force-graph.js"}
  ]
}`

// Repo limpio de verdad: cero resultados y cero errores.
const salidaLimpia = `{"results": [], "errors": []}`

// El campo "type" de un error NO siempre es string: para las variantes con
// argumentos semgrep serializa un arreglo cuyo primer elemento es el nombre.
// Payload real de bds.portal: un archivo TS parcialmente parseado. Declarar
// Type como string tumbaba el unmarshal COMPLETO — 45 hallazgos validos
// descartados por no poder leer el tipo de un aviso.
const salidaConTipoArreglo = `{
  "results": [
    {"check_id": "rulepacks.2026.08.2.semgrep.ts-explicit-any",
     "path": "frontend/src/lib/api.ts",
     "start": {"line": 12}, "end": {"line": 12},
     "extra": {"message": "any explicito", "severity": "ERROR",
               "lines": "function f(x: any) {", "metadata": {"pillar": "quality"}}}
  ],
  "errors": [
    {"code": 3, "level": "warn",
     "type": ["PartialParsing", [{"path": "frontend\\src\\features\\notifications\\index.ts",
       "start": {"line": 18, "col": 8, "offset": 0},
       "end": {"line": 18, "col": 12, "offset": 0}}]],
     "message": "Syntax error at line frontend\\src\\features\\notifications\\index.ts:18"}
  ]
}`

func TestTipoDeErrorComoArregloNoTumbaElEscaneo(t *testing.T) {
	res := parsear(t, salidaConTipoArreglo)
	if len(res.Results) != 1 {
		t.Fatalf("los hallazgos deben sobrevivir al tipo-arreglo; hubo %d", len(res.Results))
	}
	if got := res.Errors[0].Type; got != "PartialParsing" {
		t.Errorf("el nombre de la variante debe extraerse del arreglo: %q", got)
	}
	// Un archivo parcialmente parseado no invalida el escaneo.
	if res.fatal() != nil {
		t.Error("PartialParsing no es fatal: el resto del archivo y del repo se analizo")
	}
}

func parsear(t *testing.T, s string) sgResult {
	t.Helper()
	var res sgResult
	if err := json.Unmarshal([]byte(s), &res); err != nil {
		t.Fatalf("payload de prueba ilegible: %v", err)
	}
	return res
}

// El fallo que costó mas caro del proyecto: cero hallazgos y "no pude mirar"
// se contaban como lo mismo. `codeguard report` anunciaba COMPLETADO mientras
// habia 28 hallazgos reales, y la baseline se genero igual de ciega.
func TestEscaneoAbortadoNoPasaPorLimpio(t *testing.T) {
	abortado := parsear(t, salidaEscaneoAbortado)
	if len(abortado.Results) != 0 {
		t.Fatal("el payload de prueba debe traer cero resultados: ese es el caso")
	}
	e := abortado.fatal()
	if e == nil {
		t.Fatal("un escaneo abortado debe detectarse como fatal, no leerse como repo limpio")
	}
	if !strings.Contains(e.Message, "Invalid scanning root") {
		t.Errorf("el error fatal perdio su mensaje: %q", e.Message)
	}

	// Y un repo genuinamente limpio no debe confundirse con uno abortado.
	if parsear(t, salidaLimpia).fatal() != nil {
		t.Error("cero resultados y cero errores es un repo limpio, no un fallo")
	}
}

// El salto callado: un error de nivel "error" que no sea regla-rota significa
// que un objetivo quedo SIN analizar, y hasta aqui pasaba en silencio — exit 0,
// JSON valido, cero resultados: «corrio y limpio» sobre un archivo que nadie
// miro (medido en el CI con -race: el e2e cazo a semgrep sin ver el
// subprocess shell=True plantado). Los warn (Timeout del saltador interno —
// hoy apagado con --timeout 0 —, PartialParsing) se DICEN sin tumbar la capa:
// en bds.portal un archivo parcialmente parseado convivia con 45 hallazgos
// validos.
func TestUnObjetivoSaltadoNoEsLimpio(t *testing.T) {
	res := parsear(t, `{
	  "results": [],
	  "errors": [
	    {"code": 2, "level": "error", "type": "OutOfMemory",
	     "path": "app/inseguro.py", "message": "semgrep ran out of memory"},
	    {"code": 2, "level": "warn", "type": "Timeout",
	     "message": "Timeout in cmd/daemon/frontend/3d-force-graph.js"},
	    {"code": 2, "level": "error", "type": "Rule parse error",
	     "rule_id": "rulepacks.2026.08.2.semgrep.log-dato-sensible",
	     "message": "Invalid pattern"}
	  ]
	}`)
	om := res.noAnalizados()
	if len(om) != 1 || om[0].Path != "app/inseguro.py" {
		t.Fatalf("noAnalizados = %+v; el OutOfMemory de nivel error es el unico que tumba", om)
	}
	pa := res.parciales()
	if len(pa) != 1 || pa[0].Type != "Timeout" {
		t.Fatalf("parciales = %+v; el Timeout warn se dice sin tumbar", pa)
	}
	if rotas := res.reglasRotas(); len(rotas) != 1 {
		t.Fatalf("reglasRotas = %v; la regla rota no es ni omitido ni parcial", rotas)
	}
}

// La exigencia de la revision: PartialParsing con cero resultados NO puede
// presentarse como limpio. El aviso viaja como hallazgo WARNING no bloqueante
// en el veredicto —la unica superficie que el desarrollador mira—, no como un
// log del daemon. Y no bloquea (P4): degradar la capa entera por un parcial
// tiraria los hallazgos validos que conviven con el (bds.portal: 45).
func TestUnParcialConCeroResultadosNoEsLimpio(t *testing.T) {
	res := parsear(t, `{"results":[],"errors":[
	  {"code":3,"level":"warn","type":["PartialParsing",[{}]],
	   "path":"C:\\repo\\doc\\raro.ts","message":"parcial"}]}`)
	avisos := avisosParciales(res, `C:\repo`)
	if len(avisos) != 1 {
		t.Fatalf("avisos = %+v; un parcial con cero resultados no puede quedar en nada", avisos)
	}
	a := avisos[0]
	if a.Blocking || a.Severity != finding.Warning {
		t.Errorf("el aviso debe ser WARNING no bloqueante (P4), llego: bloqueante=%v severidad=%v", a.Blocking, a.Severity)
	}
	if a.File != "doc/raro.ts" {
		t.Errorf("File = %q; el aviso cuelga del archivo afectado, relativo al repo", a.File)
	}
	if a.Fingerprint == "" {
		t.Error("sin huella el aviso no sobrevive baseline ni dedupe")
	}
}

// Un "Rule parse error" llega con level "error" pero el escaneo SI corrio: sus
// resultados valen. Tratarlo como fatal apagaria el motor entero cada vez que
// una sola regla del pack tenga un patron invalido — que es justo lo que le
// pasa hoy a cinco reglas de este rulepack.
func TestUnaReglaRotaNoInvalidaElEscaneo(t *testing.T) {
	res := parsear(t, salidaConAvisos)
	if res.fatal() != nil {
		t.Error("reglas rotas y timeouts no invalidan el escaneo: sus hallazgos son buenos")
	}
	if len(res.Results) != 1 {
		t.Fatalf("se esperaba 1 hallazgo, hubo %d", len(res.Results))
	}

	rotas := res.reglasRotas()
	if len(rotas) != 2 {
		t.Fatalf("se esperaban 2 reglas rotas, hubo %d: %v", len(rotas), rotas)
	}
	for _, esperada := range []string{"log-dato-sensible", "pii-en-telemetria"} {
		var encontrada bool
		for _, r := range rotas {
			if r == esperada {
				encontrada = true
			}
		}
		if !encontrada {
			t.Errorf("%q no aparece entre las reglas rotas: %v", esperada, rotas)
		}
	}
	// El timeout es un aviso por archivo, no una regla rota.
	for _, r := range rotas {
		if strings.Contains(r, "Timeout") {
			t.Errorf("un timeout no es una regla rota: %v", rotas)
		}
	}
}

// Windows corta CreateProcess a 32767 caracteres y este motor pasa una ruta
// POR ARCHIVO. Medido: el repo bds.portal, con 854 archivos, genera 105 029
// caracteres — semgrep no llegaba a arrancar y las 112 reglas de la casa
// quedaban sin aplicar, tambien al generar la baseline. El repo del propio
// agente tiene 156 archivos (16 218 caracteres) y por eso nunca lo destapo.
func TestLotesRespetanElLimiteDeLineaDeComandos(t *testing.T) {
	// 854 rutas del largo real que tienen en ese repo.
	objetivos := make([]string, 854)
	for i := range objetivos {
		objetivos[i] = "C:\\Users\\alguien\\Desktop\\01-Proyectos-GitHub\\BODESA\\bds.portal\\backend\\internal\\infra\\archivo.go"
	}

	const limite = maxLineaComandos
	grupos := lotes(objetivos, limite)
	if len(grupos) < 2 {
		t.Fatalf("854 rutas largas deben trocearse; salio %d lote(s)", len(grupos))
	}

	var total int
	for i, g := range grupos {
		largo := 0
		for _, o := range g {
			largo += len(o) + 1
		}
		// Un lote de mas de un objetivo NUNCA debe pasarse del limite.
		if len(g) > 1 && largo > limite {
			t.Errorf("lote %d mide %d, por encima del limite %d", i, largo, limite)
		}
		total += len(g)
	}
	// Y sobre todo: no se puede perder ni un archivo por el camino. Analizar
	// un subconjunto en silencio es el fallo que esto viene a impedir.
	if total != len(objetivos) {
		t.Errorf("se perdieron objetivos: %d de %d", total, len(objetivos))
	}
}

// Una ruta tan larga que no cabe por si sola va en su propio lote, no se
// descarta: dejar de analizar un archivo sin decirlo es peor que una llamada
// que falle ruidosamente.
func TestLoteConUnObjetivoDemasiadoLargo(t *testing.T) {
	larga := strings.Repeat("x", 50)
	grupos := lotes([]string{larga, larga}, 40)
	if len(grupos) != 2 {
		t.Fatalf("se esperaban 2 lotes de uno, salieron %d", len(grupos))
	}
	for _, g := range grupos {
		if len(g) != 1 {
			t.Errorf("cada lote deberia llevar un solo objetivo, lleva %d", len(g))
		}
	}
}

// Pocos archivos —el caso del hook— siguen yendo en una sola invocacion: el
// troceado no puede costar arranques en frio de mas donde antes no los habia.
func TestPocosObjetivosVanEnUnSoloLote(t *testing.T) {
	grupos := lotes([]string{"a.go", "b.go", "c.go"}, maxLineaComandos)
	if len(grupos) != 1 {
		t.Errorf("tres archivos deben ir en un lote, salieron %d", len(grupos))
	}
}

// El id que semgrep reporta viene con la ruta del rulepack por delante; al dev
// se le muestra el nombre corto.
func TestShortRuleID(t *testing.T) {
	casos := map[string]string{
		"rulepacks.2026.08.2.semgrep.go-dinero-float": "go-dinero-float",
		"go-dinero-float": "go-dinero-float",
		"":                "",
	}
	for entrada, esperado := range casos {
		if got := shortRuleID(entrada); got != esperado {
			t.Errorf("shortRuleID(%q) = %q, se esperaba %q", entrada, got, esperado)
		}
	}
}

// ── caché por archivo ────────────────────────────────────────────────────────

type cacheDePrueba struct {
	entradas  map[string][]finding.Finding
	guardados map[string][]finding.Finding
}

func (c *cacheDePrueba) Leer(shas []string) map[string][]finding.Finding {
	out := map[string][]finding.Finding{}
	for _, sha := range shas {
		if fs, ok := c.entradas[sha]; ok {
			out[sha] = fs
		}
	}
	return out
}

func (c *cacheDePrueba) Guardar(porSHA map[string][]finding.Finding) {
	c.guardados = porSHA
}

func dirConReglas(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "semgrep"), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// Con TODOS los archivos en caché, semgrep no se ejecuta: el binario apunta a
// un nombre que no existe y Run aun así responde. Esa es la promesa entera
// del caché — y de paso prueba la reescritura de ruta: dos archivos con el
// mismo contenido comparten entrada, pero cada hallazgo sale con SU ruta y
// SU fingerprint.
func TestCacheTotalNoEjecutaSemgrep(t *testing.T) {
	guardado := finding.Finding{
		Engine: "semgrep", RuleKey: "python-eval", File: "original.py", Line: 3,
		LineContent: "eval(x)", Message: "eval",
	}
	guardado.ComputeFingerprint()

	cache := &cacheDePrueba{entradas: map[string][]finding.Finding{
		"sha-a": {guardado},
		"sha-b": {},
	}}
	e := &Engine{Binary: "semgrep-que-no-existe.exe", Cache: cache}
	fs, err := e.Run(context.Background(), engines.Input{
		RepoRoot:    t.TempDir(),
		RulepackDir: dirConReglas(t),
		Files: []gitdiff.ChangedFile{
			{Path: "original.py", Status: "M", SHA256: "sha-a"},
			{Path: "copia/duplicado.py", Status: "A", SHA256: "sha-a"},
			{Path: "limpio.py", Status: "M", SHA256: "sha-b"},
		},
	})
	if err != nil {
		t.Fatalf("con caché total no hay nada que ejecutar, pero Run falló: %v", err)
	}
	if len(fs) != 2 {
		t.Fatalf("esperaba 2 hallazgos (uno por copia del contenido), hay %d: %+v", len(fs), fs)
	}
	rutas := map[string]string{} // ruta → fingerprint
	for _, f := range fs {
		rutas[f.File] = f.Fingerprint
	}
	if _, ok := rutas["original.py"]; !ok {
		t.Error("falta el hallazgo del archivo original")
	}
	if _, ok := rutas["copia/duplicado.py"]; !ok {
		t.Error("falta el hallazgo del duplicado: la entrada es por contenido y debe servir a ambas rutas")
	}
	if rutas["original.py"] == rutas["copia/duplicado.py"] {
		t.Error("rutas distintas deben producir fingerprints distintos (la ruta es parte de la huella)")
	}
}

// Un archivo sin huella jamás pasa por el caché: ni acierta ni se guarda.
func TestSinHuellaNoHayCache(t *testing.T) {
	cache := &cacheDePrueba{entradas: map[string][]finding.Finding{}}
	e := &Engine{Binary: "semgrep-que-no-existe.exe", Cache: cache}
	_, err := e.Run(context.Background(), engines.Input{
		RepoRoot:    t.TempDir(),
		RulepackDir: dirConReglas(t),
		Files:       []gitdiff.ChangedFile{{Path: "x.py", Status: "M"}}, // sin SHA256
	})
	if err == nil {
		t.Fatal("sin huella el archivo debía ir a semgrep (que aquí no existe): Run debió fallar")
	}
}

// porArchivo atribuye por ruta y garantiza la entrada vacía del archivo limpio.
func TestPorArchivoAtribuyeYRegistraLimpios(t *testing.T) {
	analizados := []objetivo{
		{rel: "a.py", sha: "sha-a"},
		{rel: "b.py", sha: "sha-b"},
		{rel: "sin-huella.py", sha: ""},
	}
	fs := []finding.Finding{
		{File: "a.py", RuleKey: "r1"},
		{File: "a.py", RuleKey: "r2"},
		{File: "sin-huella.py", RuleKey: "r3"},
	}
	m := porArchivo(fs, analizados)
	if len(m) != 2 {
		t.Fatalf("esperaba 2 entradas (a y b; sin-huella no es cacheable): %v", m)
	}
	if len(m["sha-a"]) != 2 {
		t.Errorf("a.py debía aportar 2 hallazgos: %v", m["sha-a"])
	}
	if fs, ok := m["sha-b"]; !ok || len(fs) != 0 {
		t.Errorf("b.py se analizó y quedó limpio: su entrada vacía ES el resultado: %v", m)
	}
}

// Ciclo completo con el semgrep real: la primera corrida puebla el caché (el
// limpio con lista vacía), la segunda —con el binario roto— sirve lo mismo
// desde el caché. Es el contrato de F2a de punta a punta.
func TestCacheCicloCompletoConSemgrepReal(t *testing.T) {
	if testing.Short() {
		t.Skip("integración: ejecuta semgrep real")
	}
	if _, err := exec.LookPath("semgrep"); err != nil {
		t.Skip("semgrep no está en PATH")
	}
	rulepack := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rulepack, "semgrep"), 0o755); err != nil {
		t.Fatal(err)
	}
	regla := `rules:
  - id: python-eval
    languages: [python]
    severity: ERROR
    message: "eval prohibido"
    pattern: "eval(...)"
`
	if err := os.WriteFile(filepath.Join(rulepack, "semgrep", "regla.yaml"), []byte(regla), 0o644); err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "malo.py"), []byte("eval(entrada)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "limpio.py"), []byte("x = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	files := []gitdiff.ChangedFile{
		{Path: "malo.py", Status: "M", SHA256: gitdiff.SHA256De(repo, "malo.py")},
		{Path: "limpio.py", Status: "M", SHA256: gitdiff.SHA256De(repo, "limpio.py")},
	}

	cache := &cacheDePrueba{entradas: map[string][]finding.Finding{}}
	primera, err := (&Engine{Cache: cache}).Run(context.Background(),
		engines.Input{RepoRoot: repo, RulepackDir: rulepack, Files: files})
	if err != nil {
		t.Fatalf("primera corrida: %v", err)
	}
	if len(primera) != 1 || primera[0].File != "malo.py" {
		t.Fatalf("esperaba exactamente el eval de malo.py: %+v", primera)
	}
	if cache.guardados == nil {
		t.Fatal("la corrida limpia debió poblar el caché")
	}
	if fs, ok := cache.guardados[files[1].SHA256]; !ok || len(fs) != 0 {
		t.Fatalf("limpio.py debió guardarse con lista vacía: %v", cache.guardados)
	}
	if len(cache.guardados[files[0].SHA256]) != 1 {
		t.Fatalf("malo.py debió guardarse con su hallazgo: %v", cache.guardados)
	}

	// Segunda corrida: binario roto + caché poblado = mismos hallazgos.
	cache.entradas = cache.guardados
	segunda, err := (&Engine{Binary: "semgrep-que-no-existe.exe", Cache: cache}).Run(context.Background(),
		engines.Input{RepoRoot: repo, RulepackDir: rulepack, Files: files})
	if err != nil {
		t.Fatalf("segunda corrida (todo cacheado): %v", err)
	}
	if len(segunda) != 1 || segunda[0].Fingerprint != primera[0].Fingerprint {
		t.Fatalf("el caché debe reproducir el resultado exacto:\n primera: %+v\n segunda: %+v", primera, segunda)
	}
}
