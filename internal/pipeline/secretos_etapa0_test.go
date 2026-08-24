package pipeline

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"codeguard/internal/config"
	"codeguard/internal/engines"
	"codeguard/internal/engines/gitleaks"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
)

// N005: la etapa 0 decidía si había trabajo mirando un conjunto que la compuerta
// de secretos NO mira.
//
// filterExcluded recorre opt.Diff.Files —el diff de ÁRBOLES entre base y head,
// filtrado por paths.exclude— y si queda vacío devuelve Skipped y se acaba el
// análisis. Pero el motor de secretos en modo rango no lee in.Files ni una sola
// vez: escanea el HISTORIAL del rango con --log-opts. Son dos conjuntos
// distintos, y el pequeño estaba decidiendo por el grande.
//
// Es la cuarta puerta al mismo sitio que H009/H021, y la única que no necesita
// un atacante ni un valor raro en un flag. Medido contra gitleaks 8.30.0:
//
//	commits: c1 → c2 añade creds.go con un PAT → c3 lo borra
//
//	git diff  c1..c3            → vacío (los árboles coinciden)
//	git log   c1..c3            → 2 commits
//	gitleaks  --log-opts c1..c3 → leaks found: 1
//	codeguard ci --base c1 --head c3 → "análisis omitido", EXIT 0
//
// Eso es el flujo de quien commitea una credencial, se da cuenta y la quita en
// el commit siguiente creyendo que ya está. El secreto se queda en el historial
// para siempre, que es exactamente contra lo que existe un escáner por
// historial: el propio mensaje del hallazgo dice "borrarlo del historial NO
// invalida la credencial".
//
// El hook NO comparte esto y por eso no se toca: allí la compuerta de secretos
// corre en la fase 1, en su propio proceso, ANTES del pipeline (hook.go pasa
// Secrets: nil precisamente porque ya corrió). Comprobado: con un secreto
// preparado en una ruta excluida, el hook bloquea. Sólo el modo ci mete la
// compuerta DENTRO del pipeline, detrás de la etapa 0.

// espiaDeSecretos es la compuerta de mentira. De ella sólo importa una cosa, y
// es la que el fallo contestaba mal: si LLEGÓ A CORRER.
type espiaDeSecretos struct {
	corrio          bool
	devuelveSecreto bool
}

func (*espiaDeSecretos) Name() string               { return "gitleaks" }
func (*espiaDeSecretos) Applies(engines.Input) bool { return true }

func (e *espiaDeSecretos) Run(context.Context, engines.Input) ([]finding.Finding, error) {
	e.corrio = true
	if !e.devuelveSecreto {
		return nil, nil
	}
	f := finding.Finding{
		Engine: "gitleaks", RuleKey: "github-pat", Pillar: finding.Security,
		Severity: finding.Error, Blocking: true, File: "bin/config.txt", Line: 1,
		Message: "Secreto detectado", LineContent: "REDACTED", Source: finding.Deterministic,
	}
	f.ComputeFingerprint()
	return []finding.Finding{f}, nil
}

func cfgConExclusiones(t *testing.T, excluidos ...string) *config.Config {
	t.Helper()
	c := &config.Config{Rulepack: "test", RepoRoot: t.TempDir(), MaxDiffLines: 2000}
	c.Paths.Exclude = excluidos
	return c
}

func diffDe(rutas ...string) *gitdiff.Diff {
	d := &gitdiff.Diff{}
	for _, r := range rutas {
		d.Files = append(d.Files, gitdiff.ChangedFile{Path: r, Status: "A"})
	}
	return d
}

// El invariante, sin depender de gitleaks: que TODAS las rutas tocadas estén
// excluidas no puede dejar sin correr a la compuerta de secretos.
//
// paths.exclude sirve para no pasarle vendor/ ni los .log al analizador de
// estilo. La compuerta de secretos no analiza esas rutas —escanea el rango
// entero, sin mirar in.Files—, así que una lista de rutas no puede ser lo que
// decida si corre. Y ya era incoherente consigo misma: el MISMO secreto en el
// MISMO bin/config.txt bloqueaba si venía acompañado de un archivo no excluido
// y pasaba si venía solo.
func TestLaExclusionDeRutasNoPuedeSaltarseLaCompuertaDeSecretos(t *testing.T) {
	// El control primero: si la compuerta no corriera ni en el caso normal, el
	// resto de la prueba no distinguiría "arreglado" de "roto de otra forma".
	normal := &espiaDeSecretos{}
	res := run(t, Options{Config: cfgConExclusiones(t, "bin/**"), Diff: diffDe("a.go"), Secrets: normal})
	if !normal.corrio {
		t.Fatal("la compuerta no corrió ni con un archivo normal: la prueba no probaría nada")
	}
	if res.Verdict != Pass {
		t.Fatalf("sin hallazgos el veredicto debía ser %q, fue %q", Pass, res.Verdict)
	}

	// Y el caso del fallo: el secreto está en la única ruta tocada, y está
	// excluida.
	espia := &espiaDeSecretos{devuelveSecreto: true}
	res = run(t, Options{
		Config:  cfgConExclusiones(t, "bin/**", "**/*.log"),
		Diff:    diffDe("bin/config.txt", "logs/despliegue.log"),
		Secrets: espia,
	})
	if !espia.corrio {
		t.Fatal("la etapa 0 se saltó la compuerta de secretos porque todas las rutas " +
			"estaban excluidas: el secreto entra al historial y el análisis sale con éxito")
	}
	if res.Verdict != Block {
		t.Errorf("con un secreto delante el veredicto debía ser %q, fue %q (motivo: %q)",
			Block, res.Verdict, res.Reason)
	}
	if res.Reason == MotivoTodoExcluido {
		t.Errorf("el motivo sigue diciendo %q cuando la compuerta SÍ corrió", MotivoTodoExcluido)
	}
}

// La contraparte, para que esto no se "consiga" bloqueando de más: sin secreto,
// un cambio que sólo toca rutas excluidas sigue sin bloquear y sigue sin correr
// las compuertas deterministas, que efectivamente no tienen nada que mirar.
func TestSinSecretoLasRutasExcluidasSiguenSinBloquearNiAnalizar(t *testing.T) {
	espia := &espiaDeSecretos{}
	deterministas := &espiaDeSecretos{devuelveSecreto: true} // si corriera, bloquearía
	res := run(t, Options{
		Config:  cfgConExclusiones(t, "bin/**"),
		Diff:    diffDe("bin/config.txt"),
		Secrets: espia,
		Engines: []engines.Engine{deterministas},
	})
	if res.Verdict == Block {
		t.Errorf("un cambio limpio en rutas excluidas no puede bloquear: %q", res.Reason)
	}
	if deterministas.corrio {
		t.Error("las compuertas deterministas corrieron sobre una lista de archivos vacía: " +
			"ahí sí no hay nada que mirar, y hacerlas correr gastaría el presupuesto del commit")
	}
}

// El precio del arreglo, medido y querido: con la compuerta CAÍDA, un cambio
// que sólo toca rutas excluidas ahora BLOQUEA en vez de pasar en verde.
//
// Antes ni se intentaba, así que un CI sin gitleaks instalado daba EXIT 0 sobre
// un rango que nadie miró. Eso es precisamente lo que §14 llama fail-closed, y
// la razón de que ErrUnavailable sea la única ruta de error que bloquea: "la
// compuerta no pudo correr" no puede parecerse a "corrió y no encontró nada".
// Va con prueba propia porque es lo primero que alguien intentará "arreglar"
// cuando le tumbe un job.
func TestSiLaCompuertaNoPuedeCorrerBloqueaAunqueNoHayaArchivosAnalizables(t *testing.T) {
	res := run(t, Options{
		Config:  cfgConExclusiones(t, "bin/**"),
		Diff:    diffDe("bin/config.txt"),
		Secrets: compuertaCaida{},
	})
	if res.Verdict != Block {
		t.Errorf("veredicto = %q, se esperaba %q: una compuerta que no pudo correr "+
			"no puede terminar en verde", res.Verdict, Block)
	}
	if !strings.Contains(res.Reason, "fail-closed") {
		t.Errorf("el motivo no dice que se bloqueó por no poder mirar: %q", res.Reason)
	}
}

type compuertaCaida struct{}

func (compuertaCaida) Name() string               { return "gitleaks" }
func (compuertaCaida) Applies(engines.Input) bool { return true }
func (compuertaCaida) Run(context.Context, engines.Input) ([]finding.Finding, error) {
	return nil, fmt.Errorf("%w: no se encontró el binario", gitleaks.ErrUnavailable)
}

// Con la compuerta de secretos YA corrida —el camino del hook, que pasa
// Secrets: nil— la etapa 0 tiene que seguir cortando exactamente como antes.
// Es la mitad del contrato que no puede cambiar: ese camino corre en CADA
// commit y allí el conjunto del diff SÍ es el que mira la compuerta.
func TestConLaCompuertaYaCorridaLaEtapa0SigueCortandoIgual(t *testing.T) {
	res := run(t, Options{
		Config:  cfgConExclusiones(t, "bin/**"),
		Diff:    diffDe("bin/config.txt"),
		Secrets: nil,
	})
	if res.Verdict != Skipped {
		t.Errorf("veredicto = %q, se esperaba %q", res.Verdict, Skipped)
	}
	if res.Reason != MotivoTodoExcluido {
		t.Errorf("motivo = %q, se esperaba %q — el hook lo compara por valor para "+
			"decidir el tono del mensaje", res.Reason, MotivoTodoExcluido)
	}
}

// Y el caso de verdad, contra gitleaks de verdad: el secreto que se añade y se
// borra dentro del rango. Aquí no hay ninguna exclusión de por medio — el diff
// de árboles sale vacío porque el árbol final es idéntico al inicial.
func TestUnSecretoAnadidoYBorradoDentroDelRangoNoSeSaltaElAnalisis(t *testing.T) {
	repo, base, head := repoConSecretoAnadidoYBorrado(t)

	d, err := gitdiff.Range(repo, base, head)
	if err != nil {
		t.Fatalf("el rango debió leerse: %v", err)
	}
	// El control que hace la prueba honesta: si el diff NO saliera vacío,
	// estaríamos midiendo el camino de siempre y no el del fallo.
	if len(d.Files) != 0 {
		t.Fatalf("el diff de árboles debía salir vacío y trajo %d archivo(s): "+
			"la prueba ya no reproduce N005", len(d.Files))
	}

	cfg := &config.Config{Rulepack: "test", RepoRoot: repo, MaxDiffLines: 2000}
	res, err := Run(context.Background(), Options{
		Config:  cfg,
		Diff:    d,
		Secrets: &gitleaks.Engine{Mode: "range", Base: base, Head: head},
	})
	if err != nil {
		t.Fatalf("no esperaba error: %v", err)
	}
	if res.Verdict == Skipped {
		t.Fatalf("el análisis se omitió (%q) con un secreto vivo en el historial del rango: "+
			"el job del CI sale con EXIT 0 y la credencial queda commiteada", res.Reason)
	}
	if res.Verdict != Block {
		t.Fatalf("veredicto = %q, se esperaba %q — gitleaks ve el PAT en el rango %s..%s",
			res.Verdict, Block, base[:8], head[:8])
	}
	if len(res.Findings) == 0 || res.Findings[0].Engine != "gitleaks" {
		t.Errorf("el hallazgo no vino de la compuerta de secretos: %+v", res.Findings)
	}
}

// Y su contraparte con gitleaks real: un rango igual de vacío pero SIN secreto
// no puede acabar bloqueando. Sin esto, "arreglarlo" bloqueando todo rango de
// diff vacío pasaría la prueba de arriba.
func TestUnRangoDeDiffVacioSinSecretoNoBloquea(t *testing.T) {
	repo, base, head := repoConArchivoAnadidoYBorrado(t)

	d, err := gitdiff.Range(repo, base, head)
	if err != nil {
		t.Fatalf("el rango debió leerse: %v", err)
	}
	if len(d.Files) != 0 {
		t.Fatalf("el diff debía salir vacío y trajo %d archivo(s)", len(d.Files))
	}

	cfg := &config.Config{Rulepack: "test", RepoRoot: repo, MaxDiffLines: 2000}
	res, err := Run(context.Background(), Options{
		Config:  cfg,
		Diff:    d,
		Secrets: &gitleaks.Engine{Mode: "range", Base: base, Head: head},
	})
	if err != nil {
		t.Fatalf("no esperaba error: %v", err)
	}
	if res.Verdict == Block {
		t.Errorf("un rango sin secretos no puede bloquear: %q · %+v", res.Reason, res.Findings)
	}
}

// ── andamiaje ────────────────────────────────────────────────────────────────

// El PAT va partido en dos trozos a propósito, como en internal/shadow/redact_test.go:
// entero, la compuerta de secretos de ESTE repo lo caza al commitear la prueba
// que lo usa. gitleaks lo detecta igual porque lo ve ya concatenado en el
// archivo del repo temporal.
const patDePrueba = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"

func repoConSecretoAnadidoYBorrado(t *testing.T) (repo, base, head string) {
	t.Helper()
	repo, base = repoBase(t)
	escribirEn(t, repo, "creds.go", "package p\n\nconst Token = \""+patDePrueba+"\"\n")
	gitEn(t, repo, "add", "-A")
	gitEn(t, repo, "commit", "-q", "-m", "wip: conectando la API")
	gitEn(t, repo, "rm", "-q", "creds.go")
	gitEn(t, repo, "commit", "-q", "-m", "quito la clave de ahí")
	return repo, base, revision(t, repo, "HEAD")
}

func repoConArchivoAnadidoYBorrado(t *testing.T) (repo, base, head string) {
	t.Helper()
	repo, base = repoBase(t)
	escribirEn(t, repo, "temporal.go", "package p\n\nfunc Temporal() {}\n")
	gitEn(t, repo, "add", "-A")
	gitEn(t, repo, "commit", "-q", "-m", "wip")
	gitEn(t, repo, "rm", "-q", "temporal.go")
	gitEn(t, repo, "commit", "-q", "-m", "ya no hace falta")
	return repo, base, revision(t, repo, "HEAD")
}

func repoBase(t *testing.T) (repo, base string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("sin git no hay rango que leer")
	}
	if _, err := exec.LookPath("gitleaks"); err != nil {
		t.Skip("sin gitleaks no hay compuerta de secretos que probar — `codeguard repair` lo instala")
	}
	repo = t.TempDir()
	gitEn(t, repo, "init", "-q", "-b", "main", ".")
	gitEn(t, repo, "config", "user.email", "prueba@codeguard.local")
	gitEn(t, repo, "config", "user.name", "Prueba")
	gitEn(t, repo, "config", "commit.gpgsign", "false")
	escribirEn(t, repo, "a.go", "package p\n")
	gitEn(t, repo, "add", "-A")
	gitEn(t, repo, "commit", "-q", "-m", "inicial")
	return repo, revision(t, repo, "HEAD")
}

func gitEn(t *testing.T, repo string, args ...string) {
	t.Helper()
	c := exec.Command("git", args...)
	c.Dir = repo
	// Sin la config del usuario: un include global con hooks o alias propios
	// cambiaría lo que la prueba mide.
	c.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "HOME="+repo, "USERPROFILE="+repo)
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func revision(t *testing.T, repo, ref string) string {
	t.Helper()
	c := exec.Command("git", "rev-parse", ref)
	c.Dir = repo
	out, err := c.Output()
	if err != nil {
		t.Fatalf("git rev-parse %s: %v", ref, err)
	}
	return strings.TrimSpace(string(out))
}

func escribirEn(t *testing.T, repo, rel, contenido string) {
	t.Helper()
	ruta := filepath.Join(repo, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(ruta), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ruta, []byte(contenido), 0o644); err != nil {
		t.Fatal(err)
	}
}
