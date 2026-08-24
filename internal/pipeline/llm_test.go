package pipeline_test

// Fase 5.3 — la capa LLM nunca bloquea, y lo que sale a la red va redactado.
//
// Son las dos promesas del producto más fáciles de romper sin que nadie lo
// note, porque las dos fallan EN SILENCIO: un modelo que bloquea sólo se ve el
// día que rechaza un commit bueno, y un diff que viaja sin redactar no se ve
// nunca — el secreto ya está en el proveedor.
//
// P2 dice que el modelo no bloquea. P5 dice que nada que parezca credencial
// sale a la red. Las dos están escritas en el código (Blocking: false «no
// negociable», Redact antes de armar el prompt), y las dos se comprueban aquí
// INTERCEPTANDO LA LLAMADA: se levanta un servidor que hace de modelo y se mira
// lo que de verdad le llegó. Que la función de redacción exista y tenga sus
// pruebas de unidad no demuestra que alguien la llame en el camino real.
//
// El modelo falso responde hallazgos marcados como críticos, que es la forma de
// preguntar «¿y si el modelo insiste?».

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// modeloFalso hace de proveedor: apunta lo que le llega y contesta en el
// dialecto de OpenAI (SSE), que es el que habla el cliente con provider=openai.
type modeloFalso struct {
	*httptest.Server
	mu       sync.Mutex
	cuerpos  []string
	llamadas int
	primera  time.Time
}

func (m *modeloFalso) registrar(cuerpo string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.llamadas == 0 {
		m.primera = time.Now()
	}
	m.llamadas++
	m.cuerpos = append(m.cuerpos, cuerpo)
}

func (m *modeloFalso) veces() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.llamadas
}

func (m *modeloFalso) todoLoEnviado() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return strings.Join(m.cuerpos, "\n")
}

// esperarLlamada espera a que el modelo reciba al menos una petición.
func (m *modeloFalso) esperarLlamada(limite time.Duration) bool {
	hasta := time.Now().Add(limite)
	for time.Now().Before(hasta) {
		if m.veces() > 0 {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

// Los dos hallazgos que devuelve el modelo falso, y qué debe pasar con cada uno.
//
// El del medio es el interesante: el modelo INSISTE en que algo es crítico. La
// sombra no lo degrada a aviso — lo RECHAZA entero, porque el modelo no emite
// errores (verify()). Es una defensa más fuerte que "Blocking: false" y por eso
// se prueba aparte: si alguien la relajara para "aprovechar" los hallazgos
// graves del modelo, esto tiene que ponerse rojo.
const (
	mensajeCritico = "el modelo insiste en que esto es gravisimo"
	mensajeAviso   = "el modelo sugiere renombrar la variable"
)

// levantarModelo devuelve un proveedor falso que contesta DOS hallazgos: uno
// crítico (debe rechazarse) y uno de aviso (debe aceptarse, sin bloquear).
//
// Los dos con confianza alta y sobre un archivo y una línea que existen en el
// diff, para que lo único que los distinga sea la severidad.
func levantarModelo(t *testing.T, archivo string, linea int) *modeloFalso {
	t.Helper()
	m := &modeloFalso{}
	respuesta := fmt.Sprintf(`{"findings":[`+
		`{"file":%q,"line":%d,"rule_key":"ad-hoc","severity":"critical","confidence":0.99,`+
		`"message":%q,"why":"porque si","fix_hint":"arreglalo"},`+
		`{"file":%q,"line":%d,"rule_key":"ad-hoc","severity":"warning","confidence":0.99,`+
		`"message":%q,"why":"claridad","fix_hint":"renombra"}]}`,
		archivo, linea, mensajeCritico, archivo, linea, mensajeAviso)

	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ReadAll y no un Read suelto: un único Read puede devolver menos bytes
		// de los pedidos, y registrar un cuerpo truncado haría que el arnés
		// juzgara una petición que no es la que el cliente mandó — el aserto de
		// que la clave viaja redactada pasaría en falso si la clave quedó en el
		// trozo no leído. El error de lectura tampoco se traga: un cuerpo a
		// medias dado por bueno es justo el "parece que se miró" que este arnés
		// existe para cazar. Errorf y no Fatalf porque esto corre en la goroutine
		// del servidor, donde FailNow no es legal.
		cuerpo, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("no se pudo leer el cuerpo de la petición al modelo: %v", err)
		}
		m.registrar(string(cuerpo))

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		trozo, _ := json.Marshal(map[string]any{
			"choices": []map[string]any{{"delta": map[string]string{"content": respuesta}}},
		})
		fmt.Fprintf(w, "data: %s\n\n", trozo)
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	t.Cleanup(m.Close)
	return m
}

func configConModelo(rulepack string, urlModelo string) string {
	return "version: 1\nrulepack: \"" + rulepack + "\"\nmax_diff_lines: 50000\n" +
		// umbral 0: la sombra corre siempre, sin depender del riesgo que
		// calcule RADAR para este fixture.
		"risk:\n  threshold: 0\n" +
		"llm:\n" +
		"  provider: openai\n" +
		"  endpoint: " + urlModelo + "\n" +
		"  api_key_env: CODEGUARD_PRUEBA_LLM\n" +
		"  model: modelo-de-prueba\n" +
		"  timeout_ms: 20000\n" +
		"  max_diff_tokens: 4000\n"
}

// ── 5.3.a · el modelo no bloquea, y ni siquiera llega a tiempo de intentarlo ──

func TestLaCapaLLMNoBloqueaAunqueElModeloInsista(t *testing.T) {
	bin, binDaemon, repo, datos, pipe := prepararLLM(t)
	copiarRulepack(t, repo)
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-q", "-m", "añadir rulepack", "--no-verify")
	modelo := levantarModelo(t, "app/tocado.py", 1)
	escribir(t, repo, ".codeguard/config.yaml", configConModelo("2026.08.2", modelo.URL))
	escribir(t, repo, "app/tocado.py", "def suma(a: int, b: int) -> int:\n    return a + b\n")
	gitConEntorno(t, repo, datos, "add", "-A")

	arrancarDaemonConLLM(t, binDaemon, datos, pipe)

	inicio := time.Now()
	salida, codigo := correrPorElPipe(t, bin, repo, datos, pipe)
	tardo := time.Since(inicio)

	if codigo != 0 {
		t.Fatalf("el gancho bloqueó un cambio limpio: la capa LLM no puede ser la causa "+
			"pero tampoco hay nada que medir aquí.\n%s", salida)
	}
	t.Logf("  ✓ el veredicto salió en %.1fs y permitió el commit", tardo.Seconds())

	// La sombra corre DESPUÉS de responder al hook. Si el commit hubiera
	// esperado al modelo, la primera llamada sería anterior a la respuesta.
	if !modelo.esperarLlamada(60 * time.Second) {
		t.Fatalf("el modelo no recibió ninguna llamada: la capa LLM no se encendió y "+
			"esta prueba no ha medido nada.\n%s\n--- LOG DAEMON ---\n%s", salida, colaDelLog(t, datos))
	}
	if modelo.primera.Before(inicio.Add(tardo)) {
		t.Errorf("el modelo recibió la llamada ANTES de que el gancho terminara: "+
			"el commit está esperando al modelo (%.1fs de veredicto)", tardo.Seconds())
	} else {
		t.Log("  ✓ el modelo se llamó después del veredicto: fuera de banda")
	}

	// Y el fondo del asunto: lo que el modelo devolvió no bloquea a nadie.
	//
	// Se exige que el hallazgo de AVISO haya llegado a la base antes de mirar
	// nada más: sin él, "ninguno bloquea" sería cero de cero.
	esperarHallazgosLLM(t, datos, 30*time.Second)

	// LÍMITE de esta comprobación, medido y no supuesto: P2 se defiende en DOS
	// capas —verify() construye el hallazgo con Blocking:false, y el INSERT de
	// SaveLLMFindings escribe blocking = 0 literal— así que esto sólo se pone
	// rojo si se rompen las dos. Se hizo el control poniendo Blocking:true en
	// verify() y la prueba siguió verde: el literal del store lo tapaba.
	//
	// Se deja como está —mide el estado final, que es lo que sufre el usuario— y
	// cada capa lleva su propio control: la de verify() la pina la comprobación
	// del hallazgo crítico de aquí abajo, y la del store,
	// TestUnHallazgoDelModeloNuncaSeGuardaComoBloqueante.
	if n := hallazgosLLMBloqueantes(t, datos); n > 0 {
		t.Errorf("%d hallazgo(s) del MODELO quedaron marcados como bloqueantes.\n"+
			"P2 no es negociable: el modelo aconseja, no decide. Un modelo que bloquea "+
			"convierte cada commit en una tirada de dados.", n)
	} else {
		t.Logf("  ✓ %d hallazgo(s) del modelo en la base, ninguno bloqueante",
			contarHallazgosLLM(t, datos))
	}

	// Y el crítico: no se degrada a aviso, se descarta. Si apareciera —aunque
	// fuera como aviso— querría decir que el modelo puede colar su propia
	// escala de gravedad en el informe del usuario.
	if hayHallazgoLLMConMensaje(t, datos, mensajeCritico) {
		t.Error("el hallazgo que el modelo marcó como CRÍTICO entró igualmente.\n" +
			"verify() lo rechaza precisamente para que el modelo no imponga su escala: " +
			"el día que se relaje, el informe del usuario se llena de alarmas del modelo.")
	} else {
		t.Log("  ✓ el hallazgo que el modelo marcó como crítico fue rechazado, no degradado")
	}
}

// ── 5.3.b · lo que sale a la red va redactado ──

func TestLoQueViajaAlModeloVaRedactado(t *testing.T) {
	bin, binDaemon, repo, datos, pipe := prepararLLM(t)
	copiarRulepack(t, repo)
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-q", "-m", "añadir rulepack", "--no-verify")
	modelo := levantarModelo(t, "app/conexion.py", 1)
	escribir(t, repo, ".codeguard/config.yaml", configConModelo("2026.08.2", modelo.URL))

	// Una credencial que la compuerta de secretos NO bloquea —si bloqueara, no
	// habría llamada que inspeccionar— pero que la redacción sí tiene que tapar.
	const laClave = "Contrasenya-De-La-Base-1234"
	escribir(t, repo, "app/conexion.py",
		"CADENA = \"Server=db;Database=x;User Id=sa;Password="+laClave+";\"\n")
	gitConEntorno(t, repo, datos, "add", "-A")

	arrancarDaemonConLLM(t, binDaemon, datos, pipe)
	salida, codigo := correrPorElPipe(t, bin, repo, datos, pipe)
	if codigo != 0 {
		t.Skipf("la compuerta de secretos bloqueó este fixture, así que no hay "+
			"llamada que inspeccionar; hace falta otra credencial de prueba.\n%s", salida)
	}
	if !modelo.esperarLlamada(60 * time.Second) {
		t.Fatalf("el modelo no recibió ninguna llamada: sin tráfico no se puede "+
			"comprobar qué viaja.\n%s", salida)
	}
	// Un momento más: la sombra manda un prompt por pilar y basta con que uno
	// se cuele sin redactar.
	time.Sleep(3 * time.Second)

	enviado := modelo.todoLoEnviado()
	if strings.Contains(enviado, laClave) {
		t.Errorf("la contraseña VIAJÓ EN CLARO al proveedor.\n"+
			"P5 dice que nada que parezca credencial sale a la red, y esto ya no se "+
			"puede deshacer: el secreto está en el otro lado.\n"+
			"fragmento: %s", alrededorDe(enviado, laClave))
	} else {
		t.Log("  ✓ la contraseña no aparece en nada de lo enviado")
	}
	if !strings.Contains(enviado, "REDACTADO") {
		t.Errorf("no aparece ninguna marca de redacción en las %d llamada(s): "+
			"puede que el diff viaje por otro camino que no pasa por Redact",
			modelo.veces())
	} else {
		t.Log("  ✓ la marca de redacción está en lo que se envió")
	}
}

// ── 5.3.c · con un secreto, NADA sale a la red ──
//
// El gancho se lo dice al usuario con esas palabras cuando bloquea. Es una
// promesa concreta y verificable, y de las que más cuesta creer sin medirla:
// justo el commit con el secreto dentro es el que más apetece analizar.

func TestConUnSecretoNadaSaleALaRed(t *testing.T) {
	bin, binDaemon, repo, datos, pipe := prepararLLM(t)
	modelo := levantarModelo(t, "config.env", 1)
	escribir(t, repo, ".codeguard/config.yaml", configConModelo("2026.08.2", modelo.URL))
	escribir(t, repo, "config.env", elSecreto)
	gitConEntorno(t, repo, datos, "add", "-A")

	arrancarDaemonConLLM(t, binDaemon, datos, pipe)
	salida, codigo := correrPorElPipe(t, bin, repo, datos, pipe)
	if codigo == 0 {
		t.Fatalf("el secreto NO bloqueó: este escenario no es el que se quería medir.\n%s", salida)
	}
	if !strings.Contains(salida, "NADA salió a la red") {
		t.Errorf("el bloqueo no le promete al usuario que nada salió a la red:\n%s", salida)
	}

	// Se le da tiempo de sobra a la sombra —que además duerme 2 s antes de
	// arrancar— para que, si fuera a llamar, llamara.
	time.Sleep(12 * time.Second)

	if n := modelo.veces(); n != 0 {
		t.Errorf("con un secreto en el diff hubo %d llamada(s) al proveedor.\n"+
			"El gancho le acaba de prometer al usuario que NADA salió a la red.\n%s",
			n, alrededorDe(modelo.todoLoEnviado(), "ghp_"))
	} else {
		t.Log("  ✓ ninguna llamada al proveedor: el secreto no salió de la máquina")
	}
}

// ── andamiaje ────────────────────────────────────────────────────────────

func prepararLLM(t *testing.T) (bin, binDaemon, repo, datos, pipe string) {
	t.Helper()
	if testing.Short() {
		t.Skip("levanta el daemon y un proveedor falso")
	}
	if runtime.GOOS != "windows" {
		t.Skip("CodeGuard sólo se distribuye para Windows")
	}
	bin = construirBinario(t)
	binDaemon = construirDaemon(t)
	repo = repoLimpio(t)
	datos = t.TempDir()
	// Un pipe por prueba Y POR PROCESO: si dos compartieran nombre, la segunda
	// hablaría con el daemon de la primera y mediría su configuración.
	//
	// Sólo con el nombre de la prueba faltaba la mitad, y costó una mañana: dos
	// CORRIDAS del mismo test caen en el mismo nombre, así que un daemon que
	// sobrevivió a una corrida anterior se quedaba con el pipe y todas las
	// siguientes hablaban con él. Se midió en esta máquina, con un huérfano de
	// las 23:36 que dejaba este test en rojo pasara lo que pasara. El PID es lo
	// que separa dos ejecuciones del mismo binario de pruebas.
	pipe = pipeDePrueba(t) + "-llm"
	return bin, binDaemon, repo, datos, pipe
}

// repoLimpio es un repo enrolado y sin violaciones: aquí se mide la capa LLM,
// no los motores deterministas.
func repoLimpio(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	for _, o := range [][]string{
		{"init", "-q"},
		{"config", "user.email", "e2e@ejemplo.local"},
		{"config", "user.name", "Verificación"},
		{"config", "commit.gpgsign", "false"},
	} {
		git(t, repo, o...)
	}
	escribir(t, repo, "LEEME.md", "repositorio de verificación de la capa LLM\n")
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-q", "-m", "base", "--no-verify")
	return repo
}

// arrancarDaemonConLLM levanta el daemon con la clave del proveedor falso en el
// entorno: sin ella, llm.New devuelve nil y la sombra se apaga en silencio.
func arrancarDaemonConLLM(t *testing.T, binDaemon, datos, pipe string) {
	t.Helper()
	entorno := append(entornoConPipe(t, datos, pipe), "CODEGUARD_PRUEBA_LLM=clave-de-prueba")
	arrancarDaemonCon(t, binDaemon, datos, pipe, entorno)
}

func correrPorElPipe(t *testing.T, bin, repo, datos, pipe string) (string, int) {
	t.Helper()
	c := exec.Command(bin, "hook", "pre-commit")
	c.Dir = repo
	c.Env = entornoConPipe(t, datos, pipe)
	out, err := c.CombinedOutput()
	codigo := 0
	if ee, ok := err.(*exec.ExitError); ok {
		codigo = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("no se pudo ejecutar el gancho: %v", err)
	}
	return string(out), codigo
}

// esperarHallazgosLLM espera a que la sombra registre lo que el modelo dijo, y
// FALLA si no llega.
//
// Sin hallazgos del modelo, comprobar que "ninguno bloquea" no demuestra nada:
// cero de cero siempre da cero. Es exactamente la trampa que este arnés existe
// para cazar, y la primera versión de esta prueba cayó en ella —salió verde
// anunciando que ningún hallazgo del modelo bloqueaba, cuando lo que pasaba es
// que no había ninguno.
func esperarHallazgosLLM(t *testing.T, datos string, limite time.Duration) {
	t.Helper()
	hasta := time.Now().Add(limite)
	for time.Now().Before(hasta) {
		if contarHallazgosLLM(t, datos) > 0 {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("la sombra no registró ningún hallazgo del modelo en %s, así que "+
		"comprobar que no bloquean no mediría nada.\n%s", limite, colaDelLog(t, datos))
}

func contarHallazgosLLM(t *testing.T, datos string) int {
	t.Helper()
	ruta := filepath.Join(datos, "codeguard", "codeguard.db")
	if _, err := os.Stat(ruta); err != nil {
		return 0
	}
	db := abrirBase(t, ruta)
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM findings WHERE source = 'llm'`).Scan(&n); err != nil {
		return 0
	}
	return n
}

func hallazgosLLMBloqueantes(t *testing.T, datos string) int {
	t.Helper()
	db := abrirBase(t, filepath.Join(datos, "codeguard", "codeguard.db"))
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM findings WHERE source = 'llm' AND blocking = 1`).Scan(&n); err != nil {
		t.Fatalf("no se pudieron contar los hallazgos del modelo: %v", err)
	}
	return n
}

// alrededorDe recorta el contexto de una aguja para que el mensaje de error
// enseñe la prueba sin volcar el prompt entero.
func alrededorDe(texto, aguja string) string {
	i := strings.Index(texto, aguja)
	if i < 0 {
		return "(no aparece)"
	}
	desde := max(0, i-60)
	hasta := min(len(texto), i+len(aguja)+60)
	return "…" + texto[desde:hasta] + "…"
}

// hayHallazgoLLMConMensaje dice si un hallazgo concreto del modelo llegó a la
// base.
func hayHallazgoLLMConMensaje(t *testing.T, datos, mensaje string) bool {
	t.Helper()
	db := abrirBase(t, filepath.Join(datos, "codeguard", "codeguard.db"))
	defer db.Close()
	var n int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM findings WHERE source = 'llm' AND message = ?`, mensaje).Scan(&n); err != nil {
		t.Fatalf("no se pudo buscar el hallazgo del modelo: %v", err)
	}
	return n > 0
}
