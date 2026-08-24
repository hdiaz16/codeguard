package ipc

import (
	"net"
	"strings"
	"testing"
	"time"

	"codeguard/internal/finding"
)

// pipePropio da a cada prueba su pipe: el de producción es exclusivo y en la
// máquina de desarrollo suele estar ocupado por el daemon real.
func pipePropio(t *testing.T) {
	t.Helper()
	limpio := strings.NewReplacer("/", "-", "\\", "-", " ", "-").Replace(t.Name())
	t.Setenv("CODEGUARD_PIPE", `\\.\pipe\codeguard-test-`+limpio)
}

// El contrato hook↔daemon completo, por el pipe de verdad: el hook manda una
// petición y recibe la respuesta con la versión de protocolo estampada.
// Si esto se rompe, ningún commit se analiza — y hasta hoy no tenía prueba.
func TestIdaYVueltaPorElPipe(t *testing.T) {
	pipePropio(t)
	l, err := Listen()
	if err != nil {
		t.Fatalf("no se pudo abrir el pipe: %v", err)
	}
	defer l.Close()

	// El daemon de mentira: lee una petición, contesta con eco del RunID.
	errs := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			errs <- err
			return
		}
		defer conn.Close()
		req, err := ReadRequest(conn)
		if err != nil {
			errs <- err
			return
		}
		errs <- WriteResponse(conn, &Response{
			RunID:            req.RunID,
			Verdict:          "block",
			BlockingFindings: 1,
			Degraded:         []string{},
			Findings: []finding.Finding{{
				Engine: "prueba", RuleKey: "regla-x", File: "a.go", Line: 3,
				Message: "algo con acentos: migración bloqueada", Blocking: true,
			}},
		})
	}()

	resp, err := Call(&Request{
		RunID:    "01TEST",
		RepoRoot: "C:/tmp/repo",
		Branch:   "master",
	}, 5*time.Second)
	if err != nil {
		t.Fatalf("Call falló: %v", err)
	}
	if err := <-errs; err != nil {
		t.Fatalf("lado servidor: %v", err)
	}

	if resp.RunID != "01TEST" {
		t.Errorf("el RunID no viajó de vuelta: %q", resp.RunID)
	}
	if resp.Verdict != "block" || resp.BlockingFindings != 1 {
		t.Errorf("veredicto corrupto: %+v", resp)
	}
	if resp.ProtocolVersion != ProtocolVersion {
		t.Errorf("WriteResponse debe estampar la versión: %d", resp.ProtocolVersion)
	}
	if len(resp.Findings) != 1 || !strings.Contains(resp.Findings[0].Message, "migración") {
		t.Errorf("el hallazgo llegó corrupto (¿UTF-8?): %+v", resp.Findings)
	}
}

// La versión del protocolo la pone Call, no quien lo llama: un hook viejo y
// un daemon nuevo tienen que poder detectarse.
func TestCallEstampaLaVersionDelProtocolo(t *testing.T) {
	pipePropio(t)
	l, err := Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	visto := make(chan int, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if req, err := ReadRequest(conn); err == nil {
			visto <- req.ProtocolVersion
			WriteResponse(conn, &Response{RunID: req.RunID, Verdict: "pass"})
		}
	}()

	if _, err := Call(&Request{RunID: "01V"}, 3*time.Second); err != nil {
		t.Fatal(err)
	}
	if v := <-visto; v != ProtocolVersion {
		t.Errorf("llegó versión %d, se esperaba %d", v, ProtocolVersion)
	}
}

// P4: sin daemon, el hook debe fallar RÁPIDO y dejar pasar el commit, no
// colgarse. El presupuesto de conexión es 2 s. Con el pipe propio de la
// prueba, "sin daemon" está garantizado: nadie escucha ahí.
func TestSinDaemonFallaRapido(t *testing.T) {
	pipePropio(t)
	inicio := time.Now()
	_, err := Call(&Request{RunID: "01X"}, 5*time.Second)
	if err == nil {
		t.Fatal("no hay nadie escuchando en este pipe: Call debió fallar")
	}
	if d := time.Since(inicio); d > 4*time.Second {
		t.Errorf("tardó %v en rendirse; el commit del dev estaría colgado", d)
	}
}

// Un diff grande (~2 MB) tiene que caber: los buffers del scanner están en
// 16 MB justo porque un commit gordo real reventaba el límite por defecto
// de bufio (64 KB).
func TestUnaPeticionGrandeNoSeTrunca(t *testing.T) {
	pipePropio(t)
	l, err := Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	tam := make(chan int, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if req, err := ReadRequest(conn); err == nil {
			tam <- len(req.DiffUnified)
			WriteResponse(conn, &Response{RunID: req.RunID, Verdict: "pass"})
		} else {
			tam <- -1
		}
	}()

	diff := strings.Repeat("+línea añadida con texto suficiente para abultar\n", 40_000) // ~2 MB
	if _, err := Call(&Request{RunID: "01G", DiffUnified: diff}, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if got := <-tam; got != len(diff) {
		t.Errorf("el diff llegó truncado: %d de %d bytes", got, len(diff))
	}
}

func TestPipeNameLlevaElSIDDelUsuario(t *testing.T) {
	// Aquí se prueba el nombre REAL, así que el override se vacía.
	t.Setenv("CODEGUARD_PIPE", "")
	name, err := PipeName()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(name, `\\.\pipe\codeguard-`) {
		t.Errorf("nombre inesperado: %q", name)
	}
	// El sufijo es el SID: sin él, dos usuarios de la misma máquina
	// compartirían pipe y el DACL no tendría sentido.
	if strings.TrimPrefix(name, `\\.\pipe\codeguard-`) == "" {
		t.Error("el pipe no lleva el SID del usuario")
	}
}

// El listener es exclusivo: dos daemons a la vez deben ser imposibles.
func TestElPipeEsExclusivo(t *testing.T) {
	pipePropio(t)
	l, err := Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if l2, err := Listen(); err == nil {
		l2.Close()
		t.Error("un segundo Listen debió fallar: dos daemons compartirían las peticiones")
	}
}

func TestListenImplementaNetListener(t *testing.T) {
	pipePropio(t)
	l, err := Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, ok := any(l).(net.Listener); !ok {
		t.Fatal("Listen() debe retornar una instancia válida de net.Listener")
	}
	if l.Addr() == nil {
		t.Fatal("l.Addr() no debe ser nil")
	}
}
