// Spike S4 — named pipes con go-winio.
// Criterio: 100 conexiones seriadas intercambiando JSON, sin fugas de handles.
// El pipe usa el SID del usuario actual en el nombre y una DACL que solo
// admite a ese usuario (ADR-12 / sección 8 de la spec).
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/user"
	"runtime"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

type request struct {
	ProtocolVersion int    `json:"protocol_version"`
	RunID           string `json:"run_id"`
	DiffUnified     string `json:"diff_unified"`
}

type response struct {
	ProtocolVersion int    `json:"protocol_version"`
	RunID           string `json:"run_id"`
	Verdict         string `json:"verdict"`
	ElapsedMs       int64  `json:"elapsed_ms"`
}

func pipeName() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	return `\\.\pipe\codeguard-` + u.Uid, nil
}

// DACL: acceso total solo para el usuario actual (D:P protege contra herencia).
func securityDescriptor() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("D:P(A;;GA;;;%s)", u.Uid), nil
}

func runServer(name string, ready chan<- struct{}, done <-chan struct{}) error {
	sd, err := securityDescriptor()
	if err != nil {
		return err
	}
	l, err := winio.ListenPipe(name, &winio.PipeConfig{
		SecurityDescriptor: sd,
		MessageMode:        false,
		InputBufferSize:    65536,
		OutputBufferSize:   65536,
	})
	if err != nil {
		return err
	}
	defer l.Close()
	close(ready)

	for {
		select {
		case <-done:
			return nil
		default:
		}
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-done:
				return nil
			default:
				return err
			}
		}
		go handle(conn)
	}
}

func handle(conn net.Conn) {
	defer conn.Close()
	start := time.Now()
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 65536), 1<<20)
	if !sc.Scan() {
		return
	}
	var req request
	if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
		return
	}
	resp := response{
		ProtocolVersion: 1,
		RunID:           req.RunID,
		Verdict:         "pass",
		ElapsedMs:       time.Since(start).Milliseconds(),
	}
	out, _ := json.Marshal(resp)
	conn.Write(append(out, '\n'))
}

var procGetProcessHandleCount = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetProcessHandleCount")

func handleCount() (uint32, error) {
	var count uint32
	h := windows.CurrentProcess()
	r, _, err := procGetProcessHandleCount.Call(uintptr(h), uintptr(unsafe.Pointer(&count)))
	if r == 0 {
		return 0, err
	}
	return count, nil
}

func main() {
	const iterations = 100

	name, err := pipeName()
	if err != nil {
		fmt.Println("FAIL: no se pudo obtener el SID:", err)
		os.Exit(1)
	}
	fmt.Println("pipe:", name)

	ready := make(chan struct{})
	done := make(chan struct{})
	serverErr := make(chan error, 1)
	go func() { serverErr <- runServer(name, ready, done) }()

	select {
	case <-ready:
	case err := <-serverErr:
		fmt.Println("FAIL: servidor no arrancó:", err)
		os.Exit(1)
	case <-time.After(5 * time.Second):
		fmt.Println("FAIL: timeout esperando al servidor")
		os.Exit(1)
	}

	// Calentar y medir handles base tras unas conexiones iniciales.
	for i := 0; i < 5; i++ {
		if err := oneConnection(name, i); err != nil {
			fmt.Println("FAIL en calentamiento:", err)
			os.Exit(1)
		}
	}
	base, err := handleCount()
	if err != nil {
		fmt.Println("WARN: no se pudo leer el conteo de handles:", err)
	}

	settle := func() uint32 {
		runtime.GC()
		time.Sleep(1 * time.Second)
		runtime.GC()
		c, _ := handleCount()
		return c
	}

	var totalLatency time.Duration
	round := func() {
		for i := 0; i < iterations; i++ {
			start := time.Now()
			if err := oneConnection(name, i); err != nil {
				fmt.Printf("FAIL en conexión %d: %v\n", i, err)
				os.Exit(1)
			}
			totalLatency += time.Since(start)
		}
	}

	round()
	after1 := settle()
	round()
	after2 := settle()

	close(done)
	// Conexión de desbloqueo para que Accept() salga.
	if c, err := winio.DialPipe(name, nil); err == nil {
		c.Close()
	}

	d1 := int64(after1) - int64(base)
	d2 := int64(after2) - int64(after1)
	fmt.Printf("conexiones: %d OK (2 rondas)\n", 2*iterations)
	fmt.Printf("latencia media por ida y vuelta: %v\n", totalLatency/(2*iterations))
	fmt.Printf("handles: base=%d ronda1=%d (%+d) ronda2=%d (%+d)\n", base, after1, d1, after2, d2)

	// Fuga real = crecimiento sostenido por ronda. Ruido de arranque = delta que no se repite.
	if d2 > 10 {
		fmt.Println("RESULTADO: FAIL — crecimiento sostenido de handles entre rondas")
		os.Exit(1)
	}
	fmt.Println("RESULTADO: PASS")
}

func oneConnection(name string, i int) error {
	timeout := 2 * time.Second
	conn, err := winio.DialPipe(name, &timeout)
	if err != nil {
		return err
	}
	defer conn.Close()

	req := request{
		ProtocolVersion: 1,
		RunID:           fmt.Sprintf("spike-%03d", i),
		DiffUnified:     "diff --git a/main.go b/main.go\n+// cambio de prueba\n",
	}
	out, _ := json.Marshal(req)
	if _, err := conn.Write(append(out, '\n')); err != nil {
		return err
	}
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 65536), 1<<20)
	if !sc.Scan() {
		return fmt.Errorf("sin respuesta: %v", sc.Err())
	}
	var resp response
	if err := json.Unmarshal(sc.Bytes(), &resp); err != nil {
		return err
	}
	if resp.RunID != req.RunID || resp.Verdict != "pass" {
		return fmt.Errorf("respuesta inesperada: %s", sc.Text())
	}
	return nil
}
