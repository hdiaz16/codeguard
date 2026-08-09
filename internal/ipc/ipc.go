// Package ipc implementa el contrato hook ↔ daemon de la sección 8:
// named pipe \\.\pipe\codeguard-<SID> con DACL de solo-usuario,
// JSON delimitado por líneas.
package ipc

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/user"
	"time"

	"github.com/Microsoft/go-winio"

	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
)

const ProtocolVersion = 1

type Request struct {
	ProtocolVersion int `json:"protocol_version"`
	// Command vacío = analizar (el caso normal). "open-graph" pide al daemon
	// que abra el explorador en SU ventana — nada de navegador.
	Command         string                `json:"command,omitempty"`
	RunID           string                `json:"run_id"`
	RepoRoot        string                `json:"repo_root"`
	RepoID          string                `json:"repo_id"`
	Branch          string                `json:"branch"`
	StagedFiles     []gitdiff.ChangedFile `json:"staged_files"`
	DiffUnified     string                `json:"diff_unified"`
	RulepackVersion string                `json:"rulepack_version"`
	ConfigHash      string                `json:"config_hash"`
	AIGenerated     bool                  `json:"ai_generated"`
	DeadlineMs      int                   `json:"deadline_ms"`
}

type Response struct {
	ProtocolVersion  int               `json:"protocol_version"`
	RunID            string            `json:"run_id"`
	Verdict          string            `json:"verdict"`
	BlockingFindings int               `json:"blocking_findings"`
	AdvisoryFindings int               `json:"advisory_findings"`
	CIParity         bool              `json:"ci_parity"`
	Suppressed       int               `json:"suppressed"` // deuda de baseline que no bloqueó
	Degraded         []string          `json:"degraded"`
	Findings         []finding.Finding `json:"findings"`
	ElapsedMs        int64             `json:"elapsed_ms"`
}

// PipeName devuelve \\.\pipe\codeguard-<SID del usuario actual>.
//
// CODEGUARD_PIPE lo sustituye entero. Existe porque el pipe es exclusivo: las
// pruebas necesitan el suyo para no chocar con un daemon real corriendo en la
// misma máquina, y sirve igual para correr una instancia aislada a mano.
func PipeName() (string, error) {
	if p := os.Getenv("CODEGUARD_PIPE"); p != "" {
		return p, nil
	}
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	return `\\.\pipe\codeguard-` + u.Uid, nil
}

// Listen abre el pipe con DACL que solo admite al usuario actual.
func Listen() (net.Listener, error) {
	name, err := PipeName()
	if err != nil {
		return nil, err
	}
	u, err := user.Current()
	if err != nil {
		return nil, err
	}
	return winio.ListenPipe(name, &winio.PipeConfig{
		SecurityDescriptor: fmt.Sprintf("D:P(A;;GA;;;%s)", u.Uid),
		InputBufferSize:    1 << 20,
		OutputBufferSize:   1 << 20,
	})
}

// Call conecta con el daemon, manda la petición y espera la respuesta.
// La conexión debe ser inmediata (el daemon está o no está: 2 s); la
// respuesta puede tardar hasta timeout + margen, porque el daemon corta
// sus motores antes del deadline y siempre alcanza a responder.
func Call(req *Request, timeout time.Duration) (*Response, error) {
	name, err := PipeName()
	if err != nil {
		return nil, err
	}
	dial := 2 * time.Second
	conn, err := winio.DialPipe(name, &dial)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout + 3*time.Second))

	req.ProtocolVersion = ProtocolVersion
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(append(payload, '\n')); err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	if !sc.Scan() {
		return nil, fmt.Errorf("el daemon no respondió: %v", sc.Err())
	}
	var resp Response
	if err := json.Unmarshal(sc.Bytes(), &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ReadRequest y WriteResponse son el lado servidor.
func ReadRequest(conn net.Conn) (*Request, error) {
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	if !sc.Scan() {
		return nil, fmt.Errorf("petición vacía: %v", sc.Err())
	}
	var req Request
	if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
		return nil, err
	}
	return &req, nil
}

func WriteResponse(conn net.Conn, resp *Response) error {
	resp.ProtocolVersion = ProtocolVersion
	payload, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	_, err = conn.Write(append(payload, '\n'))
	return err
}
