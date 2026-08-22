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
	"strings"
	"time"

	"github.com/Microsoft/go-winio"

	"codeguard/internal/capas"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
)

const ProtocolVersion = 1

type Request struct {
	ProtocolVersion int `json:"protocol_version"`
	// Command vacío = analizar (el caso normal). "open-graph" pide al daemon
	// que abra el explorador en SU ventana — nada de navegador.
	Command     string                `json:"command,omitempty"`
	RunID       string                `json:"run_id"`
	RepoRoot    string                `json:"repo_root"`
	RepoID      string                `json:"repo_id"`
	Branch      string                `json:"branch"`
	StagedFiles []gitdiff.ChangedFile `json:"staged_files"`
	DiffUnified string                `json:"diff_unified"`
	// DiffLines es el tamaño del cambio en líneas. Viaja porque el otro lado no
	// puede deducirlo: el daemon reconstruía el diff con Files y Unified y
	// Lines se quedaba en CERO, así que por la ruta del daemon —la de todos los
	// días— no existían ni el aviso de "cambio demasiado grande" (§P4) ni la
	// degradación a sólo-secretos por diff enorme, que sí existen sin daemon.
	// Dos comportamientos documentados apagados por un campo que no cruzaba.
	DiffLines int `json:"diff_lines"`
	// SecretosBloqueados: CUÁNTOS secretos frenaron este commit. Sólo viaja con
	// el comando "secreto-bloqueado".
	//
	// La etapa 1 corre dentro del proceso del gancho —es fail-closed y no puede
	// depender de que el daemon esté vivo— y salía por os.Exit antes de hablar
	// con nadie: el commit quedaba bloqueado y el orbe seguía en verde. Este
	// campo es lo único que hace falta para que la UI se entere.
	//
	// Es un NÚMERO y no los hallazgos, y eso es la regla dura de este camino: el
	// valor del secreto no puede salir por un canal nuevo, que sería justo lo
	// que el producto existe para impedir. El detalle ya está en la base, que el
	// gancho escribe antes de salir, y se lee en la pestaña Historial.
	SecretosBloqueados int `json:"secretos_bloqueados,omitempty"`
	// SecretosEn es DÓNDE está cada uno: "ruta/archivo.go:12". Sólo eso.
	//
	// Ni el valor, ni la línea de código, ni el mensaje del motor —que en
	// gitleaks puede venir de una regla del propio repo—. Con el archivo y la
	// línea, quien lo lee sabe adónde ir; con cualquier otra cosa, este canal
	// empezaría a transportar justo lo que el producto acaba de frenar.
	SecretosEn      []string `json:"secretos_en,omitempty"`
	RulepackVersion string   `json:"rulepack_version"`
	ConfigHash      string   `json:"config_hash"`
	AIGenerated     bool     `json:"ai_generated"`
	DeadlineMs      int      `json:"deadline_ms"`
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
	// Capas dice, motor por motor, si miró y con qué resultado. Degraded sólo
	// nombra a los que fallaron, así que sin esto la UI no puede distinguir
	// "revisó y está limpio" de "no revisó". Ver internal/capas.
	Capas []capas.Capa `json:"capas,omitempty"`
	// ParityReason explica en una línea POR QUÉ se rompió la paridad. El aviso
	// sin motivo ("no puedo garantizar que pase el CI") es de los que se
	// aprenden a ignorar: nadie puede arreglar lo que no se nombra.
	ParityReason string `json:"parity_reason,omitempty"`
	// Reason explica POR QUÉ no se analizó, cuando Verdict es "skipped".
	//
	// Sin este campo el motivo no cruzaba: el pipeline lo calcula ("todos los
	// archivos tocados están excluidos", "merge o revert"), el camino de CI lo
	// imprime, y por el pipe se perdía. El hook podía decir que no se revisó
	// nada, pero no por qué — y un veredicto sin motivo es de los que el dev
	// aprende a ignorar, igual que pasaba con ParityReason.
	//
	// Es aditivo y opcional a propósito, para no romper una actualización a
	// medias: encoding/json ignora los campos que no conoce, así que una CLI
	// vieja contra un daemon nuevo lo descarta sin enterarse, y una CLI nueva
	// contra un daemon viejo lo recibe vacío y lo trata como "no llegó". Por eso
	// tampoco sube ProtocolVersion: el formato no cambia para quien no lo mira,
	// y con omitempty los bytes son idénticos cuando va vacío.
	Reason string `json:"reason,omitempty"`
}

// ── La huella cruza el pipe ──────────────────────────────────────────────
//
// finding.Finding marca Fingerprint y LineContent como json:"-" para que no
// ensucien el informe. El pipe usa el MISMO struct, así que por aquí los dos
// campos se caían: el daemon calculaba la huella en su proceso, la mandaba, y
// al otro lado llegaba vacía. El gancho guardaba entonces en la base hallazgos
// SIN HUELLA — y por la ruta del daemon pasa el commit de todos los días.
//
// No rompía la baseline (el daemon aplica las supresiones antes de responder),
// pero sí lo que se GRABA: la huella es lo único que identifica un hallazgo
// entre corridas, y es la columna que `codeguard sync` empuja al central y de
// la que depende la calibración. Meses de datos sin la clave que los une.
//
// Se arregla aquí y no cambiando el tag de finding.Finding: el informe y el
// SARIF no tienen por qué llevar el contenido de la línea señalada, y ese tag
// es de ellos. Lo que viaja por el pipe es asunto del pipe.
//
// Compatible en las dos direcciones: un daemon viejo no manda "fp" y el gancho
// nuevo lo recibe vacío —exactamente lo de hoy—, y un gancho viejo ignora el
// campo que no conoce.
type hallazgoEnCable struct {
	finding.Finding
	Fingerprint string `json:"fp"`
	LineContent string `json:"linea,omitempty"`
}

// respuestaPlana evita la recursión infinita: Marshal sobre Response llamaría a
// MarshalJSON otra vez.
type respuestaPlana Response

// sobre lleva los campos de Response con Findings sustituido. El Findings de
// fuera gana al de dentro por profundidad, que es como encoding/json resuelve
// el choque de nombres.
type sobre struct {
	respuestaPlana
	Findings []hallazgoEnCable `json:"findings"`
}

func (r Response) MarshalJSON() ([]byte, error) {
	s := sobre{respuestaPlana: respuestaPlana(r)}
	for _, f := range r.Findings {
		s.Findings = append(s.Findings, hallazgoEnCable{
			Finding:     f,
			Fingerprint: f.Fingerprint,
			LineContent: f.LineContent,
		})
	}
	return json.Marshal(s)
}

func (r *Response) UnmarshalJSON(b []byte) error {
	var s sobre
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	*r = Response(s.respuestaPlana)
	r.Findings = nil
	for _, h := range s.Findings {
		f := h.Finding
		f.Fingerprint = h.Fingerprint
		f.LineContent = h.LineContent
		r.Findings = append(r.Findings, f)
	}
	return nil
}

// PipeName devuelve \\.\pipe\codeguard-<SID del usuario actual>.
//
// CODEGUARD_PIPE lo sustituye entero. Existe porque el pipe es exclusivo: las
// pruebas necesitan el suyo para no chocar con un daemon real corriendo en la
// misma máquina, y sirve igual para correr una instancia aislada a mano.
func PipeName() (string, error) {
	if p := os.Getenv("CODEGUARD_PIPE"); p != "" {
		if !strings.HasPrefix(p, `\\.\pipe\`) {
			p = `\\.\pipe\` + p
		}
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
func Call(req *Request, timeout time.Duration) (*Response, error) {
	name, err := PipeName()
	if err != nil {
		return nil, err
	}
	var conn net.Conn
	limite := time.Now().Add(2 * time.Second)
	for {
		dial := 500 * time.Millisecond
		conn, err = winio.DialPipe(name, &dial)
		if err == nil {
			break
		}
		if time.Now().After(limite) {
			return nil, err
		}
		time.Sleep(50 * time.Millisecond)
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
	// La DACL admite a cualquier proceso del mismo usuario, y basta con que uno
	// conecte y no mande nada para dejar colgada en Scan a la goroutine que lo
	// atiende: repetido, es fuga de goroutines y un daemon inservible justo
	// cuando hace falta, antes de un commit. Acota SOLO la lectura de la
	// petición; la respuesta puede tardar lo que tarde el análisis.
	if err := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return nil, fmt.Errorf("no se pudo acotar la lectura de la petición: %w", err)
	}
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
	// La escritura también se puede colgar: si el hook murió a media espera
	// (un Ctrl-C) y el búfer del pipe se llena, este Write bloquea para siempre
	// y la goroutine que atiende la conexión se fuga — en un daemon que vive
	// días y acepta en bucle, esas fugas se acumulan. Va aquí y no en el
	// llamador para cubrir por igual la respuesta del análisis y el ack de los
	// comandos. La respuesta es un JSON pequeño: diez segundos son de sobra.
	if err := conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return fmt.Errorf("no se pudo acotar la escritura de la respuesta: %w", err)
	}
	_, err = conn.Write(append(payload, '\n'))
	return err
}
