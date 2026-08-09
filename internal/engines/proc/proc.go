// Package proc ejecuta los motores externos con dos garantías que os/exec no
// da por sí solo:
//
//  1. La salida está acotada. Un motor que escupe cientos de megabytes —un
//     Semgrep sobre un monorepo, un Trivy con miles de vulnerabilidades— no
//     puede tumbar al daemon llenando la memoria.
//  2. Los procesos nietos mueren con el padre. exec.CommandContext mata al
//     hijo directo al vencer el plazo, pero en Windows sus hijos quedan
//     huérfanos corriendo indefinidamente.
package proc

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"sync"
	"time"
)

// MaxSalida es el tope por flujo (stdout y stderr por separado). 64 MB es
// órdenes de magnitud más de lo que produce cualquier motor en un repo sano,
// así que recortar aquí sólo pasa cuando algo ya salió mal.
const MaxSalida = 64 << 20

// Salida es lo que produjo el motor, ya acotado.
type Salida struct {
	Stdout    []byte
	Stderr    []byte
	Recortada bool // se alcanzó el tope; la salida está incompleta
}

// Combinada devuelve stdout seguido de stderr, para los motores que sólo
// usan la salida como texto de diagnóstico.
func (s Salida) Combinada() []byte {
	if len(s.Stderr) == 0 {
		return s.Stdout
	}
	return append(append([]byte{}, s.Stdout...), s.Stderr...)
}

// Correr ejecuta c y devuelve su salida acotada. El comando lo arma quien
// llama (binario, argumentos, Dir, Env); Stdout y Stderr los pone Correr y
// se sobrescriben si venían puestos.
//
// El error devuelto es el de exec.Cmd.Wait: un código de salida distinto de
// cero llega como *exec.ExitError, que varios motores usan como señal legítima
// (Semgrep sale con 1 cuando encuentra algo). Distinguirlos es del que llama.
func Correr(ctx context.Context, c *exec.Cmd, tope int64) (Salida, error) {
	if tope <= 0 {
		tope = MaxSalida
	}
	so, se := &acotado{tope: tope}, &acotado{tope: tope}
	c.Stdout, c.Stderr = so, se
	// Con Stdout/Stderr distintos de *os.File, os/exec arma pipes y Wait no
	// vuelve hasta que se cierren TODOS sus extremos de escritura —incluidos
	// los que heredó un nieto. Sin este plazo, un motor cortado por timeout
	// dejaba colgado al que llama por todo lo que durara el nieto (medido:
	// 2 minutos con un plazo de 1.5 s).
	if c.WaitDelay == 0 {
		c.WaitDelay = 3 * time.Second
	}

	if err := c.Start(); err != nil {
		return Salida{}, err
	}
	// Si el contenedor falla no abortamos: perder el aislamiento del árbol de
	// procesos es peor que nada, pero no correr el motor es peor todavía.
	if cerrar, err := contener(c); err == nil {
		var una sync.Once
		matar := func() { una.Do(cerrar) }
		defer matar()

		// Matar el árbol en cuanto vence el plazo, sin esperar a Wait: cerrar
		// el job libera los pipes y es lo que desatasca a Wait.
		listo := make(chan struct{})
		defer close(listo)
		go func() {
			select {
			case <-ctx.Done():
				matar()
			case <-listo:
			}
		}()
	}

	err := c.Wait()
	s := Salida{Stdout: so.buf.Bytes(), Stderr: se.buf.Bytes(), Recortada: so.recortada || se.recortada}
	if s.Recortada && err == nil {
		err = fmt.Errorf("la salida superó el tope de %d MB y se recortó", tope>>20)
	}
	return s, err
}

// acotado acumula hasta tope bytes y descarta el resto en silencio.
//
// Devolver un error al pasarse cerraría el pipe y el motor moriría con
// EPIPE a media escritura, perdiendo también lo que ya habíamos leído. Es
// preferible quedarnos con el prefijo —normalmente suficiente para saber qué
// pasó— y marcarlo como recortado.
type acotado struct {
	tope      int64
	n         int64
	buf       bytes.Buffer
	recortada bool
}

func (a *acotado) Write(p []byte) (int, error) {
	espacio := a.tope - a.n
	switch {
	case espacio <= 0:
		a.recortada = true
	case int64(len(p)) > espacio:
		a.buf.Write(p[:espacio])
		a.n = a.tope
		a.recortada = true
	default:
		a.buf.Write(p)
		a.n += int64(len(p))
	}
	return len(p), nil // siempre "éxito": ver comentario del tipo
}
