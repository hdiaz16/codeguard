package linters

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"
)

// topeChico baja el tope de salida de runTool durante una prueba, para poder
// provocar un recorte sin generar 64 MB.
//
// Muta topeSalida, que es estado global del paquete, así que NINGUNA prueba que
// llame aquí puede usar t.Parallel(): dos en paralelo se pisarían el tope y una
// correría runTool con el de la otra, con recortes fantasma imposibles de
// atribuir. Hoy ninguna lo hace, y no se pone candado porque un candado que
// nadie contiende no impide que la próxima añada t.Parallel sin tomarlo: el
// cierre real es que runTool reciba el tope por parámetro, y eso vive en exec.go.
func topeChico(t *testing.T, n int64) {
	t.Helper()
	previo := topeSalida
	topeSalida = n
	t.Cleanup(func() { topeSalida = previo })
}

// Un análisis abortado no puede parecerse a un análisis exitoso.
//
// Cuando vence el plazo con la salida ya recortada pasan las dos cosas a la
// vez: proc.Correr devuelve Recortada==true Y el error del plazo. runTool
// toleraba el recorte mirando la bandera Salida.Recortada —el ESTADO de la
// salida— en vez de la IDENTIDAD del error, así que en ese cruce se tragaba el
// plazo agotado y devolvía la salida PARCIAL con err nil.
//
// Lo que se pierde ahí no es un mensaje: govet.go cachea los hallazgos bajo la
// clave de contenido, así que el análisis a medias queda congelado y se sirve
// en las corridas siguientes; y pipeline.go distingue "degradado" de "error"
// con errors.Is(err, context.DeadlineExceeded), señal que sólo viaja si el
// error llega entero.
func TestRunToolPropagaTimeoutAunqueRecorte(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("la prueba usa cmd.exe")
	}
	// Tope diminuto: basta el primer echo para marcar el recorte, sin depender
	// de cuánto alcanza a escribir el proceso antes de que lo maten.
	topeChico(t, 16)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	inicio := time.Now()
	// Escupe de inmediato más de lo que cabe y se queda colgado: el plazo lo
	// corta con la salida ya recortada.
	out, err := runTool(ctx, t.TempDir(), "cmd", "/c",
		"echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa & waitfor /t 10 nadie")

	if d := time.Since(inicio); d > 8*time.Second {
		t.Fatalf("runTool tardó %v: el plazo no cortó el proceso", d)
	}
	if err == nil {
		t.Fatalf("runTool devolvió err nil con salida %q: un plazo agotado se está reportando como análisis exitoso", out)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("el error fue %v; tiene que envolver context.DeadlineExceeded para que el pipeline lo clasifique como degradado y no como error", err)
	}
}

// El caso que la cláusula original SÍ quería tolerar: la salida no cupo pero el
// proceso terminó bien. Un texto recortado se sigue leyendo línea por línea, así
// que vale más que nada.
func TestRunToolToleraRecortePuro(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("la prueba usa cmd.exe")
	}
	topeChico(t, 16)

	out, err := runTool(context.Background(), t.TempDir(), "cmd", "/c",
		"echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatalf("un recorte con salida limpia no es un fallo: %v", err)
	}
	if len(out) == 0 {
		t.Error("se tiró la salida parcial, que era lo único que había")
	}
	if int64(len(out)) > 16 {
		t.Errorf("devolvió %d bytes pese al tope de 16", len(out))
	}
}

// La otra mitad del contrato: el exit != 0 se tolera PORQUE hay salida que
// leer. Sin un byte no hay análisis — devolver ("", nil) es el mismo verde
// silencioso que runToolConSalida nació para cerrar, por otra puerta. Este
// cruce (ExitError + 0 bytes) vivió prometido en el comentario de runTool y
// sin comprobar en su cuerpo.
func TestRunToolExitSinSalidaEsAveria(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("la prueba usa cmd.exe")
	}
	out, err := runTool(context.Background(), t.TempDir(), "cmd", "/c", "exit /b 3")
	if err == nil {
		t.Fatalf("runTool devolvió err nil con salida %q: un exit 3 mudo se está reportando como análisis limpio", out)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("el error fue %v; una avería de ejecución no debe disfrazarse de plazo vencido", err)
	}
	if !strings.Contains(err.Error(), "3") {
		t.Errorf("el error %q no dice el código de salida; el diagnóstico debe viajar entero", err)
	}
}

// Un código de salida distinto de cero es la forma NORMAL de decir "encontré
// problemas" en un linter; la respuesta está en la salida, no en el código.
func TestRunToolToleraExitCodeConSalida(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("la prueba usa cmd.exe")
	}
	out, err := runTool(context.Background(), t.TempDir(), "cmd", "/c",
		"echo hallazgo & exit /b 3")
	if err != nil {
		t.Fatalf("un exit code != 0 con salida no es un fallo de ejecución: %v", err)
	}
	if !strings.Contains(out, "hallazgo") {
		t.Errorf("la salida fue %q, se esperaba el texto del linter", out)
	}
}
