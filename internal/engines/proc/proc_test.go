package proc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestAcotadoRecortaYNoFalla(t *testing.T) {
	a := &acotado{tope: 10}
	// Escribir de más nunca debe devolver error ni un n corto: eso cerraría el
	// pipe y mataría al motor a media escritura.
	n, err := a.Write(bytes.Repeat([]byte("x"), 4))
	if n != 4 || err != nil {
		t.Fatalf("primera escritura: n=%d err=%v", n, err)
	}
	n, err = a.Write(bytes.Repeat([]byte("y"), 20))
	if n != 20 || err != nil {
		t.Fatalf("escritura que rebasa: n=%d err=%v", n, err)
	}
	if !a.recortada {
		t.Error("debió marcarse como recortada")
	}
	if got := a.buf.Len(); got != 10 {
		t.Errorf("guardó %d bytes, el tope era 10", got)
	}
	if got := a.buf.String(); got != "xxxxyyyyyy" {
		t.Errorf("conservó %q, se esperaba el prefijo exacto", got)
	}
	// Ya lleno: sigue aceptando sin crecer.
	if _, err := a.Write([]byte("zzz")); err != nil || a.buf.Len() != 10 {
		t.Errorf("escritura con el buffer lleno: len=%d err=%v", a.buf.Len(), err)
	}
}

func TestAcotadoBajoElTopeNoMarca(t *testing.T) {
	a := &acotado{tope: 100}
	a.Write([]byte("hola"))
	if a.recortada {
		t.Error("no debió marcarse recortada por debajo del tope")
	}
	if a.buf.String() != "hola" {
		t.Errorf("conservó %q", a.buf.String())
	}
}

func TestCorrerAcotaSalidaReal(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("la prueba usa cmd.exe")
	}
	// ~80 KB de salida contra un tope de 1 KB.
	cmd := exec.Command("cmd", "/c",
		"for /L %i in (1,1,2000) do @echo "+strings.Repeat("a", 40))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	salida, err := Correr(ctx, cmd, 1024)
	if err == nil {
		t.Error("recortar debe reportarse como error para que el motor no parsee JSON incompleto")
	}
	// El motor tiene que poder reconocer ESTE fallo concreto para tolerarlo sin
	// tolerar de paso un plazo agotado: por identidad, no por la bandera.
	if !errors.Is(err, ErrRecortada) {
		t.Errorf("el error fue %v; un recorte limpio debe envolver ErrRecortada", err)
	}
	if !salida.Recortada {
		t.Fatal("no marcó la salida como recortada")
	}
	if got := len(salida.Stdout); got > 1024 {
		t.Errorf("guardó %d bytes pese al tope de 1024", got)
	}
}

// El recorte no puede tapar al plazo agotado. Cuando el motor escupe de más Y
// además lo matan por tiempo, la bandera Recortada vale true igual que en un
// recorte limpio; la diferencia sólo está en el error, y el que llama la usa
// para decidir si tolera la salida parcial o aborta.
func TestCorrerNoDisfrazaElPlazoDeRecorte(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("la prueba usa cmd.exe")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "cmd", "/c",
		"echo "+strings.Repeat("a", 40)+" & waitfor /t 10 nadie")
	salida, err := Correr(ctx, cmd, 16)

	if !salida.Recortada {
		t.Fatal("no marcó la salida como recortada: la prueba no está midiendo el cruce que dice medir")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("el error fue %v; el plazo agotado es la causa y tiene que viajar entero", err)
	}
	if errors.Is(err, ErrRecortada) {
		t.Error("un proceso muerto por plazo se está reportando como recorte tolerable")
	}
}

func TestCorrerDevuelveSalidaCompletaCuandoCabe(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("la prueba usa cmd.exe")
	}
	cmd := exec.Command("cmd", "/c", "echo codeguard")
	salida, err := Correr(context.Background(), cmd, MaxSalida)
	if err != nil {
		t.Fatalf("comando trivial falló: %v", err)
	}
	if salida.Recortada {
		t.Error("no debió recortar una salida de 10 bytes")
	}
	if !strings.Contains(string(salida.Stdout), "codeguard") {
		t.Errorf("stdout fue %q", salida.Stdout)
	}
}

// Regresión: un motor que engendra un nieto (Semgrep y Trivy lo hacen) dejaba
// colgado al que llama durante toda la vida del nieto —medido: 2 minutos con
// un plazo de 1.5 s—, porque Wait espera a que se cierren los pipes y el nieto
// los había heredado. El job object debe matar el árbol al vencer el plazo,
// no al terminar Wait.
func TestCorrerMataElArbolYNoSeCuelga(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("la prueba usa cmd.exe")
	}
	vivos := func() int {
		out, _ := exec.Command("powershell", "-NoProfile", "-Command",
			"(Get-Process waitfor -ErrorAction SilentlyContinue | Measure-Object).Count").Output()
		n := 0
		fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &n)
		return n
	}
	if vivos() != 0 {
		t.Skip("ya había procesos waitfor de otra cosa; la prueba sería ambigua")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()

	inicio := time.Now()
	cmd := exec.CommandContext(ctx, "cmd", "/c", "start /b waitfor /t 120 nadie & waitfor /t 120 nadie")
	Correr(ctx, cmd, MaxSalida)

	if d := time.Since(inicio); d > 8*time.Second {
		t.Errorf("Correr tardó %v: se quedó esperando al nieto", d)
	}
	time.Sleep(700 * time.Millisecond) // que Windows procese las muertes
	if n := vivos(); n != 0 {
		t.Errorf("quedaron %d procesos huérfanos", n)
	}
}

// El plazo vencido debe matar al proceso, no colgar al que llama.
func TestCorrerRespetaElPlazo(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("la prueba usa cmd.exe")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	inicio := time.Now()
	cmd := exec.CommandContext(ctx, "cmd", "/c", "timeout /t 30 /nobreak")
	if _, err := Correr(ctx, cmd, MaxSalida); err == nil {
		t.Error("un proceso cortado por plazo debe devolver error")
	}
	if d := time.Since(inicio); d > 5*time.Second {
		t.Errorf("tardó %v: el plazo no cortó el proceso", d)
	}
}
