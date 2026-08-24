//go:build windows

package proc

import (
	"context"
	"errors"
	"os/exec"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func sondear(t *testing.T, ctx context.Context) (Salida, Contencion, bool, error) {
	t.Helper()
	ectx, rec := ConRecolector(ctx)
	c := exec.CommandContext(ectx, "cmd", "/c", "exit", "0")
	c.Env = Entorno()
	s, err := Correr(ectx, c, 1<<20)
	rep, hubo := rec.Resultado()
	return s, rep, hubo, err
}

// La máquina de desarrollo y el runner del CI pueden crear token y job: la
// sonda debe reportar la contención COMPLETA. Si este test falla en una
// máquina, esa máquina tiene el sandbox degradado de verdad — y eso es
// exactamente lo que el reporte existe para decir.
func TestCorrerReportaContencionCompleta(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, rep, hubo, err := sondear(t, ctx)
	if err != nil || !s.Arranco {
		t.Fatalf("la sonda no corrió: err=%v arranco=%v", err, s.Arranco)
	}
	if !hubo {
		t.Fatal("Correr no reportó al recolector: el fail-visible está muerto")
	}
	if !rep.Completa() {
		t.Fatalf("contención incompleta en esta máquina: faltan %v (%s)", rep.Degradadas(), rep.Detalle)
	}
}

// Sin token restringido el motor CORRE (defensa en profundidad, no frontera)
// y el hecho VIAJA — hasta 2026-08-23 solo quedaba una línea de log.
func TestFalloDeTokenSeReportaYElMotorCorre(t *testing.T) {
	original := crearTokenParaSandbox
	crearTokenParaSandbox = func() (windows.Token, error) {
		return 0, errors.New("inyectado: sin token")
	}
	t.Cleanup(func() { crearTokenParaSandbox = original })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, rep, hubo, err := sondear(t, ctx)
	if err != nil || !s.Arranco {
		t.Fatalf("el motor debía correr sin token: err=%v", err)
	}
	if !hubo || rep.TokenRestringido {
		t.Fatalf("el token caído debía reportarse: hubo=%v rep=%+v", hubo, rep)
	}
	if !rep.Job || !rep.MatarileArbol {
		t.Fatalf("el job no depende del token y debía activarse: %+v", rep)
	}
	if rep.Detalle == "" {
		t.Fatal("la faceta caída debe traer su porqué")
	}
}

// Sin job object el motor corre, pero se pierde el matarile del árbol por
// plazo (los nietos sobreviven) — el reporte lo dice con las DOS facetas.
func TestFalloDeJobSeReportaConSuMatarile(t *testing.T) {
	original := crearJobParaSandbox
	crearJobParaSandbox = func(_ *windows.SecurityAttributes, _ *uint16) (windows.Handle, error) {
		return 0, errors.New("inyectado: sin job")
	}
	t.Cleanup(func() { crearJobParaSandbox = original })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, rep, hubo, err := sondear(t, ctx)
	if err != nil || !s.Arranco {
		t.Fatalf("el motor debía correr sin job: err=%v", err)
	}
	if !hubo || rep.Job || rep.MatarileArbol {
		t.Fatalf("job y matarile-arbol debían reportarse caídos: hubo=%v rep=%+v", hubo, rep)
	}
	if !rep.TokenRestringido {
		t.Fatalf("el token no depende del job y debía activarse: %+v", rep)
	}
	// Sin job caen TRES facetas: las restricciones de interfaz viven EN el
	// job, así que se pierden con él.
	quiere := []string{"job", "matarile-arbol", "limites-ui"}
	got := rep.Degradadas()
	if len(got) != len(quiere) {
		t.Fatalf("Degradadas() = %v, esperaba %v", got, quiere)
	}
	for i := range quiere {
		if got[i] != quiere[i] {
			t.Fatalf("Degradadas() = %v, esperaba %v", got, quiere)
		}
	}
}

// El recolector guarda el PEOR caso entre hijos: una faceta cae si cayó en
// cualquiera.
func TestRecolectorPeorCaso(t *testing.T) {
	r := &Recolector{}
	if _, hubo := r.Resultado(); hubo {
		t.Fatal("sin anotar no debía haber resultado")
	}
	r.Anotar(Contencion{TokenRestringido: true, Job: true, MatarileArbol: true, LimitesUI: true})
	r.Anotar(Contencion{TokenRestringido: true, Job: false, MatarileArbol: false, LimitesUI: true, Detalle: "hijo 2 sin job"})
	c, hubo := r.Resultado()
	if !hubo || c.Job || c.MatarileArbol || !c.TokenRestringido || !c.LimitesUI {
		t.Fatalf("peor caso mal fusionado: %+v", c)
	}
	if c.Detalle != "hijo 2 sin job" {
		t.Fatalf("el detalle del primer caído debía conservarse: %q", c.Detalle)
	}
}

// Los 4 GB, los 64 procesos y las 8 restricciones de interfaz estuvieron años
// sin que nadie los midiera (hecho #6 del mapa W4): este test crea un job,
// lo configura con el MISMO código de producción y LEE de vuelta lo aplicado.
func TestConfigurarJobAplicaLoQueDice(t *testing.T) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(job) //nolint:errcheck

	uiOK, err := configurarJob(job)
	if err != nil {
		t.Fatal(err)
	}
	if !uiOK {
		t.Fatal("las restricciones de interfaz debían aplicarse en esta máquina")
	}

	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	if err := windows.QueryInformationJobObject(
		job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil,
	); err != nil {
		t.Fatal(err)
	}
	flags := info.BasicLimitInformation.LimitFlags
	for _, f := range []struct {
		bit    uint32
		nombre string
	}{
		{windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, "KILL_ON_JOB_CLOSE"},
		{windows.JOB_OBJECT_LIMIT_JOB_MEMORY, "JOB_MEMORY"},
		{windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS, "ACTIVE_PROCESS"},
	} {
		if flags&f.bit == 0 {
			t.Errorf("falta el límite %s en el job configurado", f.nombre)
		}
	}
	if info.BasicLimitInformation.ActiveProcessLimit != maxProcesos {
		t.Errorf("ActiveProcessLimit = %d, esperaba %d", info.BasicLimitInformation.ActiveProcessLimit, maxProcesos)
	}
	if info.JobMemoryLimit != maxMemoriaJob {
		t.Errorf("JobMemoryLimit = %d, esperaba %d", info.JobMemoryLimit, maxMemoriaJob)
	}

	var ui windows.JOBOBJECT_BASIC_UI_RESTRICTIONS
	if err := windows.QueryInformationJobObject(
		job, jobObjectBasicUIRestrictions,
		uintptr(unsafe.Pointer(&ui)), uint32(unsafe.Sizeof(ui)), nil,
	); err != nil {
		t.Fatal(err)
	}
	quiere := uint32(uilimitHandles | uilimitReadClipboard | uilimitWriteClipboard |
		uilimitSystemParameters | uilimitDisplaySettings | uilimitGlobalAtoms |
		uilimitDesktop | uilimitExitWindows)
	if ui.UIRestrictionsClass != quiere {
		t.Errorf("UIRestrictionsClass = %#x, esperaba %#x", ui.UIRestrictionsClass, quiere)
	}
}
