package identidad

import (
	"strings"
	"testing"
	"time"
)

func riesgo(art, cve, paq, ver string) Riesgo {
	return Riesgo{Artefacto: art, CVE: cve, Paquete: paq, Version: ver, Severidad: "HIGH"}
}

// Lo que de verdad protege este mecanismo: que una excepción no se pueda usar
// para apagar la compuerta. Sin firma no aplica, y punto — da igual lo bien
// redactado que esté el motivo.
func TestSinFirmaNoAplica(t *testing.T) {
	e := Excepcion{Artefacto: "gitleaks", Paquete: "x/crypto", Hasta: "2099-01-01"}
	if ok, porque := e.vigente(time.Now()); ok {
		t.Fatal("una excepción sin firmar está aplicando; eso es un bypass con buena letra")
	} else if porque == "" {
		t.Error("no dice por qué no aplica")
	}
}

func TestCaducaSola(t *testing.T) {
	e := Excepcion{Artefacto: "gitleaks", Paquete: "x/crypto",
		AceptadaPor: "alguien", Hasta: "2026-11-30"}
	if ok, _ := e.vigente(time.Date(2026, 11, 30, 23, 0, 0, 0, time.UTC)); !ok {
		t.Error("el día de la caducidad todavía debería valer entero")
	}
	if ok, porque := e.vigente(time.Date(2026, 12, 5, 0, 0, 0, 0, time.UTC)); ok {
		t.Error("una excepción caducada sigue aplicando")
	} else if porque == "" {
		t.Error("no dice que caducó")
	}
}

// Una excepción sin CVE ni paquete taparía el motor entero. Es el error que
// alguien con prisa cometería, y tiene que no funcionar.
func TestExcepcionVaciaNoTapaNada(t *testing.T) {
	e := Excepcion{Artefacto: "gitleaks", AceptadaPor: "alguien", Hasta: "2099-01-01"}
	if e.cubre(riesgo("gitleaks", "CVE-2026-1", "lo-que-sea", "v1")) {
		t.Fatal("una excepción sin CVE ni paquete está tapando el motor entero")
	}
}

func TestAcotaPorVersionYPorArtefacto(t *testing.T) {
	e := Excepcion{Artefacto: "gitleaks", Paquete: "golang.org/x/crypto", Version: "v0.35.0",
		AceptadaPor: "alguien", Hasta: "2099-01-01"}
	if !e.cubre(riesgo("gitleaks", "CVE-2026-1", "golang.org/x/crypto", "v0.35.0")) {
		t.Error("no cubre justo lo que se aceptó")
	}
	// Si el motor sube y arrastra otra versión de la dependencia, el riesgo es
	// otro y hay que volver a mirarlo.
	if e.cubre(riesgo("gitleaks", "CVE-2026-1", "golang.org/x/crypto", "v0.40.0")) {
		t.Error("la excepción se está estirando a una versión que nadie aceptó")
	}
	// Y no vale para otro motor aunque el CVE sea el mismo.
	if e.cubre(riesgo("trivy", "CVE-2026-1", "golang.org/x/crypto", "v0.35.0")) {
		t.Error("la excepción de un motor está cubriendo a otro")
	}
}

// El aviso que evita que el registro se pudra: una excepción que ya no cubre
// nada es una puerta abierta esperando a que algo vuelva a pasar por ella.
func TestAvisaDeLasQueYaNoSirven(t *testing.T) {
	original := excepcionesCargadas
	defer func() { excepcionesCargadas = original }()
	excepcionesCargadas = librosExcepciones{Excepciones: []Excepcion{
		{Artefacto: "gitleaks", Paquete: "ya-no-existe", AceptadaPor: "alguien", Hasta: "2099-01-01"},
		{Artefacto: "trivy", Paquete: "sin-firma", Hasta: "2099-01-01"},
	}}
	bloquean, aceptados, avisos := aplicarExcepciones(
		[]Riesgo{riesgo("trivy", "CVE-2026-9", "sin-firma", "v1")}, time.Now())

	if len(aceptados) != 0 {
		t.Error("aceptó algo sin firma")
	}
	if len(bloquean) != 1 {
		t.Errorf("el riesgo sin firmar debería seguir bloqueando, bloquean=%d", len(bloquean))
	}
	if len(avisos) != 2 {
		t.Errorf("esperaba avisar de las dos (una huérfana, otra sin firma), avisos=%v", avisos)
	}
}

// El archivo real que viaja embebido: si alguien añade una excepción, tiene que
// cumplir las reglas. Esta prueba lee el JSON de verdad, no uno de mentira.
func TestElRegistroRealEstaBienFormado(t *testing.T) {
	for _, e := range excepcionesCargadas.Excepciones {
		if e.Artefacto == "" {
			t.Error("hay una excepción sin artefacto")
		}
		if e.CVE == "" && e.Paquete == "" {
			t.Errorf("%s: sin CVE ni paquete, no cubriría nada (o lo cubriría todo)", e.Artefacto)
		}
		if e.Motivo == "" {
			t.Errorf("%s / %s: sin motivo — una excepción sin explicación no es una decisión, es un silencio",
				e.Artefacto, e.Objetivo())
		}
		if e.Hasta == "" {
			t.Errorf("%s / %s: sin fecha de caducidad", e.Artefacto, e.Objetivo())
		} else if _, err := time.Parse("2006-01-02", e.Hasta); err != nil {
			t.Errorf("%s / %s: fecha ilegible %q", e.Artefacto, e.Objetivo(), e.Hasta)
		}
	}
}

func TestValidacionDeFirmaRechazaExcepcionSinAceptadaPor(t *testing.T) {
	ahora, _ := time.Parse("2006-01-02", "2026-08-19")
	eSinFirma := Excepcion{
		Artefacto:   "trivy",
		Paquete:     "oras.land/oras-go/v2",
		Motivo:      "prueba",
		Hasta:       "2026-11-30",
		AceptadaPor: "",
	}
	ok, razon := eSinFirma.vigente(ahora)
	if ok || !strings.Contains(razon, "sin firmar") {
		t.Errorf("excepción sin firma no debe ser vigente, got ok=%v, razon=%q", ok, razon)
	}

	eConFirma := eSinFirma
	eConFirma.AceptadaPor = "seguridad@codeguard"
	ok, _ = eConFirma.vigente(ahora)
	if !ok {
		t.Errorf("excepción con firma y dentro de fecha debe ser vigente")
	}
}
