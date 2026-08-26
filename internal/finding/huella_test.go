package finding

import (
	"strings"
	"testing"
	"time"
)

// La aceptación medible del consejo (turnos 83-84) para huellas v2. El caso
// que gobierna todo es #9, medido en producción: cuatro usos idénticos de
// esc() en main.js colapsaban en UNA huella v1 y baselinear uno suprimía los
// futuros del mismo texto.

// archivoDePrueba simula el contenido analizado: cuatro líneas idénticas con
// vecinas DISTINTAS (contexto real de main.js: cada esc() vive entre líneas
// diferentes).
var contenidoConCuatroEsc = []string{
	"const a = leer();",           // 1
	"el.innerHTML = esc(a);",      // 2  ← ocurrencia 1
	"const b = leer();",           // 3
	"el.innerHTML = esc(a);",      // 4  ← ocurrencia 2
	"const c = leer();",           // 5
	"el.innerHTML = esc(a);",      // 6  ← ocurrencia 3
	"render(c);",                  // 7
	"el.innerHTML = esc(a);",      // 8  ← ocurrencia 4
	"export default { a, b, c };", // 9
}

func hallazgoEn(linea int) Finding {
	return Finding{
		Engine: "semgrep", RuleKey: "ts-innerhtml-var", File: "sitio/src/js/main.js",
		Line: linea, LineContent: "el.innerHTML = esc(a);",
	}
}

func fuenteFija(lineas []string) FuenteDeLineas {
	return func(string) []string { return lineas }
}

func TestLosCuatroEscDeMainJSYaNoColapsan(t *testing.T) {
	fs := []Finding{hallazgoEn(2), hallazgoEn(4), hallazgoEn(6), hallazgoEn(8)}
	AsignarHuellas(fs, fuenteFija(contenidoConCuatroEsc))

	vistas := map[string]bool{}
	for _, f := range fs {
		if f.HuellaAmbigua {
			t.Errorf("línea %d marcada ambigua: sus vecinas son distintas y deben distinguirla", f.Line)
		}
		if vistas[f.Fingerprint] {
			t.Errorf("la huella de la línea %d colapsó con otra ocurrencia — #9 sigue vivo", f.Line)
		}
		vistas[f.Fingerprint] = true
		if v, ok := ParseHuella(f.Fingerprint); !ok || v != 2 {
			t.Errorf("huella emitida ilegible o sin versión: %q", f.Fingerprint)
		}
	}
	// Y las CUATRO comparten la misma legacy v1 — que es exactamente el
	// colapso viejo, conservado como alias para que la baseline v1 siga
	// suprimiendo durante la ventana.
	for _, f := range fs[1:] {
		if f.LegacyFingerprint != fs[0].LegacyFingerprint {
			t.Error("la legacy v1 debe reproducir el algoritmo viejo, colapso incluido")
		}
	}
}

// Desplazamiento puro: el archivo gana líneas ARRIBA, todo lo demás igual.
// La identidad sobrevive — es la feature que protege baselines y la razón de
// que la línea no entre al hash (ni el ancla dependa de números).
func TestUnDesplazamientoPuroConservaLaIdentidad(t *testing.T) {
	fs := []Finding{hallazgoEn(2)}
	AsignarHuellas(fs, fuenteFija(contenidoConCuatroEsc))
	antes := fs[0].Fingerprint

	desplazado := append([]string{"// licencia", "// tres líneas nuevas", ""}, contenidoConCuatroEsc...)
	fs2 := []Finding{hallazgoEn(5)} // la misma ocurrencia, 3 líneas más abajo
	AsignarHuellas(fs2, fuenteFija(desplazado))

	if fs2[0].Fingerprint != antes {
		t.Errorf("el desplazamiento cambió la huella: %s → %s — las baselines no sobrevivirían a un import nuevo",
			huellaCorta(antes, 12), huellaCorta(fs2[0].Fingerprint, 12))
	}
}

// El veto del turno 83, fijado: borrar la ocurrencia aceptada y escribir una
// NUEVA en otro contexto no hereda ninguna identidad — la nueva bloquea.
func TestUnaOcurrenciaNuevaNoHeredaLaIdentidadDeLaBorrada(t *testing.T) {
	fs := []Finding{hallazgoEn(2)}
	AsignarHuellas(fs, fuenteFija(contenidoConCuatroEsc))
	aceptada := fs[0].Fingerprint

	// Se borra la línea 2 y aparece un esc() nuevo al final, entre otras vecinas.
	editado := []string{
		"const a = leer();",
		"const b = leer();",
		"const c = leer();",
		"render(c);",
		"peligro();",
		"el.innerHTML = esc(a);", // 6 ← NUEVA, otro contexto
		"export default { a, b, c };",
	}
	fs2 := []Finding{hallazgoEn(6)}
	AsignarHuellas(fs2, fuenteFija(editado))

	if fs2[0].Fingerprint == aceptada {
		t.Error("la ocurrencia NUEVA heredó la huella de la aceptada borrada: " +
			"«solo lo nuevo bloquea» violado con código nuevo — el agujero que el ancla existe para cerrar")
	}
}

// Duplicados contextualmente indistinguibles (mismo texto Y mismas vecinas):
// ninguno se suprime. La falla va hacia bloquear, jamás hacia enterrar.
func TestLosIndistinguiblesSeMarcanAmbiguosYNadieLosSuprime(t *testing.T) {
	repetido := []string{
		"antes();",
		"el.innerHTML = esc(a);", // 2
		"despues();",
		"antes();",
		"el.innerHTML = esc(a);", // 5 — mismas vecinas que la 2
		"despues();",
	}
	fs := []Finding{hallazgoEn(2), hallazgoEn(5)}
	AsignarHuellas(fs, fuenteFija(repetido))

	if fs[0].Fingerprint != fs[1].Fingerprint {
		t.Fatal("con texto y contexto idénticos las huellas DEBEN coincidir: si no, la ambigüedad no es detectable")
	}
	if !fs[0].HuellaAmbigua || !fs[1].HuellaAmbigua {
		t.Error("dos hallazgos indistinguibles sin marcar: baselinear uno suprimiría al otro en silencio")
	}
}

// La legacy v1 reproduce EXACTAMENTE el algoritmo viejo: es lo único que
// permite que una baseline anterior siga suprimiendo durante la ventana.
func TestLaLegacyReproduceElAlgoritmoViejoByteABite(t *testing.T) {
	f := hallazgoEn(2)
	viejo := f.ComputeFingerprint() // el algoritmo v1 original, aún en pie

	fs := []Finding{hallazgoEn(2)}
	AsignarHuellas(fs, fuenteFija(contenidoConCuatroEsc))
	if fs[0].LegacyFingerprint != viejo {
		t.Errorf("legacy %s ≠ v1 real %s: la ventana dual no casaría ni una entrada",
			huellaCorta(fs[0].LegacyFingerprint, 12), huellaCorta(viejo, 12))
	}
	if fs[0].Fingerprint == viejo {
		t.Error("la v2 no puede coincidir con la v1: el dominio del hash lleva la versión dentro")
	}
}

// Lo desconocido no se casa como nada (la lección del fpRe que moría en
// silencio): v3 futuro, mayúsculas, recortes — ok=false, avisar, no suprimir.
func TestParseHuellaNoAdivinaJamas(t *testing.T) {
	hex64 := strings.Repeat("ab12", 16)
	casos := []struct {
		token   string
		version int
		ok      bool
	}{
		{hex64, 1, true},
		{"v2:" + hex64, 2, true},
		{"v3:" + hex64, 0, false},
		{"v2:" + strings.ToUpper(hex64), 0, false},
		{"v2:" + hex64[:60], 0, false},
		{strings.ToUpper(hex64), 0, false},
		{hex64[:63], 0, false},
		{"", 0, false},
		{"v2:", 0, false},
	}
	for _, c := range casos {
		v, ok := ParseHuella(c.token)
		if v != c.version || ok != c.ok {
			t.Errorf("ParseHuella(%.20q) = (%d,%v), esperaba (%d,%v)", c.token, v, ok, c.version, c.ok)
		}
	}
}

// Sin fuente de líneas (archivo ilegible, hallazgo de módulo/archivo entero)
// el ancla es vacía y la huella vale igual: v1 tampoco tenía ancla, así que
// «distinguir menos» es el piso conocido, no una regresión.
func TestSinFuenteLaHuellaSigueValiendo(t *testing.T) {
	fs := []Finding{hallazgoEn(2)}
	AsignarHuellas(fs, nil)
	if v, ok := ParseHuella(fs[0].Fingerprint); !ok || v != 2 {
		t.Errorf("sin fuente la huella salió ilegible: %q", fs[0].Fingerprint)
	}
	if fs[0].LegacyFingerprint == "" {
		t.Error("la legacy también se asigna sin fuente: no depende del ancla")
	}
}

// HuellasDeBusqueda es LA pareja con la que se consulta un mapa de
// supresiones durante la ventana: v2 siempre, legacy si existe.
func TestHuellasDeBusquedaTraeLaPareja(t *testing.T) {
	fs := []Finding{hallazgoEn(2)}
	AsignarHuellas(fs, fuenteFija(contenidoConCuatroEsc))
	par := fs[0].HuellasDeBusqueda()
	if len(par) != 2 {
		t.Fatalf("esperaba v2+legacy, llegó %v", par)
	}
	tieneV2, tieneV1 := false, false
	for _, h := range par {
		if v, ok := ParseHuella(h); ok && v == 2 {
			tieneV2 = true
		} else if ok && v == 1 {
			tieneV1 = true
		}
	}
	if !tieneV2 || !tieneV1 {
		t.Errorf("la pareja debe traer una v2 y una v1: %v", par)
	}
}

// huellaCorta conserva el prefijo y abrevia el CUERPO (turno 76): cortar el
// token completo enseñaría "v2:abcde" — casi todo prefijo, casi nada de hash.
func TestHuellaCortaAbreviaElCuerpoNoElPrefijo(t *testing.T) {
	hex64 := strings.Repeat("ab12", 16)
	if got := huellaCorta("v2:"+hex64, 8); got != "v2:ab12ab12" {
		t.Errorf("huellaCorta v2 = %q", got)
	}
	if got := huellaCorta(hex64, 8); got != "ab12ab12" {
		t.Errorf("huellaCorta v1 = %q", got)
	}
}

// El cierre de la ventana es UNA compuerta: expirado el sunset, el alias v1
// deja de nacer y con él mueren la supresión legacy, la clave SARIF /v1 y la
// columna de BD — sin cacería por sitios. Fecha vacía o ilegible = ventana
// abierta: un binario de desarrollo (o un typo) jamás re-bloquea la deuda
// aceptada del mundo entero.
func TestElSunsetApagaElAliasEnUnSoloSitio(t *testing.T) {
	guardado := SunsetV1
	defer func() { SunsetV1 = guardado }()

	SunsetV1 = "2000-01-01" // ventana muerta hace décadas
	fs := []Finding{hallazgoEn(2)}
	AsignarHuellas(fs, fuenteFija(contenidoConCuatroEsc))
	if fs[0].LegacyFingerprint != "" {
		t.Error("la ventana expiró y el alias v1 siguió naciendo")
	}
	if par := fs[0].HuellasDeBusqueda(); len(par) != 1 {
		t.Errorf("expirada la ventana, la búsqueda es solo v2: %v", par)
	}

	SunsetV1 = "9999-12-31" // ventana abierta
	fs2 := []Finding{hallazgoEn(2)}
	AsignarHuellas(fs2, fuenteFija(contenidoConCuatroEsc))
	if fs2[0].LegacyFingerprint == "" {
		t.Error("con la ventana viva el alias v1 debe nacer")
	}

	SunsetV1 = "esto-no-es-una-fecha" // typo en el build: compatibilidad, no cierre
	if !VentanaDualActiva(time.Now()) {
		t.Error("una fecha ilegible cerró la ventana: cerrar por un typo re-bloquea deuda aceptada ajena")
	}
	SunsetV1 = ""
	if !VentanaDualActiva(time.Now()) {
		t.Error("sin fecha (binario dev) la ventana queda abierta")
	}
}
