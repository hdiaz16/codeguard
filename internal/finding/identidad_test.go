package finding

import "testing"

// Aceptación de W6 tanda (a): los seis motores «mensaje» (eslint, govet,
// staticcheck, mypy, biome, dotnet-format) dejaron de meter el MENSAJE en
// LineContent. Ahora su parser no pone línea; AsignarHuellas la lee del
// archivo (identidad de LÍNEA) y la legacy v1 se reconstruye del mensaje —lo
// que el binario viejo hasheaba— para que la ventana dual siga casando.

// los seis motores cuya disciplina migró de mensaje→línea (contenidoLegacy).
var motoresMensaje = []string{"eslint", "govet", "staticcheck", "mypy", "biome", "dotnet-format"}

// fuenteConLinea es un archivo de juguete cuya línea 3 es la señalada.
var fuenteConLinea = []string{
	"package main",  // 1
	"func main() {", // 2
	"x := 1",        // 3 ← la línea del hallazgo
	"_ = x",         // 4
	"}",             // 5
}

// La legacy del binario VIEJO para un motor mensaje: ponía LineContent =
// mensaje y hasheaba con el algoritmo v1. Reproducirla aquí es la vara contra
// la que se mide, no una copia del código de producción.
func legacyViejaDeMensaje(rule, file, mensaje string) string {
	viejo := Finding{RuleKey: rule, File: file, LineContent: mensaje}
	return viejo.ComputeFingerprint()
}

// Fixture POR MOTOR (condición de GPT, t.128): para cada uno de los seis, con
// LineContent vacío y un mensaje, AsignarHuellas (a) lee la línea real y la
// pone en LineContent, y (b) emite una legacy v1 idéntica a la del binario
// viejo. Sin (b) las baselines del mundo dejan de suprimir en el upgrade.
func TestLosSeisMotoresMensajeReproducenSuLegacyV1(t *testing.T) {
	const mensaje = "'x' is assigned a value but never used"
	for _, eng := range motoresMensaje {
		t.Run(eng, func(t *testing.T) {
			fs := []Finding{{
				Engine: eng, RuleKey: "R1", File: "a.go", Line: 3,
				Message: mensaje, Identidad: IdentidadLinea, // LineContent vacío a propósito
			}}
			AsignarHuellas(fs, fuenteFija(fuenteConLinea))

			if fs[0].LineContent != "x := 1" {
				t.Errorf("AsignarHuellas debía leer la línea real; LineContent = %q", fs[0].LineContent)
			}
			if fs[0].NoSuprimible {
				t.Error("línea legible: el hallazgo NO debe quedar como no suprimible")
			}
			if v, ok := ParseHuella(fs[0].Fingerprint); !ok || v != 2 {
				t.Errorf("v2 ilegible: %q", fs[0].Fingerprint)
			}
			esperada := legacyViejaDeMensaje("R1", "a.go", mensaje)
			if fs[0].LegacyFingerprint != esperada {
				t.Errorf("legacy %s ≠ v1 vieja %s: la baseline anterior de %s dejaría de suprimir",
					huellaCorta(fs[0].LegacyFingerprint, 12), huellaCorta(esperada, 12), eng)
			}
		})
	}
}

// los cuatro HÍBRIDOS (W6 tanda b): su v1 hasheaba «<regla> <mensaje>».
var motoresHibridos = []string{"ruff", "tsc", "dotnet-build", "pmd"}

// La legacy vieja de un híbrido: el binario viejo ponía LineContent =
// RuleKey+" "+Message y hasheaba con v1.
func legacyViejaDeHibrido(rule, file, mensaje string) string {
	viejo := Finding{RuleKey: rule, File: file, LineContent: rule + " " + mensaje}
	return viejo.ComputeFingerprint()
}

// Fixture POR MOTOR para los híbridos: con LineContent vacío, AsignarHuellas
// lee la línea real y reconstruye la legacy v1 desde RuleKey+Message — que es
// lo que el binario viejo metía en LineContent. Sin esto, la baseline previa
// de ruff/tsc/dotnet-build/pmd deja de suprimir en cuanto se actualiza el
// binario.
func TestLosCuatroHibridosReproducenSuLegacyV1(t *testing.T) {
	const mensaje = "cannot find name 'foo'"
	for _, eng := range motoresHibridos {
		t.Run(eng, func(t *testing.T) {
			fs := []Finding{{
				Engine: eng, RuleKey: "TS2304", File: "a.go", Line: 3,
				Message: mensaje, Identidad: IdentidadLinea, // LineContent vacío
			}}
			AsignarHuellas(fs, fuenteFija(fuenteConLinea))

			if fs[0].LineContent != "x := 1" {
				t.Errorf("AsignarHuellas debía leer la línea real; LineContent = %q", fs[0].LineContent)
			}
			if fs[0].NoSuprimible {
				t.Error("línea legible: el hallazgo NO debe quedar como no suprimible")
			}
			esperada := legacyViejaDeHibrido("TS2304", "a.go", mensaje)
			if fs[0].LegacyFingerprint != esperada {
				t.Errorf("legacy %s ≠ v1 vieja %s: la baseline anterior de %s dejaría de suprimir",
					huellaCorta(fs[0].LegacyFingerprint, 12), huellaCorta(esperada, 12), eng)
			}
		})
	}
}

// La propiedad que justifica la migración: reformular SOLO el mensaje (un
// upgrade del linter que cambia el texto del diagnóstico) NO mueve la v2,
// porque la v2 se hace de la línea REAL. La legacy sí cambia —hasheaba el
// mensaje— pero la v2, que es la identidad primaria, aguanta el upgrade.
func TestUnCambioDeMensajeNoMueveLaV2(t *testing.T) {
	nuevo := func(msg string) Finding {
		return Finding{Engine: "eslint", RuleKey: "R1", File: "a.go", Line: 3,
			Message: msg, Identidad: IdentidadLinea}
	}
	// Dos corridas distintas (no la misma, para no marcar ambigüedad): el
	// linter viejo y el nuevo describen el MISMO hallazgo con otro texto.
	fsViejo := []Finding{nuevo("'x' is assigned a value but never used")}
	fsNuevo := []Finding{nuevo("Variable 'x' is defined but never read")}
	AsignarHuellas(fsViejo, fuenteFija(fuenteConLinea))
	AsignarHuellas(fsNuevo, fuenteFija(fuenteConLinea))

	if fsViejo[0].Fingerprint != fsNuevo[0].Fingerprint {
		t.Errorf("reformular el mensaje movió la v2 (%s → %s): la baseline no sobreviviría a un upgrade del linter",
			huellaCorta(fsViejo[0].Fingerprint, 12), huellaCorta(fsNuevo[0].Fingerprint, 12))
	}
	if fsViejo[0].LegacyFingerprint == fsNuevo[0].LegacyFingerprint {
		t.Error("la legacy debería DEPENDER del mensaje (así casaba la baseline vieja): si no cambia, no reproduce v1")
	}
}

// Línea ilegible (archivo borrado, número fuera de rango): el hallazgo de
// clase Línea pasa a NoDisponible — NO genera huella suprimible ni entra en
// baseline, pero queda visible. La falla va hacia bloquear, jamás hacia
// suprimir a ciegas una regla/ruta que otro código futuro podría reusar.
func TestLineaIlegibleNoEsSuprimible(t *testing.T) {
	for _, linea := range []int{0, 999} {
		fs := []Finding{{
			Engine: "mypy", RuleKey: "R1", File: "a.go", Line: linea,
			Message: "m", Identidad: IdentidadLinea,
		}}
		AsignarHuellas(fs, fuenteFija(fuenteConLinea)) // la fuente tiene 5 líneas

		if fs[0].Identidad != IdentidadNoDisponible {
			t.Errorf("línea %d: identidad = %d, esperaba NoDisponible", linea, fs[0].Identidad)
		}
		if !fs[0].NoSuprimible {
			t.Errorf("línea %d: debía quedar NoSuprimible", linea)
		}
		if fs[0].LegacyFingerprint != "" {
			t.Errorf("línea %d: un hallazgo no suprimible no lleva legacy (baselinaría a ciegas)", linea)
		}
		if fs[0].HuellaAmbigua {
			t.Errorf("línea %d: un no-suprimible no entra en la detección de ambigüedad", linea)
		}
	}
}

// Un motor SEMÁNTICO (identidad canónica en LineContent puesta por su parser)
// NO se toca: AsignarHuellas respeta su LineContent y jamás intenta leer una
// línea. Es el otro lado del veto al centinela: la clase se declara, no se
// adivina.
func TestElSemanticoConservaSuIdentidadCanonica(t *testing.T) {
	fs := []Finding{{
		Engine: "trivy", RuleKey: "CVE-2024-1", File: "go.mod", Line: 1,
		LineContent: "github.com/x/y@v1.2.3", Identidad: IdentidadSemantica,
	}}
	AsignarHuellas(fs, fuenteFija(fuenteConLinea))

	if fs[0].LineContent != "github.com/x/y@v1.2.3" {
		t.Errorf("AsignarHuellas pisó la identidad canónica del semántico: %q", fs[0].LineContent)
	}
	if fs[0].NoSuprimible {
		t.Error("un semántico con identidad canónica es perfectamente suprimible")
	}
}
