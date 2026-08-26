package finding

import "testing"

// La huella es un formato PERSISTIDO: vive en los baseline.txt de usuarios
// reales y en la columna de la BD. Cambiar un solo byte de cómo se construye
// resucitaría deuda ya aceptada en cada repo del mundo.
//
// Este golden fija esos bytes con literales OBTENIDOS DEL BINARIO ANTERIOR al
// refactor, no recalculados con el algoritmo que se está tocando: un test que
// reprodujera la construcción pasaría aunque los dos lados cambiaran a la vez,
// y entonces no probaría nada. Si este test falla, la respuesta correcta NUNCA
// es actualizar el valor esperado.
//
// Nació en la limpieza de 2026-08-25, al unificar la etiqueta de versión en
// una sola fuente (versionHuellaV2): la condición que firmaron Kimi y GPT para
// aceptar ese cambio fue demostrar que no movía ni un byte.
func TestGoldenDeHuellas(t *testing.T) {
	fs := []Finding{
		{
			Engine: "semgrep", RuleKey: "ts-innerhtml-var", File: "sitio/src/js/main.js",
			Line: 2, LineContent: "el.innerHTML = esc(a);",
		},
		{
			Engine: "gosec", RuleKey: "G401", File: "internal/store/store.go",
			Line: 1, LineContent: "sum := sha256.Sum256([]byte(s))",
		},
	}
	AsignarHuellas(fs, fuenteFija([]string{
		"const a = 1;",
		"el.innerHTML = esc(a);",
		"const b = 2;",
	}))

	casos := []struct {
		quien  string
		huella string
		legacy string
	}{
		{
			quien:  "semgrep/ts-innerhtml-var",
			huella: "v2:c533078730750598604cbeb95b38ac8d6696576c7f9eafbb86d15b739f607807",
			legacy: "11edb10d875f7dd630f5934be9eebc0350cef82bdf29ad875c55f346cec00dc6",
		},
		{
			quien:  "gosec/G401",
			huella: "v2:0e164a8607ce2db44a534a21d6b8c71fa18fb40888faffe6f757764febcb14c7",
			legacy: "fe1d3acec23d8c201cc2fee30111570f54e3d4275e8289f7022b37e5cfdae42b",
		},
	}
	for i, c := range casos {
		if fs[i].Fingerprint != c.huella {
			t.Errorf("%s: huella v2 = %q, el golden dice %q\n"+
				"si esto cambió, TODA baseline v2 del mundo dejó de suprimir",
				c.quien, fs[i].Fingerprint, c.huella)
		}
		if fs[i].LegacyFingerprint != c.legacy {
			t.Errorf("%s: alias v1 = %q, el golden dice %q\n"+
				"si esto cambió, TODA baseline v1 del mundo dejó de suprimir",
				c.quien, fs[i].LegacyFingerprint, c.legacy)
		}
	}
}
