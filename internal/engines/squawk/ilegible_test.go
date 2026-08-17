package squawk

import "testing"

// Un archivo que squawk no sabe leer tiene que BLOQUEAR, y con un solo aviso.
//
// Las dos mitades vienen de un daño medido y son opuestas entre sí, que es lo
// que hace fácil equivocarse aquí:
//
//   - Contra un repo MySQL salían 79 hallazgos, todos errores de sintaxis,
//     presentados como "problemas que el CI también rechazaría". Una lista de
//     79 acusaciones falsas es la vía rápida a que nadie vuelva a leer lo que
//     dice esta herramienta.
//   - Pero convertirlos en un aviso que no bloquea abrió un agujero peor:
//     cuando el archivo no parsea, squawk NO evalúa el resto, así que un
//     `DROP COLUMN` con un typo delante entraba con EXIT=0. Antes lo frenaba
//     el propio error de sintaxis.
//
// La respuesta correcta es UNO y bloqueante.
func TestUnaMigracionIlegibleBloqueaConUnSoloAviso(t *testing.T) {
	// Cinco errores de sintaxis en dos archivos, como los suelta squawk.
	crudos := map[string]violation{}
	for _, v := range []violation{
		{File: "migrations/001.sql", Line: 0, Rule: "syntax-error", Level: "Error", Message: "expected table relation name"},
		{File: "migrations/001.sql", Line: 3, Rule: "syntax-error", Level: "Error", Message: "unexpected token"},
		{File: "migrations/001.sql", Line: 9, Rule: "syntax-error", Level: "Error", Message: "unexpected token"},
		{File: "migrations/002.sql", Line: 1, Rule: "syntax-error", Level: "Error", Message: "expected AS"},
	} {
		if _, ya := crudos[v.File]; !ya {
			crudos[v.File] = v
		}
	}

	fs := ilegibles(t.TempDir(), crudos, map[string][]string{})

	if len(fs) != 2 {
		t.Fatalf("esperaba un aviso por archivo (2), salieron %d: %+v", len(fs), fs)
	}
	// Orden estable: el informe no puede bailar entre corridas.
	if fs[0].File != "migrations/001.sql" || fs[1].File != "migrations/002.sql" {
		t.Errorf("los avisos deben salir ordenados por archivo: %s, %s", fs[0].File, fs[1].File)
	}
	for _, f := range fs {
		if !f.Blocking {
			t.Errorf("%s: una migración que no se pudo revisar NO puede pasar. "+
				"Cuando squawk tropieza con la sintaxis deja de mirar el resto del "+
				"archivo, así que un DROP COLUMN más abajo entraría sin que nadie lo viera.", f.File)
		}
		if f.Fingerprint == "" {
			t.Errorf("%s sin huella: no se podría baselinear ni suprimir", f.File)
		}
		// Las DOS salidas tienen que estar: arreglar la sintaxis, o declarar el
		// motor. Con una sola, el dev del repo MySQL se queda sin remedio.
		for _, quiero := range []string{"migrations_dialect", "sintaxis"} {
			if !contiene(f.FixHint, quiero) {
				t.Errorf("%s: el arreglo propuesto no menciona %q: %s", f.File, quiero, f.FixHint)
			}
		}
	}
}

func TestSinErroresDeSintaxisNoSeInventaNada(t *testing.T) {
	if fs := ilegibles(t.TempDir(), map[string]violation{}, map[string][]string{}); len(fs) != 0 {
		t.Errorf("sin errores de sintaxis no hay nada que decir, salieron %+v", fs)
	}
}

func contiene(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
