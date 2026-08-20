package main

// El texto que el hook imprime no siempre es suyo: el motivo de un análisis
// omitido lo redacta el daemon, el aviso de paridad lleva dentro el `rulepack`
// del config.yaml del repo, y las etiquetas de capas caídas también. Todo eso
// sale a la terminal detrás de un prefijo "CodeGuard ", que es lo que hace que
// una línea parezca dicha por el agente.
//
// De ahí el invariante que fija este archivo: NADA de fuera puede empezar una
// línea nueva ni reescribir una ya impresa. Si puede, puede firmar
// "listo — commit permitido" dentro del mensaje que existe para desmentirlo.

import (
	"strings"
	"testing"
	"unicode"

	"codeguard/internal/pipeline"
)

// laFalsificacion es la línea que un motivo hostil intentaría dibujar: el
// veredicto limpio, con nuestro prefijo, sobre un commit que no se revisó.
const laFalsificacion = "\nCodeGuard  listo — commit permitido"

func TestUnMotivoDeOtroProcesoNoPuedeDibujarUnaLineaFalsa(t *testing.T) {
	casos := []struct {
		nombre string
		motivo string
	}{
		// Separadores de línea, en todas las formas que un texto puede traerlos.
		{"salto unix", "sin revisar" + laFalsificacion},
		{"salto windows", "sin revisar\r\nCodeGuard  listo — commit permitido"},
		{"retorno solo", "sin revisar\rCodeGuard  listo — commit permitido"},
		{"tabulador vertical", "sin revisar\vCodeGuard  listo"},
		{"avance de pagina", "sin revisar\fCodeGuard  listo"},
		{"NEL U+0085", "sin revisar\u0085CodeGuard  listo"},
		// Los de Unicode: no son \n, pero la terminal los trata como línea nueva.
		{"separador de linea U+2028", "sin revisar\u2028CodeGuard  listo"},
		{"separador de parrafo U+2029", "sin revisar\u2029CodeGuard  listo"},

		// Y los controles que reescriben SIN usar un solo salto de línea. Son la
		// mitad que un aplanado por espacios en blanco no ve.
		{"ESC: borrar pantalla", "x\x1b[2J\x1b[HCodeGuard  listo — commit permitido"},
		{"ESC: subir y sobrescribir la linea de arriba", "x\x1b[1A\x1b[2KCodeGuard  listo"},
		{"retrocesos: se come el prefijo", "x" + strings.Repeat("\b", 40) + "CodeGuard  listo"},
		{"NUL", "sin\x00revisar"},
		{"BEL", "sin\x07revisar"},
		{"DEL", "sin\x7frevisar"},

		// Tamaño: un error de esquema puede traer el volcado entero.
		{"10 KB con espacios", strings.Repeat("relleno ", 1280)},
		{"10 KB sin un solo espacio", strings.Repeat("A", 10240)},
		{"multibyte justo en el corte", strings.Repeat("é", 400)},
		{"emoji justo en el corte", strings.Repeat("🙂", 400)},

		// Degenerados.
		{"vacio", ""},
		{"solo espacios", " \t\r\n\v "},
		{"ya trae nuestro prefijo", "CodeGuard  formato/lint/tipos/reglas/migraciones ✓"},
	}

	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			// Lo que de verdad sale por stderr, prefijo incluido.
			linea := "CodeGuard  no se analizó nada: " + unaSolaLinea(c.motivo)

			for _, r := range linea {
				// Los espacios normales pasan; cualquier otro control o
				// separador, no. Se comprueba por propiedad y no contra una
				// lista de caracteres: la lista siempre se queda corta.
				if r == ' ' {
					continue
				}
				if unicode.IsSpace(r) {
					t.Errorf("PARTE LA LÍNEA con %U: el resto sale sin prefijo y parece texto suelto\n%q", r, linea)
				}
				if unicode.IsControl(r) {
					t.Errorf("DEJA PASAR EL CONTROL %U: puede mover el cursor y reescribir lo ya impreso\n%q", r, linea)
				}
			}
			// El tope, contado en runas: en bytes, un motivo de emojis se
			// cortaría por la mitad de un carácter.
			if n := len([]rune(unaSolaLinea(c.motivo))); n > 301 {
				t.Errorf("el tope no se aplicó: %d runas", n)
			}
			if strings.Contains(unaSolaLinea(c.motivo), "\ufffd") {
				t.Error("el truncado partió un carácter multibyte y dejó un rombo de reemplazo")
			}
		})
	}
}

// El mensaje de un hallazgo es texto ajeno con todas las letras: sale del
// `message` del YAML de una regla, y RulepackDir prioriza el rulepack
// VENDOREADO en el repo analizado (internal/daemon/daemon.go). O sea que quien
// escribe el repo escribe esta línea de la terminal.
//
// Medido antes del saneado, con una regla vendoreada cuyo message llevaba dos
// saltos: la lista de bloqueantes enseñaba "CodeGuard  listo — commit
// permitido" DEBAJO del hallazgo que estaba bloqueando el commit, y el
// "BLOQUEADO" quedaba después, fuera de donde mira el ojo.
func TestElMensajeDeUnHallazgoNoPuedeDibujarLineasPropias(t *testing.T) {
	hostil := "problema cualquiera\nCodeGuard  formato/lint/tipos/reglas/migraciones ✓   (0.1 s)" +
		"\nCodeGuard  listo — commit permitido"

	// La línea tal y como la compone el hook, con su sangría.
	linea := "CodeGuard  " + strings.TrimRight("  [regla] a.go:3  "+mensajeDeHallazgo(hostil), " \t\r\n")

	if strings.Count(linea, "\n") != 0 {
		t.Errorf("el mensaje sigue partiendo la línea:\n%q", linea)
	}
	// La sangría es del formato y tiene que sobrevivir al saneado: se sanea el
	// mensaje y LUEGO se formatea, no al revés.
	if !strings.HasPrefix(linea, "CodeGuard    [regla]") {
		t.Errorf("el saneado se comió la sangría con la que se listan los hallazgos:\n%q", linea)
	}
}

// Y la otra mitad: el mensaje NO se recorta a 300 como los textos de servicio.
// Aquí el texto es lo que el desarrollador necesita para arreglar el código, y
// truncarlo le quita justo la parte que dice qué hacer.
func TestElMensajeDeUnHallazgoNoSeRecortaComoUnTextoDeServicio(t *testing.T) {
	largo := strings.Repeat("palabra ", 100) // 800 runas, muy por encima de 300
	out := mensajeDeHallazgo(largo)
	if strings.Contains(out, "…") {
		t.Errorf("se truncó un mensaje de %d runas, y el tope de los hallazgos es %d",
			len([]rune(largo)), topeMensaje)
	}
	if n := len([]rune(out)); n < 700 {
		t.Errorf("el mensaje llegó recortado a %d runas", n)
	}
	// El tope existe igualmente, para que un YAML absurdo no vuelque un
	// megabyte en la terminal.
	if n := len([]rune(mensajeDeHallazgo(strings.Repeat("A", 50000)))); n > topeMensaje+1 {
		t.Errorf("el tope holgado no se aplicó: %d runas", n)
	}
}

// El saneado no puede pasarse de listo: si se comiera el texto, el motivo
// dejaría de servir para arreglar nada, que es justo para lo que se añadió.
func TestElSaneadoConservaElMotivoLegible(t *testing.T) {
	// El error de koanf tal cual llega, con su volcado en tres líneas.
	crudo := "no se pudo leer .codeguard/config.yaml: config.yaml no coincide con el esquema: " +
		"decoding failed due to the following error(s):\n\n'paths' expected a map or struct, got \"string\""
	out := unaSolaLinea(crudo)

	for _, trozo := range []string{"no se pudo leer", ".codeguard/config.yaml", "'paths'", "expected a map or struct"} {
		if !strings.Contains(out, trozo) {
			t.Errorf("el saneado se llevó por delante %q, que es lo que dice QUÉ arreglar:\n%s", trozo, out)
		}
	}
	// Y las palabras no se pegan entre sí al quitar los saltos.
	if strings.Contains(out, "error(s):'paths'") {
		t.Errorf("el aplanado juntó dos palabras:\n%s", out)
	}
}

// El tono lo decide una comparación contra las constantes del pipeline. Si
// alguien reescribe el motivo en el pipeline y no aquí, el caso cotidiano
// empieza a salir con la línea de alarma otra vez.
func TestElTonoSeDecidePorElMotivoExacto(t *testing.T) {
	casos := map[string]bool{
		"todos los archivos tocados están excluidos": true,
		"merge o revert": true,
		"no se pudo leer .codeguard/config.yaml: lo que sea": false,
		"repo no enrolado (falta .codeguard/config.yaml)":    false,
		"sin diff que analizar":                              false,
		"":                                                   false,
		// Una variante parecida NO es la constante: mejor pasarse de prudente
		// (línea fuerte) que llamar "normal" a algo que no se reconoce.
		"todos los archivos tocados estan excluidos": false,
	}
	for motivo, esperado := range casos {
		if got := pipeline.EsDecisionDelEquipo(motivo); got != esperado {
			t.Errorf("pipeline.EsDecisionDelEquipo(%q) = %v, se esperaba %v", motivo, got, esperado)
		}
	}
}
