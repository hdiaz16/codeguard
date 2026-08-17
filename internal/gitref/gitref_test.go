package gitref

import (
	"strings"
	"testing"
)

// Las que TIENEN que pasar. La mitad de abajo es la que tumbó el primer
// intento de arreglo: una lista blanca ASCII rechazaba las ramas de un equipo
// que escribe en español, y rechazarlas no es "más seguro", es apagar la
// compuerta. Contra gitleaks 8.30.0 de verdad, "base..corrección-h009" escanea
// el commit y caza el secreto sin despeinarse; el rechazo no era defendible.
func TestAceptaLasReferenciasDeVerdad(t *testing.T) {
	buenas := []struct{ ref, porque string }{
		{"main", "la rama de siempre"},
		{"master", "la rama de siempre, la otra"},
		{"HEAD", "el puntero"},
		{"HEAD~1", "aritmética de revisiones"},
		{"HEAD^", "aritmética de revisiones"},
		{"9f2c1ab", "SHA corto"},
		{"3e7d5c9f2c1ab4d6e8a0b2c4d6e8f0a2b4c6d8e0", "SHA de 40"},
		{"release/2026.08", "rama con barra y puntos"},
		{"v2026.8.2", "etiqueta"},
		{"feature/H009-inyeccion", "rama con guion interior"},

		// Lo que hoy falla y es el motivo del rechazo del primer arreglo:
		{"corrección-h009", "acento: pan de cada día en este equipo"},
		{"feature/validación", "acento tras una barra"},
		{"rama-con-ñ", "eñe"},
		{"用户-rama", "no todo el mundo escribe en alfabeto latino"},
		{"rama-\U0001F400", "un emoji es un símbolo imprimible, no un arma"},
	}
	for _, c := range buenas {
		if err := Validar("base", c.ref); err != nil {
			t.Errorf("%q es una referencia legítima (%s) y se rechazó: %v", c.ref, c.porque, err)
		}
	}
}

// La misma rama en NFD —la 'ó' como 'o' seguida del acento combinante— es lo
// que entrega macOS y lo que deja a veces un copiar/pegar. El acento suelto es
// una MARCA Unicode, no un carácter de control, y tiene que pasar igual que su
// forma compuesta. Va escrito con el escape a la vista y no pegado ya
// compuesto: así nadie lo "arregla" sin darse cuenta y deja la prueba
// comprobando lo mismo dos veces.
func TestAceptaAcentoDescompuesto(t *testing.T) {
	const nfd = "corrección-h009"
	if err := Validar("head", nfd); err != nil {
		t.Errorf("la forma descompuesta de %q se rechazó: %v", nfd, err)
	}
}

// Lo que de verdad abre el vector. Cada caso lleva escrito QUÉ pasaría si se
// colara, porque esa es la única razón por la que está en la lista: aquí no se
// rechaza nada por "raro", sólo por peligroso.
func TestRechazaLoQueDejaDeSerUnaReferencia(t *testing.T) {
	malas := []struct{ ref, porque string }{
		{"", "vacío: no hay commit que mirar"},
		{"   ", "sólo espacios"},
		{" main", "espacio delante: el trozo vacío se pierde y el resto viaja solo"},
		{"main ", "espacio detrás"},

		// El corazón de H009: gitleaks parte --log-opts por espacios y le
		// entrega cada trozo a `git log`, así que lo que va tras el espacio deja
		// de ser un commit y pasa a ser una opción.
		{"main --all", "opción pegada tras un espacio: amplía el rango escaneado"},
		{"--output=/tmp/x", "opción entera: desvía la salida y escribe en disco"},
		{"-n5", "opción corta: recorta cuántos commits se miran"},
		{"--all", "escanearlo todo no es escanear este rango"},

		// Espacios que no son el espacio de siempre. gitleaks 8.30.0 sólo
		// trocea por el espacio ASCII —comprobado—, así que estos cuatro son
		// defensa en profundidad y no la avería; pero son gratis y el día que
		// otro llamador use strings.Fields dejan de serlo.
		{"main\tHEAD", "tabulador"},
		{"main\nHEAD", "salto de línea"},
		{"main\rHEAD", "retorno de carro"},
		{"main\vHEAD", "tabulador vertical"},
		{"main\fHEAD", "avance de página"},
		{"main HEAD", "espacio duro: se lee como un espacio y no lo es"},
		{"main　HEAD", "espacio ideográfico"},

		// No imprimibles: no se ven en una revisión de código, que es
		// justamente lo que los hace útiles para colar algo.
		{"main\x00HEAD", "NUL: lo que ve Go y lo que ve el sistema dejan de coincidir"},
		{"main\u200bHEAD", "espacio de ancho cero: invisible en cualquier revisión"},
		{"main\u202eHEAD", "override derecha-a-izquierda: enseña una cosa y dice otra"},

		{"main..HEAD", "un rango entero donde se espera UN extremo"},
		{"a..b..HEAD", "y menos aún dos rangos"},

		// No por inseguras, por NO REPRODUCIBLES: se resuelven con el reflog y
		// el upstream de ESTA copia, que el runner del CI no tiene. La paridad
		// local/CI es la promesa del producto (ADR-03), y un rango que apunta a
		// otro sitio en cada máquina la rompe en silencio.
		{"HEAD@{1}", "reflog: en un clon recién hecho no existe"},
		{"@{-1}", "la rama anterior: depende de por dónde anduvo cada uno"},
		{"main@{upstream}", "el upstream tampoco es el mismo en todas partes"},

		{"$(git rev-parse HEAD)", "sustitución de shell (y además lleva espacios)"},
	}
	for _, c := range malas {
		if err := Validar("base", c.ref); err == nil {
			t.Errorf("%q debió rechazarse (%s)", c.ref, c.porque)
		}
	}
}

// El mensaje es la mitad del arreglo: si la ref es mala, quien la escribió
// tiene que leer QUÉ flag y QUÉ valor, o se queda mirando un fallo sin asidero.
func TestElErrorDiceQueFlagYQueValor(t *testing.T) {
	err := Validar("head", "--output=/tmp/x")
	if err == nil {
		t.Fatal("debió rechazarse")
	}
	if !strings.Contains(err.Error(), "head") {
		t.Errorf("el error no nombra el flag: %v", err)
	}
	if !strings.Contains(err.Error(), "--output=/tmp/x") {
		t.Errorf("el error no enseña el valor rechazado: %v", err)
	}
}

// El helper NO conoce la política de bloqueo de nadie. gitleaks envuelve con su
// ErrUnavailable para que el pipeline bloquee, y gitdiff con lo que toque en su
// etapa; si el centinela viviera aquí dentro, la política de un paquete se
// colaría en el otro por la puerta de atrás.
func TestElErrorEsPlanoSinCentinela(t *testing.T) {
	err := Validar("base", "--all")
	if err == nil {
		t.Fatal("debió rechazarse")
	}
	if strings.Contains(err.Error(), "no disponible") {
		t.Errorf("el helper habla de disponibilidad, que es política del llamador: %v", err)
	}
}

func TestValidarRangoArmaElRango(t *testing.T) {
	got, err := ValidarRango("release/2026.08", "corrección-h009")
	if err != nil {
		t.Fatalf("rango legítimo rechazado: %v", err)
	}
	if want := "release/2026.08..corrección-h009"; got != want {
		t.Errorf("rango = %q, se esperaba %q", got, want)
	}
}

// Validar sólo la base dejaría media puerta abierta, que es como dejarla
// abierta entera.
func TestValidarRangoMiraLosDosExtremos(t *testing.T) {
	if _, err := ValidarRango("--output=/tmp/x", "HEAD"); err == nil {
		t.Error("una base inyectada debe rechazarse")
	}
	if _, err := ValidarRango("main", "HEAD --all"); err == nil {
		t.Error("un head inyectado debe rechazarse")
	}
	// Y no puede devolver un rango a medio armar cuando falla: quien ignore el
	// error se llevaría una cadena que parece buena.
	if r, _ := ValidarRango("main", "--all"); r != "" {
		t.Errorf("al fallar debe devolver el rango vacío, devolvió %q", r)
	}
}

// Decisión explícita, no descuido: ';' se ACEPTA. git lo permite dentro de un
// nombre de rama y en esta cadena no hay ni un intérprete de comandos —los
// hijos se lanzan con exec.Command, que en Windows va a CreateProcess y no pasa
// por cmd.exe—, así que no abre ningún vector. Rechazarlo sería volver a la
// lista blanca de caracteres que ya nos costó un arreglo entero: la regla es
// rechazar lo que rompe el valor, no lo que nos parece feo.
//
// Si algún día alguien mete una ref en una línea de comandos de TEXTO, esta
// prueba falla y obliga a volver aquí a decidir con el caso delante.
func TestPuntoYComaSeAceptaAdrede(t *testing.T) {
	if err := Validar("base", "main;rm -rf /"); err == nil {
		t.Error("lleva espacios: eso sí se rechaza")
	}
	if err := Validar("base", "main;rm"); err != nil {
		t.Errorf("';' se acepta a propósito (git lo permite y no hay shell): %v", err)
	}
}

// Que la ref EXISTA no es asunto de esta función: de eso se queja git, y en voz
// alta. Aquí sólo se impide que el valor deje de ser un valor. Mezclar las dos
// cosas nos llevaría a reimplementar check-ref-format —y a rechazar refs vivas,
// que es exactamente el error del que venimos.
func TestNoSeMeteAValidarSiLaRefExiste(t *testing.T) {
	for _, ref := range []string{".oculta", "rama.lock", "no-existe-en-ningun-repo"} {
		if err := Validar("base", ref); err != nil {
			t.Errorf("%q no abre ningún vector; que exista o no lo dirá git: %v", ref, err)
		}
	}
}
