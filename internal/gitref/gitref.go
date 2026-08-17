// Package gitref valida los extremos de un rango de revisiones ANTES de que
// lleguen a git o a un motor que los reenvíe a git.
//
// Vive en su propio paquete —hoja, sin dependencias— porque lo necesitan dos
// sitios que no se conocen entre sí: gitdiff, que lee el diff, y el motor de
// gitleaks, que escanea el rango. Meterlo en gitdiff obligaría a gitleaks a
// importar el lector de diffs entero sólo para comprobar una cadena, y esa
// dependencia contaría una relación que no existe.
//
// Los errores que devuelve son PLANOS a propósito: sin centinela y sin hablar
// de bloquear ni de degradar. Cada llamador envuelve con su propia política
// —gitleaks con ErrUnavailable, para que el pipeline bloquee fail-closed; y
// gitdiff con el error de su etapa—. Si el centinela de uno viviera aquí
// dentro, la política de un paquete se colaría en el otro sin que nadie lo
// hubiera decidido.
package gitref

import (
	"fmt"
	"strings"
	"unicode"
)

// Validar comprueba que ref pueda viajar hasta git siendo todavía UNA
// referencia: ni una opción, ni dos argumentos, ni un rango entero.
//
// Lo que hay que impedir (H009/H021): --base y --head llegan de fuera —los
// flags de `codeguard ci`, que en el CI se rellenan desde el workflow— y
// terminan en dos sitios. En el motor de secretos van dentro de --log-opts, y
// gitleaks NO pasa ese valor como un argumento: lo parte por espacios y entrega
// cada trozo a `git log`. En gitdiff van directos a la línea de `git diff`. En
// los dos casos, un valor como "main --all" o "--output=/ruta" deja de nombrar
// un commit y pasa a ser OPCIONES de git: amplía el rango, lo recorta, desvía
// la salida o escribe un archivo donde diga quien lo mandó. Como la etapa de
// secretos es la única compuerta bloqueante (§14), colarse por ahí es colar un
// secreto al historial.
//
// El criterio, y esto es lo que cambió respecto al primer intento: se rechaza
// lo que hace que el valor DEJE DE SER un valor, no lo que resulta poco
// habitual. La primera versión usaba una lista blanca ASCII y tumbaba
// `corrección-h009` —una rama perfectamente normal en un equipo que escribe en
// español— haciendo BLOQUEAR el commit sin ejecutar un solo motor, mientras la
// misma rama sin acento pasaba. Contra gitleaks 8.30.0 de verdad,
// `base..corrección-h009` escanea el rango y caza el secreto: rechazarla no
// protegía de nada, sólo apagaba la compuerta. Este repo ya tenía la lección
// escrita en internal/gitdiff/acentos_test.go, donde un archivo llamado "Plan -
// Remediación y cobertura.md" tumbó semgrep y dejó pasar un commit con las 119
// reglas sin aplicar.
//
// Así que pasan todas las letras: acentos, eñes, alfabetos no latinos, acentos
// combinantes y emoji. Y se rechaza:
//
//   - la cadena vacía, que no nombra nada;
//   - cualquier espacio Unicode, que es por donde se trocea;
//   - lo no imprimible (controles, NUL, ancho cero, marcas de dirección), que no
//     se ve en una revisión de código y por eso mismo sirve para colar algo;
//   - el guion inicial, que git lee como una opción;
//   - "..", que es un rango entero metido donde va UN extremo;
//   - "@{...}", que no es inseguro pero SÍ irreproducible.
//
// De ese último conviene dejar dicho el porqué, que no es de seguridad:
// HEAD@{1} y @{-1} se resuelven con el reflog y el upstream de ESTA copia del
// repo, y un clon recién hecho —el del runner del CI— no los tiene. Un rango
// que apunta a otro sitio en cada máquina rompe en silencio la paridad
// local/CI, que es la promesa del producto (ADR-03).
//
// Lo que NO valida: si la referencia existe. De eso se queja git, en voz alta y
// con su propio mensaje. Ponerse a reimplementar check-ref-format aquí acabaría
// rechazando refs vivas, que es justo el error del que venimos.
func Validar(campo, ref string) error {
	if ref == "" {
		return fmt.Errorf("--%s vacío: hace falta una referencia de git (rama, etiqueta o SHA) para armar el rango", campo)
	}
	if strings.HasPrefix(ref, "-") {
		return fmt.Errorf("--%s = %q empieza por '-': git lo leería como una opción suya y no como un commit", campo, ref)
	}
	for _, r := range ref {
		// El orden importa para el mensaje: un tabulador es a la vez espacio y
		// no imprimible, y decir "espacio" explica mejor lo que va a pasar.
		if unicode.IsSpace(r) {
			return fmt.Errorf("--%s = %q lleva un espacio (U+%04X): quien recibe este valor lo parte justo ahí, "+
				"y lo que quede detrás dejará de ser un commit para convertirse en opciones de git", campo, ref, r)
		}
		if !unicode.IsPrint(r) {
			return fmt.Errorf("--%s = %q lleva un carácter no imprimible (U+%04X): no se ve al revisar el cambio, "+
				"que es exactamente para lo que sirve", campo, ref, r)
		}
	}
	if strings.Contains(ref, "..") {
		return fmt.Errorf("--%s = %q contiene \"..\": aquí va UN extremo del rango, no el rango entero", campo, ref)
	}
	if strings.Contains(ref, "@{") {
		return fmt.Errorf("--%s = %q usa @{...}: se resuelve con el reflog de esta copia del repo, "+
			"que el clon del CI no tiene, y el rango acabaría siendo distinto en cada máquina", campo, ref)
	}
	return nil
}

// ValidarRango comprueba los dos extremos y devuelve el "base..head" ya armado.
// Validar sólo uno deja media puerta abierta, que es como dejarla abierta
// entera. Si algo falla devuelve la cadena vacía: quien se despiste con el
// error no se llevará un rango a medio armar que parezca bueno.
func ValidarRango(base, head string) (string, error) {
	if err := Validar("base", base); err != nil {
		return "", err
	}
	if err := Validar("head", head); err != nil {
		return "", err
	}
	// El separador se comprueba DESPUÉS de armarlo, y aquí y no en Validar,
	// porque la avería no es de ninguno de los dos extremos por separado: es de
	// la CONCATENACIÓN. Rechazar el ".." completo dentro de un extremo no basta,
	// porque al atacante le sobra con aportar LA MITAD del separador — un punto
	// pegado al borde se fusiona con los dos del código y forma "...", que git
	// lee como diferencia simétrica:
	//
	//	--base "."      → "...HEAD"     → git lee HEAD...HEAD → 0 archivos, EXIT 0
	//	--base "HEAD."  → "HEAD...HEAD" → ídem
	//	--head "."      → "main..."     → git lee main...HEAD → 0 archivos, EXIT 0
	//
	// Y sale con ÉXITO: el pipeline corta en la etapa 0 con "todos los archivos
	// tocados están excluidos" y la compuerta de secretos no llega a correr. El
	// mismo desenlace que el comodín, por una puerta distinta — y el `--` de
	// gitdiff no puede cerrarla, porque esto no es un pathspec sino un rango
	// sintácticamente válido. Afecta igual a gitleaks, que comparte esta
	// función.
	//
	// La comprobación va sobre el resultado y no sobre los extremos a propósito:
	// así no hay que razonar qué borde fusiona con cuál —un punto INICIAL en el
	// base es inofensivo, y en el head no— ni mantener esa asimetría en la
	// cabeza. Si mañana el separador cambia, esto sigue siendo cierto.
	rango := base + ".." + head
	if strings.Contains(rango, "...") {
		return "", fmt.Errorf("el rango %q sale con tres puntos: los extremos se pegan a los \"..\" que los "+
			"separan y git lo lee como diferencia simétrica, que devuelve cero archivos SIN error — "+
			"el análisis se saltaría entero sin decir nada", rango)
	}
	return rango, nil
}
