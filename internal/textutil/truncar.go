// Package textutil agrupa utilidades de manipulación de texto compartidas
// por motores, LLM y shadow. Vive en un paquete neutral para que ninguna
// capa tenga que depender de internal/engines solo para recortar cadenas.
package textutil

import "unicode/utf8"

// TruncarRunas devuelve el prefijo de s de como máximo maxBytes bytes,
// SIN partir nunca una runa UTF-8 por la mitad.
//
// Por qué bytes y no runas: los presupuestos de los llamadores (tamaño de
// salida de linter, tokens aproximados del LLM, presupuesto de diff) se
// miden en bytes, así que el límite debe ser en bytes para mantener la
// semántica histórica de s[:n]. Pero cortar en el byte exacto n puede
// caer en medio de un carácter multibyte (acentos, CJK, emoji) y dejar un
// byte de continuación huérfano, que los consumidores renderizan como
// U+FFFD (mojibake). La corrección de raíz es retroceder desde maxBytes
// hasta el inicio de la runa en curso (utf8.RuneStart), de modo que el
// prefijo resultante es UTF-8 válido siempre que s lo sea.
//
// Semántica compatible con el antiguo s[:n]:
//   - Si len(s) <= maxBytes, devuelve s tal cual (sin copia).
//   - Si no, devuelve el prefijo seguro SIN ningún sufijo: quien llama
//     añade su "…" o su marca de truncado, porque los sufijos difieren.
//   - maxBytes <= 0 devuelve "".
func TruncarRunas(s string, maxBytes int) string {
	if maxBytes < 0 {
		maxBytes = 0
	}
	if len(s) <= maxBytes {
		return s
	}
	// Retroceder mientras el byte en maxBytes sea un byte de continuación
	// UTF-8 (10xxxxxx): ahí no se puede cortar sin partir la runa.
	for maxBytes > 0 && !utf8.RuneStart(s[maxBytes]) {
		maxBytes--
	}
	return s[:maxBytes]
}
