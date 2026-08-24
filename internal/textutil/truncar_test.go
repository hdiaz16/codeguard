package textutil

import (
	"testing"
	"unicode/utf8"
)

// TestTruncarRunasNoParteUTF8 fija la corrección de raíz: el corte nunca deja
// un byte de continuación huérfano, sea cual sea el punto pedido.
func TestTruncarRunasNoParteUTF8(t *testing.T) {
	casos := []struct {
		nombre   string
		s        string
		max      int
		esperado string
	}{
		{"ascii bajo el límite", "hola", 10, "hola"},
		{"ascii en el límite exacto", "hola", 4, "hola"},
		{"ascii cortado", "holamundo", 4, "hola"},
		{"acento cortado a media runa", "café", 3, "caf"}, // 'é' son 2 bytes (índices 3-4); cortar en 3 lo excluye entero
		{"acento justo antes", "café", 4, "caf"},          // byte 4 es continuación de 'é' → retrocede a 3
		{"acento completo", "café", 5, "café"},            // 5 bytes = toda la cadena
		{"CJK de 3 bytes cortado", "日本語", 4, "日"},         // cada char = 3 bytes; 4 cae dentro del 2º → retrocede a 3
		{"maxBytes cero", "café", 0, ""},
		{"maxBytes negativo", "café", -5, ""},
		{"vacío", "", 5, ""},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			got := TruncarRunas(c.s, c.max)
			if !utf8.ValidString(got) {
				t.Fatalf("TruncarRunas(%q, %d) = %q: NO es UTF-8 válido", c.s, c.max, got)
			}
			if c.esperado != "" && got != c.esperado {
				t.Errorf("TruncarRunas(%q, %d) = %q, se esperaba %q", c.s, c.max, got, c.esperado)
			}
			if len(got) > c.max && c.max >= 0 {
				t.Errorf("TruncarRunas(%q, %d) devolvió %d bytes, más del máximo", c.s, c.max, len(got))
			}
		})
	}
}

// TestTruncarRunasEmojiNoSeParte comprueba con un emoji real de 4 bytes que el
// corte a media secuencia retrocede a un límite de runa válido.
func TestTruncarRunasEmojiNoSeParte(t *testing.T) {
	s := "ab\U0001F600cd" // 😀 son 4 bytes en los índices 2..5
	for max := 2; max <= 6; max++ {
		got := TruncarRunas(s, max)
		if !utf8.ValidString(got) {
			t.Errorf("TruncarRunas(%q, %d) = %q: partió el emoji (UTF-8 inválido)", s, max, got)
		}
	}
}
