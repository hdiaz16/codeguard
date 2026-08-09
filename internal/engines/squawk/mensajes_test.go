package squawk

import (
	"strings"
	"testing"
)

// Todas las reglas que BLOQUEAN tienen que estar en español: son las que paran
// el trabajo de alguien, y ese es el peor momento para hacerle traducir.
func TestLasReglasQueBloqueanEstanEnEspanol(t *testing.T) {
	for regla := range blockingRules {
		e, ok := enEspanol[regla]
		if !ok {
			t.Errorf("%s bloquea pero no tiene texto en español", regla)
			continue
		}
		if e.Mensaje == "" || e.Arreglo == "" {
			t.Errorf("%s: mensaje o arreglo vacío", regla)
		}
		// El arreglo tiene que decir qué hacer, no sólo qué está mal.
		if len(e.Arreglo) < 40 {
			t.Errorf("%s: el arreglo es demasiado corto para ser accionable: %q", regla, e.Arreglo)
		}
	}
}

func TestUnaReglaDesconocidaConservaSuTexto(t *testing.T) {
	msg, arreglo := traducir("regla-que-no-conocemos", "Original message", "Original help")
	if msg != "Original message" || arreglo != "Original help" {
		t.Errorf("una regla nueva de squawk debe pasar tal cual: %q / %q", msg, arreglo)
	}
	// Sin mensaje, al menos el nombre de la regla: nunca vacío.
	if msg, _ := traducir("otra-desconocida", "", ""); msg != "otra-desconocida" {
		t.Errorf("sin mensaje debe caer al nombre de la regla, dio %q", msg)
	}
}

func TestNoQuedaronTextosEnIngles(t *testing.T) {
	// En minúsculas, porque los comandos SQL (CREATE INDEX CONCURRENTLY, NOT
	// VALID, ADD CONSTRAINT) van en mayúsculas y son inglés legítimo: son el
	// comando que hay que escribir, no prosa sin traducir.
	sospechosas := []string{
		" the ", " table ", " column ", " rows ", " while ", " which ",
		" blocks ", " requires ", " adding ", " existing ",
	}
	for regla, e := range enEspanol {
		texto := " " + e.Mensaje + " " + e.Arreglo + " "
		for _, s := range sospechosas {
			if strings.Contains(texto, s) {
				t.Errorf("%s parece tener prosa en inglés sin traducir (%q)", regla, strings.TrimSpace(s))
			}
		}
	}
}
