package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codeguard/internal/config"
)

// Temporal: la tabla de validación de los 7 repos. Se borra al terminar.
func TestZZTablaDeValidacion(t *testing.T) {
	if os.Getenv("MEDIR") == "" {
		t.Skip("sólo bajo MEDIR=1")
	}
	base := filepath.Join(os.Getenv("USERPROFILE"), "Desktop")
	for _, nombre := range []string{"demo-go-api", "demo-web-ts", "demo-python-etl",
		"demo-node-js", "demo-tienda", "demo-pagos", "inventario-cliente"} {
		raiz := filepath.Join(base, nombre)
		cfg, err := config.Load(raiz)
		if err != nil || cfg == nil {
			t.Logf("%-16s SIN CONFIG (%v)", nombre, err)
			continue
		}
		capas := CapasDelRepoEn(cfg, raiz)
		falta := Disponibilidad(capas)
		var nf []string
		for _, d := range falta {
			nf = append(nf, d.Motor+"("+d.Falta+")")
		}
		aviso := ""
		if len(nf) > 0 {
			aviso = "  NO PUEDEN: " + strings.Join(nf, " ")
		}
		t.Logf("%-16s stack=%v\n                 %d capas: %s%s",
			nombre, cfg.Languages, len(capas), strings.Join(capas, " "), aviso)
	}
}
