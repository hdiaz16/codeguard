package identidad

import (
	"os"
	"path/filepath"
	"testing"
)

// El manifiesto es un archivo embebido: si se corrompe, el paquete entero deja
// de servir. Comprobarlo aquí evita descubrirlo en la máquina de un dev.
func TestManifiestoTieneSentido(t *testing.T) {
	if len(cargado.Motores) == 0 {
		t.Fatal("el manifiesto no trae motores")
	}
	if _, ok := cargado.Motores["gitleaks"]; !ok {
		t.Error("falta gitleaks, que es la compuerta de secretos")
	}
	if !cargado.Motores["gitleaks"].Critico {
		t.Error("gitleaks debe estar marcado como crítico: un binario alterado calla todos los secretos")
	}
	for nombre, m := range cargado.Motores {
		if len(m.Versiones) == 0 {
			t.Errorf("%s no tiene ninguna versión publicada", nombre)
		}
		for _, v := range m.Versiones {
			if len(v.SHA256Exe) != 64 {
				t.Errorf("%s %s: sha256_exe debe ser hex de 64, es %q", nombre, v.Version, v.SHA256Exe)
			}
			if len(v.SHA256Zip) != 64 {
				t.Errorf("%s %s: sha256_zip debe ser hex de 64, es %q", nombre, v.Version, v.SHA256Zip)
			}
			if v.URL == "" || v.Fuente == "" {
				t.Errorf("%s %s: sin URL o sin fuente no se puede auditar de dónde salió el hash", nombre, v.Version)
			}
		}
	}
}

func TestBinarioAlteradoNoPasa(t *testing.T) {
	dir := t.TempDir()
	// Un "gitleaks" con contenido cualquiera: el hash no puede coincidir.
	if err := os.WriteFile(filepath.Join(dir, "gitleaks.exe"), []byte("MZ falso"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, r := range Verificar(dir) {
		if r.Motor != "gitleaks" {
			continue
		}
		if r.Estado != Desconocido {
			t.Errorf("un binario alterado debe quedar como %q, quedó como %q", Desconocido, r.Estado)
		}
		if r.Bien() {
			t.Error("un binario alterado no puede darse por bueno")
		}
		if !r.Critico {
			t.Error("gitleaks debe reportarse como crítico")
		}
		return
	}
	t.Fatal("Verificar no reportó gitleaks")
}

func TestMotorAusenteSeDistingueDeAlterado(t *testing.T) {
	for _, r := range Verificar(t.TempDir()) {
		if r.Estado != Ausente {
			t.Errorf("%s: sin archivo el estado debe ser %q, fue %q", r.Motor, Ausente, r.Estado)
		}
	}
}

// Los críticos van primero para que el humano los lea antes de perder interés.
func TestLosCriticosSeListanPrimero(t *testing.T) {
	res := Verificar(t.TempDir())
	visto := false
	for _, r := range res {
		if !r.Critico {
			visto = true
		} else if visto {
			t.Errorf("%s es crítico y aparece después de uno que no lo es", r.Motor)
		}
	}
}
