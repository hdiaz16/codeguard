package registry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// El registro vive en %LOCALAPPDATA%; las pruebas lo apuntan a un temporal.
func enTemporal(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("LOCALAPPDATA", dir)
	return dir
}

func TestLoadOlvidaDeVerdadLosQueYaNoExisten(t *testing.T) {
	base := enTemporal(t)
	vivo := filepath.Join(base, "proyecto-vivo")
	if err := os.MkdirAll(vivo, 0o755); err != nil {
		t.Fatal(err)
	}
	muerto := filepath.Join(base, "proyecto-borrado") // nunca se crea

	Add(vivo, "vivo", "go")
	Add(muerto, "borrado", "go")

	repos := Load()
	if len(repos) != 1 || repos[0].Nombre != "vivo" {
		t.Fatalf("Load debía devolver solo el vivo, devolvió %d", len(repos))
	}

	// Y el archivo tiene que haber quedado limpio: antes se filtraba en cada
	// lectura pero la entrada muerta seguía ahí, y cualquier otro lector
	// —el panel, por ejemplo— la seguía viendo.
	raw, err := os.ReadFile(path())
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 {
		t.Fatal("el registro quedó vacío")
	}
	var quedan []Repo
	if err := json.Unmarshal(raw, &quedan); err != nil {
		t.Fatal(err)
	}
	if len(quedan) != 1 {
		t.Errorf("el archivo conserva %d entradas; debía quedar 1", len(quedan))
	}
}

func TestRemoveQuitaSoloElPedido(t *testing.T) {
	base := enTemporal(t)
	uno := filepath.Join(base, "uno")
	dos := filepath.Join(base, "dos")
	os.MkdirAll(uno, 0o755)
	os.MkdirAll(dos, 0o755)
	Add(uno, "uno", "")
	Add(dos, "dos", "")

	if !Remove(uno) {
		t.Fatal("Remove debía encontrar el proyecto")
	}
	repos := Load()
	if len(repos) != 1 || repos[0].Nombre != "dos" {
		t.Errorf("quedaron %d proyectos; debía quedar solo 'dos'", len(repos))
	}
	if Remove(filepath.Join(base, "no-registrado")) {
		t.Error("Remove no debe decir que quitó algo que no estaba")
	}
}

// Una sola entrada tiene que seguir siendo una LISTA en el archivo. Al
// manipularlo desde PowerShell esto salió mal —ConvertTo-Json devuelve un
// objeto suelto— y el agente se quedó sin ningún proyecto.
func TestElArchivoEsSiempreUnaLista(t *testing.T) {
	base := enTemporal(t)
	solo := filepath.Join(base, "solo")
	os.MkdirAll(solo, 0o755)
	Add(solo, "solo", "")

	raw, err := os.ReadFile(path())
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || raw[0] != '[' {
		t.Errorf("el registro debe empezar por '['; empieza por %q", string(raw[:1]))
	}
}
