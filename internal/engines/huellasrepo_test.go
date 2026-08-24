package engines

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// repoConArchivos monta un repo git de verdad: HuellaModulo sólo mira archivos
// RASTREADOS, así que sin git no hay nada que medir.
func repoConArchivos(t *testing.T, archivos map[string]string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatalf("git tiene que existir para este test: %v", err)
	}
	raiz := t.TempDir()
	for ruta, cuerpo := range archivos {
		abs := filepath.Join(raiz, filepath.FromSlash(ruta))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte(cuerpo), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.email", "prueba@local"},
		{"config", "user.name", "prueba"},
		{"add", "-A"},
		{"commit", "-q", "-m", "semilla"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = raiz
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v falló: %v — %s", args, err, out)
		}
	}
	return raiz
}

// EL CONTRATO QUE HACE SEGURO AMORTIZAR EL RECORRIDO: la huella derivada de un
// HuellasRepo tiene que ser BYTE A BYTE la de HuellaModulo.
//
// De esto depende que las entradas ya guardadas en file_cache sigan valiendo. Si
// las dos formas de calcularla divergieran, una clave dejaría de corresponder a
// su contenido: el motor serviría hallazgos de otro código, que es el modo de
// fallo que este repo ya ha pagado con las cachés de clave incompleta.
func TestLaHuellaAmortizadaEsIdenticaALaDeSiempre(t *testing.T) {
	raiz := repoConArchivos(t, map[string]string{
		"Directory.Build.props":       "<Project/>",
		"src/Core/Core.csproj":        "<Project/>",
		"src/Core/packages.lock.json": "{}",
		"src/App/App.csproj":          "<Project/>",
		"README.md":                   "hola",
	})

	casos := []struct {
		nombre string
		dir    string
		filtro func(string) bool
	}{
		{"todo el repo, sin filtro", ".", nil},
		{"sólo csproj", ".", func(rel string) bool { return strings.HasSuffix(rel, ".csproj") }},
		{"un subdirectorio", "src/Core", nil},
		{"un filtro que no casa con nada", ".", func(rel string) bool { return false }},
	}
	huellas := LeerHuellasRepo(raiz)
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			quiero := HuellaModulo(raiz, c.dir, c.filtro)
			tengo := huellas.Modulo(c.dir, c.filtro)
			if tengo != quiero {
				t.Errorf("la huella amortizada no coincide:\n  HuellaModulo: %q\n  Modulo:       %q",
					quiero, tengo)
			}
		})
	}
}

// El memo de shas no puede cambiar el resultado entre llamadas repetidas: si la
// segunda huella del mismo ámbito saliera distinta, la clave de caché de un
// proyecto dependería de en qué orden se calcularon las de los demás.
func TestPedirLaMismaHuellaDosVecesDaLoMismo(t *testing.T) {
	raiz := repoConArchivos(t, map[string]string{
		"a/uno.cs": "class Uno {}",
		"b/dos.cs": "class Dos {}",
	})
	huellas := LeerHuellasRepo(raiz)
	primera := huellas.Modulo(".", nil)
	huellas.Modulo("a", nil) // otra huella en medio, que puebla el memo
	if segunda := huellas.Modulo(".", nil); segunda != primera {
		t.Errorf("la huella cambió entre llamadas: %q y %q", primera, segunda)
	}
	if primera == "" {
		t.Error("la huella salió vacía en un repo con archivos rastreados")
	}
}

// Un repo que no se puede enumerar no es cacheable, y eso NO puede convertirse en
// una huella válida por accidente: sería servir el resultado de otro contenido.
func TestUnRepoQueNoSePuedeEnumerarNoDaHuella(t *testing.T) {
	sinGit := t.TempDir()
	if h := LeerHuellasRepo(sinGit).Modulo(".", nil); h != "" {
		t.Errorf("un directorio sin git dio huella %q: tendría que ser no cacheable", h)
	}
	var nulo *HuellasRepo
	if h := nulo.Modulo(".", nil); h != "" {
		t.Errorf("un HuellasRepo nil dio huella %q", h)
	}
}
