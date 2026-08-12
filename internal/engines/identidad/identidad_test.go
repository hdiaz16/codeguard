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

// ── motores que no son un .exe suelto ───────────────────────────────────────

// google-java-format se instala como el .jar publicado tal cual. Sin el campo
// "instalado", Verificar lo buscaría como google-java-format.exe y diría "no
// instalado" con la herramienta funcionando — una mentira justo en el sitio
// donde se mira si los motores son los que publicaron sus autores.
func TestJarInstaladoSeVerificaPorSuNombreReal(t *testing.T) {
	dir := t.TempDir()
	v := VersionesConocidas("google-java-format")[0]
	if v.Instalado == "" {
		t.Fatal("la versión debe declarar con qué nombre queda instalada")
	}
	// Un jar cualquiera: el hash no puede coincidir con el publicado.
	if err := os.WriteFile(filepath.Join(dir, v.Instalado), []byte("PK falso"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := buscar(t, Verificar(dir), "google-java-format")
	if r.Estado != Desconocido {
		t.Errorf("un jar alterado debe quedar como %q, quedó como %q (%s)", Desconocido, r.Estado, r.Detalle)
	}
	if r.SHA256 == "" {
		t.Error("hay que poder enseñar el hash de lo que sí está instalado")
	}
}

// PMD no es un ejecutable sino un árbol de jars: la huella cubre el árbol
// ENTERO. Verificar sólo el lanzador dejaría sin comprobar el jar donde viven
// las reglas de Java, que es lo único que de verdad hay que proteger — un jar
// de reglas alterado calla los hallazgos sin que nada parezca roto.
func TestArbolInstaladoSeVerificaEntero(t *testing.T) {
	dir := t.TempDir()
	v := VersionesConocidas("pmd")[0]
	home := filepath.Join(dir, v.Instalado)
	if err := os.MkdirAll(filepath.Join(home, "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	for ruta, cuerpo := range map[string]string{
		"bin/pmd.bat":  "@echo off\n",
		"lib/pmd.jar":  "jar-de-mentira",
		"lib/otro.jar": "otro",
	} {
		abs := filepath.Join(home, filepath.FromSlash(ruta))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte(cuerpo), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	antes, err := HuellaArbol(home)
	if err != nil {
		t.Fatal(err)
	}
	if r := buscar(t, Verificar(dir), "pmd"); r.Estado != Desconocido || r.SHA256 != antes {
		t.Errorf("un árbol que no es el publicado debe quedar como %q con su huella; quedó %q/%s",
			Desconocido, r.Estado, r.SHA256)
	}

	// Tocar UN archivo de dentro tiene que cambiar la huella: si no, la
	// verificación no serviría para lo que existe.
	if err := os.WriteFile(filepath.Join(home, "lib", "otro.jar"), []byte("manipulado"), 0o644); err != nil {
		t.Fatal(err)
	}
	despues, err := HuellaArbol(home)
	if err != nil {
		t.Fatal(err)
	}
	if despues == antes {
		t.Error("cambiar un jar de dentro debe cambiar la huella del árbol")
	}
}

// La huella no puede depender de fechas ni del orden en que se recorra el
// disco: dos extracciones del mismo artefacto en dos máquinas tienen que dar el
// mismo hash, o el instalador acusaría de manipulación a una instalación sana.
func TestHuellaArbolSoloDependeDelContenido(t *testing.T) {
	crear := func(t *testing.T) string {
		t.Helper()
		raiz := t.TempDir()
		for ruta, cuerpo := range map[string]string{
			"a/uno.txt": "uno", "b/dos.txt": "dos", "raiz.txt": "tres",
		} {
			abs := filepath.Join(raiz, filepath.FromSlash(ruta))
			if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(abs, []byte(cuerpo), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return raiz
	}
	uno, dos := crear(t), crear(t)
	h1, err := HuellaArbol(uno)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := HuellaArbol(dos)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Errorf("dos árboles con el mismo contenido deben dar la misma huella: %s vs %s", h1, h2)
	}
}

func buscar(t *testing.T, res []Resultado, motor string) Resultado {
	t.Helper()
	for _, r := range res {
		if r.Motor == motor {
			return r
		}
	}
	t.Fatalf("Verificar no reportó %s", motor)
	return Resultado{}
}
