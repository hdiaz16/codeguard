package gitleaks

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"codeguard/internal/engines"
)

// UN REPO PODÍA APAGAR SU PROPIA COMPUERTA, DE CINCO MANERAS.
//
// Las cinco meten un secreto en el commit con gitleaks saliendo 0, reporte `[]`
// y ni una línea ERR/FTL — así que el discriminante anterior ("contó un error
// propio, su silencio no vale") no puede verlas. Las cinco viajan DENTRO del
// repositorio, o sea que no apagan la compuerta del que ataca: la apagan para
// todo el que clone.
//
// Este test es el arnés de esa clase entera. Corre con el gitleaks de verdad
// porque el fallo está en la interacción entre git, la configuración del repo y
// gitleaks; un stub sólo podría reproducir la conclusión que yo ya hubiera
// escrito, que es exactamente el test decorativo que no vale nada.
//
// PARA EL QUE VENGA A TOCAR ESTO: la trampa del fixture es que el secreto tiene
// que plantarse DESPUÉS de preparar el repo, y el control tiene que ir primero.
// Un fixture con la clave de ejemplo de AWS (AKIAIOSFODNN7EXAMPLE) sale limpio
// porque gitleaks la trae en su lista de permitidos, y entonces todos los casos
// "no bloquea" pasan sin haber probado nada.

// ataque describe un repo preparado para colar el secreto.
type ataque struct {
	nombre string
	// montar deja el repo listo CON el secreto ya en el índice.
	montar func(t *testing.T, repo string)
}

// tokenOculto es el mismo de patDePrueba pero con otro valor, para que los dos
// tests no compartan huella. Partido en dos literales por la razón de siempre:
// entero, la compuerta de este repo bloquearía el commit de su propio fuente.
const tokenOculto = "ghp_" + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2"

func repoVacio(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("gitleaks"); err != nil {
		t.Skip("gitleaks no está en PATH")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git no está en PATH")
	}
	repo := t.TempDir()
	for _, args := range [][]string{
		{"init"}, {"config", "user.email", "a@b.c"}, {"config", "user.name", "a"},
		{"config", "commit.gpgsign", "false"},
		// Sin esto, en Windows git reescribe los finales de línea al indexar y
		// el byte NUL del ataque 2 deja de estar donde se plantó.
		{"config", "core.autocrlf", "false"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("no pude preparar el repo (%v): %s", err, out)
		}
	}
	return repo
}

func escribirEn(t *testing.T, repo, rel string, contenido []byte) {
	t.Helper()
	destino := filepath.Join(repo, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(destino), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destino, contenido, 0o644); err != nil {
		t.Fatal(err)
	}
}

func gitEn(t *testing.T, repo string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = repo
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("git %s falló (%v): %s", strings.Join(args, " "), err, out)
	}
}

func ataques() []ataque {
	return []ataque{
		{
			// EL CONTROL. Va primero y su papel es el de siempre: si el secreto
			// en texto plano NO bloqueara, los otros cuatro estarían midiendo un
			// gitleaks que no encuentra nada por su cuenta y todo el arnés sería
			// decorativo.
			nombre: "control: secreto en texto plano",
			montar: func(t *testing.T, repo string) {
				escribirEn(t, repo, "creds.txt", []byte("token = \""+tokenOculto+"\"\n"))
				gitEn(t, repo, "add", "-A")
			},
		},
		{
			// git declara el archivo binario y no emite contenido, así que
			// gitleaks escanea 0 bytes de él y sale contento.
			nombre: "1) .gitattributes con -diff",
			montar: func(t *testing.T, repo string) {
				escribirEn(t, repo, ".gitattributes", []byte("creds.txt -diff\n"))
				gitEn(t, repo, "add", "-A")
				gitEn(t, repo, "commit", "-m", "base")
				escribirEn(t, repo, "creds.txt", []byte("token = \""+tokenOculto+"\"\n"))
				gitEn(t, repo, "add", "-A")
			},
		},
		{
			// Mismo efecto sin tocar la configuración: un byte NUL basta para
			// que git lo tenga por binario.
			nombre: "2) un byte NUL dentro del archivo",
			montar: func(t *testing.T, repo string) {
				escribirEn(t, repo, "creds.txt",
					append([]byte{0, '\n'}, []byte("token = \""+tokenOculto+"\"\n")...))
				gitEn(t, repo, "add", "-A")
			},
		},
		{
			// Aquí gitleaks SÍ mira —escanea los bytes— y calla lo que ve.
			nombre: "3) .gitleaks.toml con allowlist .*",
			montar: func(t *testing.T, repo string) {
				escribirEn(t, repo, ".gitleaks.toml",
					[]byte("title=\"x\"\n[allowlist]\ndescription=\"x\"\nregexes=[\".*\"]\n"))
				escribirEn(t, repo, "creds.txt", []byte("token = \""+tokenOculto+"\"\n"))
				gitEn(t, repo, "add", "-A")
			},
		},
		{
			// La huella es `archivo:regla:línea`. No hay que robarla: se escribe.
			nombre: "4) .gitleaksignore con la huella",
			montar: func(t *testing.T, repo string) {
				escribirEn(t, repo, "creds.txt", []byte("token = \""+tokenOculto+"\"\n"))
				escribirEn(t, repo, ".gitleaksignore", []byte("creds.txt:github-pat:1\n"))
				gitEn(t, repo, "add", "-A")
			},
		},
		{
			// El más barato de todos: un comentario pegado al secreto.
			nombre: "5) comentario # gitleaks:allow",
			montar: func(t *testing.T, repo string) {
				escribirEn(t, repo, "creds.txt",
					[]byte("token = \""+tokenOculto+"\" # gitleaks:allow\n"))
				gitEn(t, repo, "add", "-A")
			},
		},
	}
}

func TestUnRepoNoPuedeApagarSuPropiaCompuerta(t *testing.T) {
	for _, a := range ataques() {
		t.Run(a.nombre, func(t *testing.T) {
			repo := repoVacio(t)
			a.montar(t, repo)

			e := &Engine{Mode: "staged"}
			hs, err := e.Run(context.Background(), engines.Input{RepoRoot: repo})
			if err != nil {
				t.Fatalf("la compuerta no debía averiarse, debía encontrar el secreto: %v", err)
			}
			if len(hs) == 0 {
				t.Fatalf("EL SECRETO ENTRA: %s no produjo ni un hallazgo, "+
					"así que `git commit` saldría 0 con la credencial dentro", a.nombre)
			}
			// La ruta tiene que ser la del repo. Devolver la del temporal del
			// reescaneo mandaría al dev a un directorio que ya no existe.
			for _, h := range hs {
				if filepath.IsAbs(h.File) || strings.Contains(h.File, nombreArbol) {
					t.Errorf("la ruta reportada es la del temporal, no la del repo: %q", h.File)
				}
			}
		})
	}
}

// LA CONTRAPARTE, y sin ella el test de arriba no vale: un arnés que bloqueara
// SIEMPRE los pasaría los cinco y arruinaría el producto entero. Estos son los
// commits de todos los días, incluidos los tres que más miedo daban —sólo
// borrado, sólo renombrado y añadir un binario— porque los tres producen
// exactamente la misma señal que los ataques 1 y 2: git no emite contenido.
func TestLosCommitsNormalesSiguenPasando(t *testing.T) {
	casos := []struct {
		nombre string
		montar func(t *testing.T, repo string)
	}{
		{"código normal", func(t *testing.T, repo string) {
			escribirEn(t, repo, "main.go", []byte("package main\n\nfunc main() {}\n"))
			gitEn(t, repo, "add", "-A")
		}},
		{"binario de verdad", func(t *testing.T, repo string) {
			// El caso que descarta la solución fácil: si el criterio fuera
			// "nuestro diff ve texto y gitleaks escaneó ~0 bytes", esto
			// bloquearía, y con ello todo commit que añada una imagen.
			datos := make([]byte, 8192)
			for i := range datos {
				datos[i] = byte(i*7 + i/3)
			}
			escribirEn(t, repo, "foto.bin", datos)
			gitEn(t, repo, "add", "-A")
		}},
		{"sólo borrado", func(t *testing.T, repo string) {
			escribirEn(t, repo, "a.txt", []byte("hola\n"))
			gitEn(t, repo, "add", "-A")
			gitEn(t, repo, "commit", "-m", "base")
			if err := os.Remove(filepath.Join(repo, "a.txt")); err != nil {
				t.Fatal(err)
			}
			gitEn(t, repo, "add", "-A")
		}},
		{"sólo renombrado", func(t *testing.T, repo string) {
			escribirEn(t, repo, "a.txt", []byte("hola\n"))
			gitEn(t, repo, "add", "-A")
			gitEn(t, repo, "commit", "-m", "base")
			gitEn(t, repo, "mv", "a.txt", "b.txt")
		}},
		{"archivo vacío", func(t *testing.T, repo string) {
			escribirEn(t, repo, "vacio.txt", nil)
			gitEn(t, repo, "add", "-A")
		}},
		{"índice vacío", func(t *testing.T, repo string) {
			escribirEn(t, repo, "a.txt", []byte("hola\n"))
			gitEn(t, repo, "add", "-A")
			gitEn(t, repo, "commit", "-m", "base")
		}},
		{"rutas con acentos y espacios", func(t *testing.T, repo string) {
			// La ñ ya apagó el análisis entero una vez, por core.quotePath.
			escribirEn(t, repo, "docs/Plan - Remediación/ñandú.md", []byte("# hola\n"))
			gitEn(t, repo, "add", "-A")
		}},
		{"una línea que empieza por ++", func(t *testing.T, repo string) {
			// Se parece a la cabecera `+++ b/x` del diff. Si el lector la
			// tomara por cabecera, el contenido de después se atribuiría a otro
			// archivo o se perdería, y ahí se escondería un secreto de verdad.
			escribirEn(t, repo, "raro.txt", []byte("++ esto no es una cabecera\n+++ ni esto\n"))
			gitEn(t, repo, "add", "-A")
		}},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			repo := repoVacio(t)
			c.montar(t, repo)
			e := &Engine{Mode: "staged"}
			hs, err := e.Run(context.Background(), engines.Input{RepoRoot: repo})
			if err != nil {
				t.Fatalf("un commit normal no puede averiar la compuerta: %v", err)
			}
			if len(hs) != 0 {
				t.Fatalf("FALSO BLOQUEO en %q: %d hallazgo(s), el primero en %s:%d",
					c.nombre, len(hs), hs[0].File, hs[0].Line)
			}
		})
	}
}

// El reescaneo tiene que apuntar a la línea DEL ARCHIVO, no a la de la copia.
// Sin esta prueba el bloqueo sería correcto y el mensaje mentiroso: manda al dev
// a mirar una línea que no tiene nada.
func TestLaLineaQueSeReportaEsLaDelArchivo(t *testing.T) {
	repo := repoVacio(t)
	// Cuatro líneas de relleno ya commiteadas; el secreto entra en la 5.
	escribirEn(t, repo, "creds.txt", []byte("uno\ndos\ntres\ncuatro\n"))
	escribirEn(t, repo, ".gitattributes", []byte("creds.txt -diff\n"))
	gitEn(t, repo, "add", "-A")
	gitEn(t, repo, "commit", "-m", "base")
	escribirEn(t, repo, "creds.txt",
		[]byte("uno\ndos\ntres\ncuatro\ntoken = \""+tokenOculto+"\"\n"))
	gitEn(t, repo, "add", "-A")

	e := &Engine{Mode: "staged"}
	hs, err := e.Run(context.Background(), engines.Input{RepoRoot: repo})
	if err != nil {
		t.Fatal(err)
	}
	if len(hs) == 0 {
		t.Fatal("el secreto tenía que salir")
	}
	if hs[0].File != "creds.txt" {
		t.Errorf("archivo = %q, se esperaba creds.txt", hs[0].File)
	}
	if hs[0].Line != 5 {
		t.Errorf("línea = %d, se esperaba 5 (la del archivo, no la de la copia)", hs[0].Line)
	}
}

// Las dos pasadas se solapan a propósito, así que el mismo secreto lo ven las
// dos. Si no se dedujera, el dev vería cada credencial dos veces y aprendería a
// no leer la lista.
func TestElMismoSecretoNoSeReportaDosVeces(t *testing.T) {
	repo := repoVacio(t)
	escribirEn(t, repo, "creds.txt", []byte("token = \""+tokenOculto+"\"\n"))
	gitEn(t, repo, "add", "-A")

	e := &Engine{Mode: "staged"}
	hs, err := e.Run(context.Background(), engines.Input{RepoRoot: repo})
	if err != nil {
		t.Fatal(err)
	}
	if len(hs) != 1 {
		for _, h := range hs {
			t.Logf("  %s:%d %s", h.File, h.Line, h.RuleKey)
		}
		t.Fatalf("un secreto, %d hallazgos: las dos pasadas se están sumando sin deduplicar", len(hs))
	}
}
