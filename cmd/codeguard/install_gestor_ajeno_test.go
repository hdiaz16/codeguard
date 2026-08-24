package main

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// `install` apuntaba core.hooksPath a .githooks SIN mirar lo que había antes.
//
// git ejecuta los ganchos de UN solo directorio: el que diga core.hooksPath. En
// un repo con husky o lefthook —o sea, cualquier proyecto Node del equipo— esa
// escritura APAGA los ganchos que el equipo ya tenía, y no lo dice nadie: la
// instalación termina con "CodeGuard instalado en …" y a partir de ahí sus
// lint-staged, sus commitlint y sus pruebas de pre-commit dejan de correr.
//
// Es exactamente lo que este producto existe para evitar: hacer algo importante
// en silencio. Y duele más aquí que en otros sitios, porque lo que se apaga es
// la protección que el equipo ya había elegido.
//
// Se prueba por el EFECTO sobre el repo —qué quedó en git config y qué ficheros
// se crearon— y no por lo que imprime la función: lo que le importa a un equipo
// con husky es que su configuración siga en pie.

// repoConHooksPath deja un repo git recién creado con el core.hooksPath que se
// pida, y devuelve la ruta del repo.
func repoConHooksPath(t *testing.T, valor string) string {
	t.Helper()
	repo := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q", "."},
		{"config", "user.email", "prueba@codeguard.local"},
		{"config", "user.name", "prueba"},
	} {
		c := exec.Command("git", args...)
		c.Dir = repo
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	if valor != "" {
		c := exec.Command("git", "config", "core.hooksPath", valor)
		c.Dir = repo
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git config core.hooksPath %s: %v: %s", valor, err, out)
		}
	}
	// La instalación registra el proyecto en %LOCALAPPDATA%: a un temporal, que
	// una prueba no tiene por qué aparecer en el panel de quien la corre.
	t.Setenv("LOCALAPPDATA", t.TempDir())
	t.Chdir(repo)
	return repo
}

// hooksPathDe lee el valor efectivo, que es lo que git va a obedecer.
func hooksPathDe(t *testing.T, repo string) string {
	t.Helper()
	out, err := exec.Command("git", "-C", repo, "config", "--get", "core.hooksPath").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// capturarStdout devuelve lo que fn imprimió por la salida estándar.
func capturarStdout(t *testing.T, fn func() error) (salida string, err error) {
	t.Helper()
	viejo := os.Stdout
	r, w, perr := os.Pipe()
	if perr != nil {
		t.Fatal(perr)
	}
	os.Stdout = w
	hecho := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		hecho <- string(b)
	}()
	defer func() {
		_ = w.Close()
		os.Stdout = viejo
		salida = <-hecho
	}()
	return "", fn()
}

// correrInstall ejecuta el comando de verdad y devuelve lo que imprimió y el
// error mediante buffers inyectados, sin mutar os.Stdout global.
func correrInstall(t *testing.T, sustituir bool) (string, error) {
	t.Helper()
	cmd := installCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	if sustituir {
		if ferr := cmd.Flags().Set(banderaSustituir, "true"); ferr != nil {
			t.Fatalf("la bandera --%s no existe: %v", banderaSustituir, ferr)
		}
	}
	err := cmd.RunE(cmd, nil)
	return buf.String(), err
}

func TestInstallNoPisaLosGanchosDeOtroGestor(t *testing.T) {
	casos := []struct {
		nombre string
		valor  string
		marca  string // fichero que delata al gestor, si hace falta
		gestor string // nombre que el mensaje tiene que decir
	}{
		{nombre: "husky", valor: ".husky", gestor: "husky"},
		{nombre: "husky v9", valor: ".husky/_", gestor: "husky"},
		{nombre: "lefthook", valor: ".lefthook", gestor: "lefthook"},
		{nombre: "lefthook por su config", valor: ".git/hooks", marca: "lefthook.yml", gestor: "lefthook"},
		{nombre: "pre-commit", valor: ".git/hooks", marca: ".pre-commit-config.yaml", gestor: "pre-commit"},
		// Un gestor que no reconocemos NO es un permiso para pisarlo: el valor
		// está ahí porque alguien lo puso a propósito.
		{nombre: "gestor desconocido", valor: "herramientas/ganchos", gestor: ""},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			repo := repoConHooksPath(t, c.valor)
			if c.marca != "" {
				escribirEnRepo(t, filepath.Join(repo, c.marca), "# marca de la prueba\n")
			}

			salida, err := correrInstall(t, false)

			if err == nil {
				t.Fatalf("install se instaló sobre un repo con core.hooksPath = %q y salió con éxito.\n"+
					"Los ganchos que ese repo ya tenía acaban de dejar de correr y nadie se enteró.\n"+
					"salida:\n%s", c.valor, salida)
			}
			msg := err.Error()

			// 1. No tocó NADA. La comprobación va antes de cualquier escritura.
			if v := hooksPathDe(t, repo); v != c.valor {
				t.Errorf("core.hooksPath pasó de %q a %q: se negó a instalar pero ya había pisado la config", c.valor, v)
			}
			for _, rastro := range []string{".githooks", ".gitattributes"} {
				if _, serr := os.Stat(filepath.Join(repo, rastro)); serr == nil {
					t.Errorf("se negó a instalar pero dejó %s en el repo: negarse tiene que ser no tocar nada", rastro)
				}
			}

			// 2. El mensaje dice QUÉ encontró.
			if !strings.Contains(msg, c.valor) {
				t.Errorf("el mensaje no dice el valor que encontró (%q), así que el usuario no sabe qué le paró:\n%s", c.valor, msg)
			}
			// 3. …y QUIÉN es, cuando se puede reconocer.
			//
			// Se exige "parece <gestor>" y no el nombre suelto: buscar
			// "pre-commit" a secas daba por bueno un mensaje que NO lo había
			// reconocido, porque pre-commit es además el nombre del gancho de
			// git y sale en la línea de cómo encadenarlo. Medido con un mutante
			// —quitar el reconocimiento por ficheros— que la prueba dejó vivo.
			if c.gestor != "" && !strings.Contains(msg, "parece "+c.gestor) {
				t.Errorf("el mensaje no nombra a %s, que es lo que el valor %q delata:\n%s", c.gestor, c.valor, msg)
			}
			// 4. …y QUÉ HACER. Un aviso sin salida es un muro.
			if !strings.Contains(msg, "--"+banderaSustituir) {
				t.Errorf("el mensaje no dice cómo sustituirlo a propósito (--%s):\n%s", banderaSustituir, msg)
			}
		})
	}
}

// Reinstalar sobre lo nuestro es el camino de todos los días: `codeguard
// install` se corre en cada repo que se enrola y se vuelve a correr al
// actualizar el binario. Ahí no hay conflicto que anunciar, y un aviso en ese
// caso enseñaría a ignorar el aviso de verdad.
func TestInstallReinstalaSobreLoNuestroSinRuido(t *testing.T) {
	casos := []struct{ nombre, valor string }{
		{"sin nada configurado", ""},
		{"ya instalado", ".githooks"},
		// Otra forma de escribir el MISMO directorio. Comparar el texto a pelo
		// haría que esto pareciera un gestor ajeno, y negarse a reinstalar sobre
		// nosotros mismos es un fallo del camino de todos los días.
		{"el mismo directorio escrito de otra forma", "./.githooks"},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			repo := repoConHooksPath(t, c.valor)

			salida, err := correrInstall(t, false)
			if err != nil {
				t.Fatalf("la instalación normal falló con core.hooksPath = %q: %v\n%s", c.valor, err, salida)
			}
			if v := hooksPathDe(t, repo); v != ".githooks" {
				t.Errorf("tras instalar, core.hooksPath = %q y debería ser .githooks: los ganchos no correrían", v)
			}
			if _, serr := os.Stat(filepath.Join(repo, ".githooks", "pre-commit")); serr != nil {
				t.Errorf("no se escribieron los ganchos: %v", serr)
			}
			for _, ruido := range []string{"otro gestor", "no toco nada", "--" + banderaSustituir} {
				if strings.Contains(strings.ToLower(salida), strings.ToLower(ruido)) {
					t.Errorf("la instalación normal habla de un conflicto que no existe (%q):\n%s", ruido, salida)
				}
			}
		})
	}
}

// Un git que no puede contestar NO es un repo sin gestor de ganchos.
//
// git sale con 1 cuando la clave no está —el caso de todos los días— y con 128
// cuando no pudo ni mirar: repo roto, config ilegible, permisos. Tratar los dos
// igual es la trampa de siempre en este producto: "no encontré nada" y "no pude
// mirar" se ven idénticos desde fuera, y aquí el precio de confundirlos es
// escribir encima de un gestor que existía y que no llegamos a leer.
//
// Se prueba la función y no el comando porque con el repo roto `install` ni
// siquiera llega hasta aquí: falla antes al buscar la raíz, y una prueba por el
// comando pasaría sin ejercitar esta rama.
func TestUnGitQueNoContestaNoEsPermisoParaInstalar(t *testing.T) {
	roto := t.TempDir()
	escribirEnRepo(t, filepath.Join(roto, ".git"), "gitdir: /no/existe/en/ninguna/parte\n")

	g, err := hooksPathVigente(roto)

	if err == nil {
		t.Errorf("git no pudo leer la config y hooksPathVigente devolvió %+v sin error: "+
			"el que sigue instala a ciegas sobre lo que no pudo mirar", g)
	}
	if g != nil {
		t.Errorf("devolvió un gestor (%+v) a partir de una lectura que falló", g)
	}
}

// Un core.hooksPath GLOBAL no se restaura escribiéndolo en el repo.
//
// El consejo "vuelve con `git config core.hooksPath .husky`" es correcto para un
// valor local y falso para uno global: deja un override local que tapa la config
// del usuario para siempre, así que el día que cambie su global este repo no se
// entera. Lo que restaura es QUITAR el nuestro y dejar que se vea el de debajo.
//
// La config global de la prueba va a un fichero temporal por GIT_CONFIG_GLOBAL:
// una prueba no escribe en el ~/.gitconfig de quien la corre.
func TestElConsejoParaVolverDependeDelAmbito(t *testing.T) {
	repo := repoConHooksPath(t, "") // sin valor local: el que manda es el global
	global := filepath.Join(t.TempDir(), "gitconfig-de-prueba")
	escribirEnRepo(t, global, "[core]\n\thooksPath = .husky\n")
	t.Setenv("GIT_CONFIG_GLOBAL", global)

	if v := hooksPathDe(t, repo); v != ".husky" {
		t.Fatalf("la prueba no montó bien el escenario: core.hooksPath = %q", v)
	}

	_, err := correrInstall(t, false)
	if err == nil {
		t.Fatal("install pisó un core.hooksPath global sin decir nada")
	}
	msg := err.Error()

	if !strings.Contains(msg, "git config --unset core.hooksPath") {
		t.Errorf("con el valor en la config global, el mensaje no dice que se vuelve QUITANDO "+
			"el nuestro:\n%s", msg)
	}
	if strings.Contains(msg, "git config core.hooksPath .husky") {
		t.Errorf("el mensaje manda a escribir el valor global en el repo: eso no restaura nada, "+
			"deja un override local que tapa la config del usuario para siempre:\n%s", msg)
	}
	if !strings.Contains(msg, "global") {
		t.Errorf("el mensaje no dice que el valor viene de la config global, que es lo que "+
			"explica por qué aparece en un repo donde nadie lo puso:\n%s", msg)
	}
}

// `status` mandaba al desastre con un ✗ bien intencionado: en un repo con husky
// leía core.hooksPath, veía que no era `.githooks`, y escribía "core.hooksPath
// sin configurar → `codeguard install`". Ni estaba sin configurar —estaba
// configurado por otro— ni ese comando era la salida: era justo la orden que
// apagaba husky.
//
// Ahora que `install` se niega, ese consejo además no lleva a ninguna parte: el
// usuario va del ✗ al comando y del comando de vuelta al ✗. Un diagnóstico
// tiene que decir lo que hay, y el remedio tiene que poder ejecutarse.
func TestStatusNoConfundeUnGestorAjenoConFaltaDeConfiguracion(t *testing.T) {
	repo := repoConHooksPath(t, ".husky")

	salida, _ := capturarStdout(t, func() error { revisarRepo(repo); return nil })

	linea := ""
	for _, l := range strings.Split(salida, "\n") {
		if campos := strings.Fields(l); len(campos) > 1 && campos[1] == "hooksPath" {
			linea = l
		}
	}
	if linea == "" {
		t.Fatalf("status no dijo nada de hooksPath:\n%s", salida)
	}
	if strings.Contains(linea, "sin configurar") {
		t.Errorf("status llama «sin configurar» a un core.hooksPath que otro gestor puso a propósito:\n%s", linea)
	}
	if !strings.Contains(linea, ".husky") {
		t.Errorf("status no dice a dónde apunta core.hooksPath, que es el dato entero:\n%s", linea)
	}
	// El remedio que propone tiene que ser uno que no se niegue.
	if strings.Contains(linea, "codeguard install") && !strings.Contains(linea, "--"+banderaSustituir) {
		t.Errorf("status manda a `codeguard install`, que en este repo se niega: "+
			"el usuario da la vuelta y vuelve aquí:\n%s", linea)
	}
}

// La bandera existe para el equipo que decide cambiarse. Sustituir SÍ, en
// silencio NO: quien la usa tiene que salir de ahí sabiendo qué apagó y cómo
// volver, porque el valor viejo desaparece de git config al escribir el nuestro.
func TestInstallConLaBanderaSustituyeYLoDice(t *testing.T) {
	repo := repoConHooksPath(t, ".husky")

	salida, err := correrInstall(t, true)
	if err != nil {
		t.Fatalf("con --%s la instalación tenía que seguir adelante: %v\n%s", banderaSustituir, err, salida)
	}
	if v := hooksPathDe(t, repo); v != ".githooks" {
		t.Fatalf("con --%s core.hooksPath quedó en %q: la bandera no hizo lo que dice", banderaSustituir, v)
	}
	for _, exigido := range []string{"husky", ".husky"} {
		if !strings.Contains(salida, exigido) {
			t.Errorf("sustituyó los ganchos de husky sin nombrar %q en la salida:\n%s", exigido, salida)
		}
	}
	// Cómo volver. Es el único sitio donde queda escrito el valor que se pisó.
	if !strings.Contains(salida, "core.hooksPath .husky") {
		t.Errorf("la salida no dice cómo devolver los ganchos a su gestor "+
			"(`git config core.hooksPath .husky`), y ese valor ya no está en ningún otro sitio:\n%s", salida)
	}
}
