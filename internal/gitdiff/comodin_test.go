package gitdiff

import (
	"strings"
	"testing"
)

// El tercer modo de leer el argumento, que ni H009 ni H021 contemplaron.
//
// Las dos vueltas anteriores cerraron que el valor se leyera como OPCIÓN
// (--end-of-options) y que llegara a git sin validar (gitref). Quedaba abierto
// que git lo leyera como RUTA: cuando no puede resolver "A..B" como rango, no
// falla — cae a pathspec. Y ahí está la asimetría, medida contra git 2.43:
//
//	<sha>..noexiste  → exit 128  fatal: ambiguous argument
//	<sha>..*         → exit 0    (salida vacía)
//
// Un pathspec sin comodín tiene que existir; uno CON comodín no. Así que
// `--head "*"` devolvía cero archivos CON ÉXITO, el pipeline cortaba en la
// etapa 0 con "todos los archivos tocados están excluidos", y la compuerta de
// secretos no llegaba a correr: EXIT 0, commit permitido, secreto sin mirar.
//
// Es el mismo desenlace que H021 pero por una puerta distinta, y por eso la
// validación rechazó el arreglo dos veces: el criterio de gitref no podía
// verlo, porque un comodín no empieza por '-', no lleva espacios y es
// perfectamente imprimible.
//
// Lo cierra el `--` de read, que le quita a git ese tercer modo. Y no hace
// falta un atacante: un `--head "v1.*"` mal escrito en un workflow dejaba el
// CI en verde perpetuo sin decir una palabra.
func TestUnComodinNoPuedeVaciarElDiffEnSilencio(t *testing.T) {
	repo := repoDePrueba(t)
	escribir(t, repo, "secreto.txt", "AWS_SECRET=no-deberia-pasar\n")
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-q", "-m", "segundo")

	// El control primero: si el rango honesto no viera el archivo, el resto de
	// la prueba no distinguiría "bloqueado" de "aquí no hay nada".
	d, err := Range(repo, "HEAD~1", "HEAD")
	if err != nil {
		t.Fatalf("el rango honesto debió leerse: %v", err)
	}
	if len(d.Files) != 1 {
		t.Fatalf("el control esperaba 1 archivo, hubo %d: la prueba no probaría nada", len(d.Files))
	}

	comodines := []string{"*", "?", "release/*", "v1.*", "feature/[abc]", "no/existe*"}
	for _, c := range comodines {
		t.Run("head_"+c, func(t *testing.T) {
			exigirRechazo(t, repo, "HEAD~1", c)
		})
		t.Run("base_"+c, func(t *testing.T) {
			exigirRechazo(t, repo, c, "HEAD")
		})
	}
}

// exigirRechazo comprueba lo único que importa: que un rango que git no puede
// resolver NO produzca "cero archivos y todo bien". Da igual si lo para gitref
// antes o git después; lo que no puede pasar es que salga un diff vacío sin
// error, porque eso aguas arriba se lee como "no había nada que revisar".
func exigirRechazo(t *testing.T, repo, base, head string) {
	t.Helper()
	d, err := Range(repo, base, head)
	if err != nil {
		return // rechazado: es el desenlace correcto
	}
	if len(d.Files) == 0 {
		t.Fatalf("%s..%s devolvió un diff VACÍO sin error: la compuerta de secretos "+
			"no llegaría a correr y el commit pasaría con EXIT 0", base, head)
	}
	t.Fatalf("%s..%s se resolvió como un rango legítimo (%d archivos), que no es lo que nadie quiso",
		base, head, len(d.Files))
}

// La contraparte, para que el arreglo no pueda "conseguirse" rechazándolo todo:
// las refs legítimas —incluidas las que llevan acentos, que ya nos costaron un
// rechazo— siguen resolviéndose con el `--` puesto.
func TestElCierreNoRompeLasRefsLegitimas(t *testing.T) {
	repo := repoDePrueba(t)
	escribir(t, repo, "nuevo.go", "package p\n\nfunc Nuevo() {}\n")
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-q", "-m", "segundo")

	for _, rama := range []string{"corrección-h009", "feature/validación", "rama-con-ñ"} {
		git(t, repo, "branch", rama)
	}

	for _, head := range []string{"HEAD", "corrección-h009", "feature/validación", "rama-con-ñ"} {
		d, err := Range(repo, "HEAD~1", head)
		if err != nil {
			t.Errorf("HEAD~1..%s debió leerse y falló: %v", head, err)
			continue
		}
		if len(d.Files) != 1 || d.Files[0].Path != "nuevo.go" {
			t.Errorf("HEAD~1..%s: se esperaba nuevo.go, se obtuvo %+v", head, d.Files)
		}
		if !strings.Contains(d.Unified, "func Nuevo()") {
			t.Errorf("HEAD~1..%s: el diff unificado no trae el cambio", head)
		}
	}
}
