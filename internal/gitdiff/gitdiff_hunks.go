package gitdiff

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"codeguard/internal/gitref"
)

type LineaAnadida struct {
	Linea int
	Texto string
}

// AnadidasComoTextoStaged y AnadidasComoTextoRango devuelven, por archivo, las
// líneas que el commit AÑADE, leyendo el diff con --text.
//
// EXISTEN PARA VER LO QUE GIT DECIDE NO ENSEÑAR, que es por donde se colaban
// dos secretos enteros (medido contra gitleaks 8.30.1 y git 2.43):
//
//	.gitattributes con `creds.txt -diff`  → el diff normal muestra 0 bytes
//	un byte NUL dentro del archivo        → el diff normal muestra 0 bytes
//
// En los dos casos git declara el archivo binario, no emite contenido, y
// gitleaks —que escanea el parche que git le da— sale con 0 y escribe `[]` sin
// haber mirado el secreto. Los dos ataques VIAJAN CON EL REPO: quien clone se
// queda sin compuerta. Con --text git entrega el contenido igualmente, y ahí
// están las dos líneas del token.
//
// --text NO se le pone al diff principal a propósito: ese diff alimenta el
// informe, el presupuesto y las huellas de paridad, y volcar dentro de él los
// bytes crudos de cada PNG (medido: 2 036 bytes por una imagen de 20 KB) los
// rompería los tres. Esta lectura es aparte y sólo la consume la segunda pasada
// de la compuerta de secretos.
//
// Lo que NO hay que intentar con esto, porque ya se probó y es falso: usar
// «nuestro diff ve texto y gitleaks no» como prueba de sabotaje. Un binario
// legítimo produce exactamente la misma señal —un PNG da 14 líneas añadidas que
// git llama binarias— así que ese criterio bloquearía todo commit que añada una
// imagen. Un NUL plantado y un binario de verdad son indistinguibles por
// estructura; sólo se separan mirando el CONTENIDO, que es lo que hace la
// segunda pasada.
func AnadidasComoTextoStaged(repoRoot string) (map[string][]LineaAnadida, error) {
	return anadidasComoTexto(repoRoot, []string{"--cached"}, nil)
}

func AnadidasComoTextoRango(repoRoot, base, head string) (map[string][]LineaAnadida, error) {
	rango, err := gitref.ValidarRango(base, head)
	if err != nil {
		return nil, fmt.Errorf("rango inválido: %w", err)
	}
	return anadidasComoTexto(repoRoot, nil, []string{rango})
}

func anadidasComoTexto(repoRoot string, banderas, revs []string) (map[string][]LineaAnadida, error) {
	// --unified=0: sin líneas de contexto. Aquí sólo interesa lo que ENTRA en
	// el commit, y el contexto sería contenido ya commiteado que reescanear
	// convertiría deuda vieja en un bloqueo nuevo sin salida (los secretos no
	// se baselinan).
	args := append([]string{"diff", "--no-textconv", "--no-ext-diff", "--no-color", "--text", "--unified=0"}, banderas...)
	if len(revs) > 0 {
		// Mismo blindaje que read(): --end-of-options para que un valor no se
		// lea como opción, y -- para que no se lea como pathspec.
		args = append(args, "--end-of-options")
		args = append(args, revs...)
		args = append(args, "--")
	}
	out, err := run(repoRoot, args...)
	if err != nil {
		return nil, err
	}

	res := make(map[string][]LineaAnadida)
	var archivo string
	var linea int
	// enCabecera distingue el `+++ b/x` que ABRE un archivo de una línea
	// añadida cuyo texto empieza por "++ ". Sin este estado, un commit que
	// añada la línea literal `++ hola` se leería como una cabecera y todo lo
	// que viniera detrás se atribuiría a un archivo llamado "hola" —o se
	// perdería. Sólo `diff --git` abre cabecera, y sólo el primer `+++` de
	// dentro la cierra.
	enCabecera := false
	for _, l := range bytes.Split(out, []byte("\n")) {
		switch {
		case bytes.HasPrefix(l, []byte("diff --git ")):
			enCabecera, archivo, linea = true, "", 0
		case enCabecera && bytes.HasPrefix(l, []byte("+++ ")):
			enCabecera = false
			nombre := strings.TrimSuffix(string(l[4:]), "\r")
			if nombre == "/dev/null" {
				// Borrado: no hay archivo nuevo que escanear.
				continue
			}
			archivo = filepath.ToSlash(strings.TrimPrefix(nombre, "b/"))
		case archivo != "" && bytes.HasPrefix(l, []byte("@@ ")):
			linea = inicioDelHunk(l)
		case archivo != "" && linea > 0 && bytes.HasPrefix(l, []byte("+")):
			res[archivo] = append(res[archivo], LineaAnadida{Linea: linea, Texto: string(l[1:])})
			linea++
		}
	}
	return res, nil
}

// inicioDelHunk saca la primera línea del lado NUEVO de una cabecera
// `@@ -12,0 +13,2 @@`. Devuelve 0 si no la entiende, y con 0 el llamador
// ignora el hunk: preferimos perder un hunk raro a numerar mal y mandar al dev
// a una línea que no es.
func inicioDelHunk(l []byte) int {
	i := bytes.IndexByte(l, '+')
	if i < 0 {
		return 0
	}
	n := 0
	visto := false
	for _, c := range l[i+1:] {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
		visto = true
	}
	if !visto {
		return 0
	}
	return n
}

// ConCambiosSinPreparar devuelve, de entre las rutas dadas, las que en el árbol
// de trabajo NO son iguales a lo que hay en el índice.
//
// EXISTE PORQUE LA COMPUERTA MIRA UNA COSA Y GIT COMMITEA OTRA. `Staged()` saca
// la LISTA de archivos del índice (`git diff --cached`), pero el CONTENIDO que
// analizan los motores por archivo —y la huella `SHA256De` que sirve de clave de
// caché— sale de `os.ReadFile`, o sea del DISCO. Mientras las dos versiones
// coinciden da igual; en cuanto se separan, el análisis habla de un contenido
// que no es el que va a entrar al historial.
//
// Y separarlas es rutina, no un caso raro: `git add -p`, o editar un archivo
// después de haberlo añadido. Medido en un repo de juguete: con B en el índice y
// C en el disco, el sha del índice y el del árbol son completamente distintos.
//
// El efecto no es que entre un secreto —la etapa 1 va por `--cached` y no le
// afecta—, es que se rompe la promesa central: «si pasa aquí, pasa allá». El
// dev ve verde sobre el contenido de su editor y el CI analiza el otro.
//
// ARREGLARLO DE VERDAD ES OTRA COSA, y por eso esto sólo AVISA. Para que los
// motores analizaran el índice habría que materializarlo en un árbol temporal y
// correrlo todo allí: `go vet`, `staticcheck`, `tsc` y `dotnet build` COMPILAN,
// no saben leer un índice de git, así que no basta con cambiar un ReadFile. Es
// una decisión de arquitectura con coste en cada commit, y se toma aparte.
// Mientras tanto, lo que no se puede hacer es callarlo: decir «revisado» sobre
// un contenido distinto del que se commitea es la misma clase de mentira que
// este producto existe para retirar.
func ConCambiosSinPreparar(repoRoot string, rutas []string) ([]string, error) {
	if len(rutas) == 0 {
		return nil, nil
	}
	// `git diff --name-only` sin --cached = árbol de trabajo CONTRA el índice:
	// exactamente los archivos cuyo contenido en disco no es el preparado.
	out, err := run(repoRoot, "diff", "--no-textconv", "--no-ext-diff", "--name-only")
	if err != nil {
		return nil, err
	}
	sucios := make(map[string]bool)
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if l != "" {
			sucios[filepath.ToSlash(l)] = true
		}
	}
	var divergentes []string
	for _, r := range rutas {
		if sucios[filepath.ToSlash(r)] {
			divergentes = append(divergentes, r)
		}
	}
	return divergentes, nil
}

// SHA256De calcula la huella del contenido de un archivo del repo normalizado
// a LF — la MISMA huella que llevan los ChangedFile de un diff. Es la clave
// del caché por archivo (§9): si el hook y `codeguard report` no comparten
// esta definición, cada uno llena su propio caché y ninguno acierta en el del
// otro. Devuelve vacío si el archivo no se puede leer (vacío = no cacheable).
func SHA256De(repoRoot, rel string) string {
	raw, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(rel)))
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(normalizeLF(raw))
	return hex.EncodeToString(sum[:])
}

// Rastreados lista las rutas que git tiene rastreadas, relativas a la raíz.
//
// Los dos argumentos raros son el punto de la función. Por defecto `git
// ls-files` ENTRECOMILLA y escapa en octal cualquier ruta con caracteres no
// ASCII —"docs/obsidian/Telemetr\303\255a y calibraci\303\263n.md"— y quien
// consumía esa salida tal cual acababa pasándole a los motores una ruta que no
// existe. Semgrep, ante una raíz inválida, no se queja de ese archivo: aborta
// el escaneo COMPLETO y devuelve cero hallazgos en un JSON perfectamente
// válido. El informe de este repo decía "0 bloqueantes · COMPLETADO" mientras
// había 28 hallazgos reales, por un único archivo de documentación con acentos
// en el nombre.
//
// El separador NUL (-z) cubre además el nombre con salto de línea, que partir
// por "\n" rompería igual de silenciosamente.
func Rastreados(repoRoot string, patrones ...string) ([]string, error) {
	// core.quotePath ya lo pone `run` para todos: aquí sólo queda el -z, que
	// además protege de nombres con espacios o saltos de línea.
	// El "--" es el separador estándar de pathspecs de git: un patrón que
	// empiece por "-" se leería como opción de ls-files sin él.
	args := append([]string{"ls-files", "-z", "--"}, patrones...)
	out, err := run(repoRoot, args...)
	if err != nil {
		return nil, err
	}
	// Sin TrimSpace: con -z las entradas son exactas, y un nombre puede
	// llevar espacios al principio o al final de forma legítima.
	var rutas []string
	for _, r := range strings.Split(string(out), "\x00") {
		if r != "" {
			rutas = append(rutas, filepath.ToSlash(r))
		}
	}
	return rutas, nil
}

// RepoRoot devuelve la raíz del repo que contiene dir.
func RepoRoot(dir string) (string, error) {
	out, err := run(dir, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
