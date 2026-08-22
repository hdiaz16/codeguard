package gitdiff

import (
	"bytes"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"codeguard/internal/engines/proc"
	"codeguard/internal/gitref"
)

type ChangedFile struct {
	Path   string // relativo a la raíz del repo, separador /
	Status string // A, M, D, R...
	SHA256 string // del contenido normalizado a LF; vacío si el archivo fue borrado
}

type Diff struct {
	Files   []ChangedFile
	Unified string // diff completo normalizado a LF
	Lines   int    // líneas de diff (aprox: añadidas + eliminadas)
}

// run invoca git con core.quotePath desactivado.
//
// Por defecto git ENTRECOMILLA y escapa en octal cualquier ruta con bytes no
// ASCII: `docs/Plan - Remediación.md` sale como
//
//	"docs/Plan - Remediaci\303\263n.md"
//
// —con las comillas dentro de la cadena— y esa cadena literal, comillas y
// todo, viajaba tal cual hasta los motores como si fuera una ruta. semgrep
// respondía `Invalid scanning root` y moría, y con él se caía el análisis
// ENTERO del commit: no el archivo con acento, los 230. El commit pasaba con
// una línea de "capas no revisadas: semgrep:error" y las 119 reglas de la casa
// sin aplicar.
//
// En un equipo que escribe en español esto no es un caso raro, es el martes.
// Y falla de la peor manera posible: un solo archivo con ñ o acento en el
// nombre apaga la compuerta para todo lo demás, en silencio salvo por una
// línea que nadie lee.
//
// core.quotePath=false hace que git emita los bytes UTF-8 tal cual, que es lo
// que Go y los motores esperan.
//
// Va en `run` y no en cada llamada por lo que enseñó este fallo: la bandera YA
// estaba puesta en `Rastreados`, con su prueba y todo, desde que alguien se
// topó con esto. Nadie la puso en `read`, que es justo la que corre en cada
// commit. Un arreglo que no se generaliza deja el mismo agujero abierto al
// lado, y encima con la falsa tranquilidad de que "eso ya lo arreglamos".
//
// Alcance, para que quede dicho: esto cubre los no-ASCII, que es lo que
// rompía. Git sigue entrecomillando rutas con comillas dobles o saltos de
// línea, pero Windows no permite esos caracteres en un nombre de archivo y
// CodeGuard sólo se distribuye para Windows. El día que haya build de Linux,
// esto necesita `-z` como ya hace `Rastreados`.
//
// El entorno va acotado como el de cualquier otro motor. git es el hijo que más
// veces se lanza —cada commit pasa por aquí— y heredaba el entorno completo del
// proceso, con la clave del modelo dentro; ninguna de las operaciones que se le
// piden (diff, ls-files, rev-parse) habla con ningún servicio ni la necesita.
// EntornoGit conserva las GIT_*, que son las que le dicen qué índice está
// mirando: filtrarlas cambiaría en silencio QUÉ se analiza en un `git commit -a`.
func run(repoRoot string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", append([]string{"-c", "core.quotePath=false"}, args...)...)
	proc.SinVentana(cmd)
	cmd.Dir = repoRoot
	cmd.Env = proc.EntornoGit()
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, errb.String())
	}
	return out.Bytes(), nil
}

func normalizeLF(b []byte) []byte {
	return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
}

// Range lee el diff base..head (modo ci).
//
// base y head son lo ÚNICO que entra aquí desde fuera: son los flags
// --base/--head de `codeguard ci`, que en el CI se rellenan desde el workflow.
// Se validan antes de tocar la línea de comandos porque sin eso git no ve un
// rango, ve opciones suyas — y ahí empieza H021.
//
// Lo que pasaba, y es peor que un escaneo torcido: con --base "--output=/ruta",
// `git diff` acepta la opción, ESCRIBE el archivo que le digan y devuelve exit
// 0 con cero archivos cambiados. Range no daba error, main.go seguía adelante,
// y el pipeline cortaba en la etapa 0 —"todos los archivos tocados están
// excluidos", veredicto Skipped— sin llegar NUNCA a la etapa de secretos. El
// proceso terminaba en EXIT 0 con el secreto sin detectar.
//
// Por eso la validación tiene que estar TAMBIÉN aquí y no sólo en el motor de
// gitleaks: main.go llama a Range antes de montar el pipeline, así que una
// frontera puesta únicamente en el motor se salta sin tocarla, simplemente
// haciendo que no haya nada que analizar. Ese es el modo de fallo que más caro
// ha salido en este repo: la compuerta no se fuerza, se deja sin trabajo.
//
// El criterio de validez es el de internal/gitref, compartido con el motor de
// secretos para que las dos fronteras no se separen con el tiempo.
func Range(repoRoot, base, head string) (*Diff, error) {
	rango, err := gitref.ValidarRango(base, head)
	if err != nil {
		return nil, fmt.Errorf("rango inválido: %w", err)
	}
	return read(repoRoot, nil, []string{rango})
}

// Staged lee el diff del índice (modo hook, fase 2).
func Staged(repoRoot string) (*Diff, error) {
	return read(repoRoot, []string{"--cached"}, nil)
}

// read arma las dos pasadas de `git diff`. banderas son opciones fijas del
// código; revs son los argumentos POSICIONALES, que en el modo ci vienen de
// fuera y son los que hay que blindar.
//
// De ahí la separación, que antes no existía: --end-of-options le dice a git
// que a partir de ahí no hay más opciones, pase lo que pase, así que un valor
// como "--output=/ruta" se queda en argumento y no en bandera aunque la
// validación de arriba fallara o la olvidara un llamador nuevo. Comprobado
// contra git 2.43: sin él, git crea el archivo; con él, muere con exit 128 sin
// escribir nada.
//
// Obliga a poner TODAS las banderas delante (git rechaza una opción que venga
// detrás de un argumento posicional), que es el porqué de que --name-status y
// --cached ya no se peguen al final.
//
// Y sólo se añade cuando hay algo posicional que proteger: en el modo staged no
// entra nada de fuera, así que meterlo ahí no ganaría nada y le pediría git
// 2.24 o superior al camino que corre en CADA commit.
func read(repoRoot string, banderas, revs []string) (*Diff, error) {
	// --no-textconv --no-ext-diff: paridad del hash entre máquinas (sección 4.1).
	common := append([]string{"diff", "--no-textconv", "--no-ext-diff", "--no-color"}, banderas...)
	armar := func(modo string) []string {
		args := append(append([]string{}, common...), modo)
		if len(revs) > 0 {
			args = append(args, "--end-of-options")
			args = append(args, revs...)
			// El `--` de cierre no es redundante con --end-of-options: cortan
			// cosas distintas. --end-of-options impide que un valor se lea como
			// OPCIÓN; el `--` impide que se lea como RUTA.
			//
			// git tiene un tercer modo para este argumento que no es ni opción
			// ni revisión: si no puede resolver "A..B" como rango, cae a
			// pathspec. Y ahí está la asimetría que lo abría — medido contra
			// git 2.43:
			//
			//	<sha>..noexiste  → exit 128  fatal: ambiguous argument
			//	<sha>..*         → exit 0    (salida vacía)
			//
			// Un pathspec sin comodín tiene que existir; uno CON comodín no.
			// Así que un `--head "*"` devolvía cero archivos con éxito, el
			// pipeline cortaba en la etapa 0 con "todos los archivos tocados
			// están excluidos", y la compuerta de secretos no llegaba a correr:
			// commit permitido, secreto sin mirar, y ni una palabra.
			//
			// Con el `--` git se queda sin ese tercer modo y falla ruidosamente.
			// Y no hace falta un atacante: un `--head "v1.*"` mal escrito en un
			// workflow dejaba el CI en verde perpetuo.
			args = append(args, "--")
		}
		return args
	}

	nameStatus, err := run(repoRoot, armar("--name-status")...)
	if err != nil {
		return nil, err
	}
	unified, err := run(repoRoot, armar("--unified=3")...)
	if err != nil {
		return nil, err
	}
	unifiedLF := normalizeLF(unified)

	d := &Diff{Unified: string(unifiedLF)}
	for _, line := range strings.Split(strings.TrimSpace(string(nameStatus)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 2 {
			continue
		}
		status := parts[0][:1]
		path := parts[len(parts)-1] // en renames (R100\told\tnew) el destino es el último campo
		cf := ChangedFile{Path: filepath.ToSlash(path), Status: status}
		if status != "D" {
			cf.SHA256 = SHA256De(repoRoot, path)
		}
		d.Files = append(d.Files, cf)
	}
	for _, l := range strings.Split(d.Unified, "\n") {
		if len(l) > 0 && (l[0] == '+' || l[0] == '-') && !strings.HasPrefix(l, "+++") && !strings.HasPrefix(l, "---") {
			d.Lines++
		}
	}
	return d, nil
}

// LineaAnadida es una línea que el diff AÑADE, con el número que ocupa en el
// archivo resultante — no en el parche.
