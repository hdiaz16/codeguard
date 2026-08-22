package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// nuestro.
type gestorDeGanchos struct {
	Valor  string // tal cual lo tiene git: es lo que el usuario reconoce
	Ambito string // local | global | system | worktree, como lo dice git
	Nombre string // husky | lefthook | pre-commit, o "" si no se reconoce
}

// hooksPathVigente devuelve el core.hooksPath que git obedece hoy en este repo,
// o nil si no hay ninguno.
//
// git ejecuta los ganchos de UN solo directorio, así que escribir core.hooksPath
// no es añadir: es sustituir. Sin esta lectura previa, `install` apagaba husky o
// lefthook y terminaba diciendo "CodeGuard instalado" — el equipo se quedaba sin
// su lint-staged ni su commitlint y no había forma de enterarse salvo notar que
// dejaron de saltar.
//
// Se lee con --show-scope porque el ámbito cambia el consejo: un valor local se
// devuelve escribiéndolo otra vez, y uno global NO —ahí lo que hay que quitar es
// el local que le pusimos encima—. Un consejo que no restaura es peor que
// ninguno: el usuario cree que ya lo arregló.
//
// Lo usan dos comandos con preguntas distintas: `install` quiere saber si hay
// alguien a quien estaría apagando, y `status` necesita además distinguir "no
// hay nada" de "es el nuestro", que para el usuario son un ✗ y un ✓.
func hooksPathVigente(repoRoot string) (*gestorDeGanchos, error) {
	out, err := gitCmd("-C", repoRoot, "config", "--show-scope", "--get", "core.hooksPath").Output()
	if err != nil {
		// Salir con 1 es "esa clave no está", que es el caso de todos los días.
		// Cualquier otro código es git diciendo que no pudo contestar, y ahí NO
		// se puede seguir: instalar sería escribir encima de algo que no
		// llegamos a leer, justo lo que este bloque existe para impedir.
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 1 {
			return nil, nil
		}
		// Con lo que git haya dicho: sin su stderr, un `--show-scope` que no
		// existe (git anterior a 2.26) se lee aquí como "exit status 129" y no
		// hay forma de saber qué pasó.
		detalle := ""
		if ee != nil {
			detalle = ": " + strings.TrimSpace(string(ee.Stderr))
		}
		return nil, fmt.Errorf("no pude leer core.hooksPath de %s (%v%s).\n"+
			"No instalo nada: no sé si este repo ya tiene otro gestor de ganchos al que estaría apagando",
			repoRoot, err, detalle)
	}
	ambito, valor, _ := strings.Cut(strings.TrimRight(string(out), "\r\n"), "\t")
	valor = strings.TrimSpace(valor)
	if valor == "" {
		return nil, nil
	}
	return &gestorDeGanchos{
		Valor:  valor,
		Ambito: strings.TrimSpace(ambito),
		Nombre: reconocerGestor(repoRoot, valor),
	}, nil
}

// hooksPathAjeno es el vigente cuando NO es el nuestro: exactamente los casos en
// los que instalar apaga los ganchos de alguien.
func hooksPathAjeno(repoRoot string) (*gestorDeGanchos, error) {
	g, err := hooksPathVigente(repoRoot)
	if err != nil || g == nil || g.esNuestro(repoRoot) {
		return nil, err
	}
	return g, nil
}

// esNuestro decide si ese core.hooksPath ya apunta a .githooks.
//
// Reinstalar sobre lo nuestro es el camino de todos los días —se corre en cada
// repo que se enrola y otra vez al actualizar el binario—, así que aquí un falso
// negativo rompe el uso normal: pediría --sustituir-hooks para pisarnos a
// nosotros mismos.
func (g *gestorDeGanchos) esNuestro(repoRoot string) bool {
	nuestro := filepath.Join(repoRoot, dirGanchos)
	ruta := filepath.FromSlash(g.Valor)
	if !filepath.IsAbs(ruta) {
		// git resuelve un core.hooksPath relativo desde la raíz del árbol.
		ruta = filepath.Join(repoRoot, ruta)
	}
	if filepath.Clean(ruta) == filepath.Clean(nuestro) {
		return true
	}
	// Y si los dos existen, que conteste el sistema de ficheros. En Windows el
	// mismo directorio se escribe con otra caja o en formato corto (HECTOR~1) y
	// comparar el texto diría que son distintos.
	a, errA := os.Stat(ruta)
	b, errB := os.Stat(nuestro)
	return errA == nil && errB == nil && os.SameFile(a, b)
}

// reconocerGestor pone nombre al valor cuando se puede. No reconocerlo NO es
// permiso para pisarlo: ese valor está ahí porque alguien lo puso.
func reconocerGestor(repoRoot, valor string) string {
	v := strings.TrimPrefix(strings.ToLower(filepath.ToSlash(valor)), "./")
	switch {
	// husky v8 usa .husky y v9 apunta a .husky/_, donde deja sus envoltorios.
	case v == ".husky" || strings.HasPrefix(v, ".husky/"):
		return "husky"
	case strings.Contains(v, "lefthook"):
		return "lefthook"
	}
	// El valor no siempre delata: lefthook y pre-commit saben trabajar sobre
	// .git/hooks, que es el directorio de siempre. Ahí pregunta el repo.
	for _, m := range []struct{ marca, nombre string }{
		{".husky", "husky"},
		{"lefthook.yml", "lefthook"},
		{"lefthook.yaml", "lefthook"},
		{".lefthook.yml", "lefthook"},
		{".pre-commit-config.yaml", "pre-commit"},
		{".pre-commit-config.yml", "pre-commit"},
	} {
		if _, err := os.Stat(filepath.Join(repoRoot, m.marca)); err == nil {
			return m.nombre
		}
	}
	return ""
}

func (g *gestorDeGanchos) quien() string {
	if g.Nombre == "" {
		return "no reconozco qué lo puso"
	}
	return "parece " + g.Nombre
}

func (g *gestorDeGanchos) nombreCorto() string {
	if g.Nombre == "" {
		return "ese gestor"
	}
	return g.Nombre
}

func (g *gestorDeGanchos) ambitoLegible() string {
	switch g.Ambito {
	case "local":
		return "config local del repo"
	case "global":
		return "config global de tu usuario"
	case "system":
		return "config del sistema"
	case "worktree":
		return "config de este worktree"
	}
	return "config de git"
}

// comoVolver es la orden que devuelve los ganchos a su gestor. Depende del
// ámbito: sobre un valor global, escribirlo en el repo NO restaura nada —deja un
// override local que tapa la config del usuario para siempre—; lo que restaura
// es quitar el nuestro.
func (g *gestorDeGanchos) comoVolver() string {
	if g.Ambito == "local" || g.Ambito == "worktree" || g.Ambito == "" {
		return "git config core.hooksPath " + g.Valor
	}
	return "git config --unset core.hooksPath"
}

// comoEncadenar dice cómo llamar a CodeGuard SIN quitarle el mando al otro
// gestor. Lo hace el usuario en su config, no nosotros por detrás: orquestar los
// ganchos de otro producto significa que, el día que algo falle, quien commitea
// no sabrá a quién culpar.
func (g *gestorDeGanchos) comoEncadenar() string {
	switch g.Nombre {
	case "husky":
		return "añade `codeguard hook pre-commit \"$@\"` a .husky/pre-commit (y a prepare-commit-msg y post-commit)"
	case "lefthook":
		return "añade un comando `run: codeguard hook pre-commit` en pre-commit de tu lefthook.yml"
	case "pre-commit":
		return "añade a .pre-commit-config.yaml un hook `repo: local` que ejecute `codeguard hook pre-commit`"
	}
	return "llama a `codeguard hook pre-commit \"$@\"` desde tus ganchos de " + g.Valor
}

// explicar es el mensaje de la negativa. Dice qué hay, por qué no lo piso, y las
// tres salidas reales — incluida la de no instalarnos, que a veces es la buena.
// El comando se pasa porque este texto sale igual desde `install` que desde
// `init`, y mandar a alguien al comando equivocado convierte el aviso en ruido.
func (g *gestorDeGanchos) explicar(comando string) string {
	var b strings.Builder
	b.WriteString("este repo ya tiene otro gestor de ganchos y apagarlo no es decisión mía\n\n")
	fmt.Fprintf(&b, "  core.hooksPath = %s   (%s · %s)\n\n", g.Valor, g.quien(), g.ambitoLegible())
	b.WriteString("No he tocado nada. git ejecuta los ganchos de UN solo directorio: si apunto\n")
	fmt.Fprintf(&b, "core.hooksPath a %s, lo que %s revisa hoy deja de correr y nadie recibe\n", dirGanchos, g.nombreCorto())
	b.WriteString("un aviso — los commits siguen saliendo como si nada.\n\n")
	b.WriteString("Puedes:\n")
	b.WriteString("  1) dejarlo así: no instalo nada y tus ganchos siguen intactos\n")
	fmt.Fprintf(&b, "  2) cambiarte a CodeGuard:  codeguard %s --%s\n", comando, banderaSustituir)
	fmt.Fprintf(&b, "     (los ganchos de %s dejan de correr; se vuelve con `%s`)\n", g.nombreCorto(), g.comoVolver())
	fmt.Fprintf(&b, "  3) convivir: que siga mandando %s y llame a CodeGuard desde sus ganchos.\n", g.nombreCorto())
	fmt.Fprintf(&b, "     %s\n", g.comoEncadenar())
	fmt.Fprintf(&b, "     Antes necesitas la config del repo: `codeguard init --%s` y luego\n", banderaSustituir)
	fmt.Fprintf(&b, "     `%s` para devolvérselos.\n", g.comoVolver())
	return b.String()
}

// avisoSustitucion es lo que se lee al usar la bandera. Sustituir es legítimo;
// hacerlo callando, no. Y el valor viejo se dice aquí porque al escribir el
// nuestro deja de estar en git config: esta línea es el único sitio donde queda.
func (g *gestorDeGanchos) avisoSustitucion() string {
	var b strings.Builder
	fmt.Fprintf(&b, "AVISO — este repo usaba otro gestor de ganchos: core.hooksPath = %s (%s)\n", g.Valor, g.quien())
	fmt.Fprintf(&b, "        los ganchos de %s DEJAN DE CORRER: git sólo ejecuta un directorio\n", g.nombreCorto())
	fmt.Fprintf(&b, "        para devolvérselos:  %s\n", g.comoVolver())
	b.WriteString("        apunta esa orden: al escribir el nuestro, ese valor desaparece de git config\n\n")
	return b.String()
}

