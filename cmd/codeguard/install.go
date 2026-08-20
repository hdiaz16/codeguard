package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"codeguard/internal/config"
	"codeguard/internal/daemon"
	"codeguard/internal/engines/identidad"
	"codeguard/internal/gitdiff"
	"codeguard/internal/registry"
)

// Los shims van con LF y shebang sh: Git for Windows los ejecuta vía bash
// (MSYS2). CRLF produce "bad interpreter" (§4.1).
const shimTemplate = `#!/bin/sh
# instalado por codeguard install — no editar a mano
exec "$(git config codeguard.binpath)/%s" hook %s "$@"
`

// dirGanchos es NUESTRO directorio de ganchos, el que apunta core.hooksPath.
// Está aquí y no en tres literales sueltos porque ahora hay que compararlo
// contra lo que el repo ya tuviera: escribirlo y reconocerlo tienen que ser el
// mismo valor siempre.
const dirGanchos = ".githooks"

// banderaSustituir es el permiso explícito para apagar los ganchos de otro
// gestor. Se llama así y no `--force` por dos razones medidas en este repo:
// `init` ya tiene un `--force` que significa otra cosa (regenerar la config), y
// un nombre genérico se teclea de memoria. El nombre dice el objeto —los
// ganchos— y el verbo destructivo: sustituir no es añadir.
const banderaSustituir = "sustituir-hooks"

func installCmd() *cobra.Command {
	var sustituir bool
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Instala los hooks de CodeGuard en el repo actual (core.hooksPath)",
		RunE: func(cmd *cobra.Command, args []string) error {
			repoRoot, err := gitdiff.RepoRoot(".")
			if err != nil {
				return fmt.Errorf("no estás dentro de un repo git: %w", err)
			}
			// Antes de escribir NADA. Si el repo ya tiene un gestor de ganchos,
			// apagarlo es una decisión de quien conoce el repo, y negarse tiene
			// que dejarlo exactamente como estaba.
			ajeno, err := hooksPathAjeno(repoRoot)
			if err != nil {
				return err
			}
			if ajeno != nil {
				if !sustituir {
					return errors.New(ajeno.explicar("install"))
				}
				fmt.Fprint(cmd.OutOrStdout(), ajeno.avisoSustitucion())
			}
			hooksDir := filepath.Join(repoRoot, dirGanchos)
			if err := os.MkdirAll(hooksDir, 0o755); err != nil {
				return err
			}
			// El binario se resuelve ANTES de escribir nada: si no se sabe a qué
			// invocar, no se dejan ganchos a medio instalar que fallen en cada
			// commit. Y el shim lleva el nombre REAL del ejecutable en vez del
			// literal codeguard.exe: con el literal, el binario tiene que
			// llamarse exactamente así o los ganchos no encuentran nada (los
			// tests de extremo a extremo ya cargan con esa restricción).
			exe, err := os.Executable()
			if err != nil {
				return err
			}
			binario := filepath.Base(exe)
			for _, hook := range []string{"pre-commit", "prepare-commit-msg", "post-commit"} {
				shim := fmt.Sprintf(shimTemplate, binario, hook)
				path := filepath.Join(hooksDir, hook)
				// WriteFile respeta los LF del template; nunca CRLF.
				if err := os.WriteFile(path, []byte(shim), 0o755); err != nil {
					return err
				}
			}

			// .gitattributes: los shims siempre LF, en cualquier máquina (§4.1).
			gaPath := filepath.Join(repoRoot, ".gitattributes")
			const gaRule = dirGanchos + "/* text eol=lf"
			ga, _ := os.ReadFile(gaPath)
			if !strings.Contains(string(ga), gaRule) {
				f, err := os.OpenFile(gaPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
				if err != nil {
					return err
				}
				// Si el .gitattributes que ya había no termina en salto de
				// línea (típico si se editó a mano), anexar directo pegaría la
				// regla al final de esa última línea y dejaría las dos rotas.
				regla := gaRule
				if len(ga) > 0 && ga[len(ga)-1] != '\n' {
					regla = "\n" + gaRule
				}
				// Los errores de escritura y de cierre se comprueban: si esta
				// regla no llega al .gitattributes, los shims se checan con
				// CRLF en otra máquina y git falla con "bad interpreter".
				// Perderla en silencio rompe el enrolamiento de quien clone.
				_, werr := fmt.Fprintf(f, "%s\n", regla)
				if cerr := f.Close(); werr != nil || cerr != nil {
					return fmt.Errorf("no se pudo escribir la regla de fin de línea en %s: %w",
						gaPath, errors.Join(werr, cerr))
				}
			}

			binDir := filepath.ToSlash(filepath.Dir(exe))
			for _, kv := range [][2]string{
				{"core.hooksPath", dirGanchos},
				{"codeguard.binpath", binDir},
			} {
				if out, err := gitCmd("-C", repoRoot, "config", kv[0], kv[1]).CombinedOutput(); err != nil {
					return fmt.Errorf("git config %s: %v: %s", kv[0], err, out)
				}
			}

			// Registrar el proyecto también aquí: el dev que recibe la config
			// por `git pull` solo corre `install`, nunca `init`.
			registry.Add(repoRoot, filepath.Base(repoRoot), "")

			fmt.Println("CodeGuard instalado en", repoRoot)
			fmt.Println("  hooks:   .githooks/{pre-commit, prepare-commit-msg, post-commit}")
			fmt.Println("  binario:", binDir)
			if _, err := os.Stat(filepath.Join(repoRoot, ".codeguard", "config.yaml")); err != nil {
				fmt.Println("  FALTA .codeguard/config.yaml — sin él el repo no está enrolado y el hook no hace nada")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&sustituir, banderaSustituir, false,
		"instalar aunque el repo use otro gestor de ganchos (husky, lefthook…): los suyos dejan de correr")
	return cmd
}

// gestorDeGanchos es un core.hooksPath que ya mandaba en este repo y NO es el
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

// repararRulepack mueve el pin del repo a una versión instalada cuando la que
// tiene desapareció. Sin esto, retirar una versión dejaba repos analizando con
// cero reglas de la casa, y el único aviso era una línea de "capas no
// revisadas" que nadie lee.
func repararRulepack() error {
	raiz, err := gitdiff.RepoRoot(".")
	if err != nil {
		return nil // fuera de un repo no hay nada que reparar
	}
	cfg, err := config.Load(raiz)
	if err != nil || cfg == nil {
		return nil // repo no enrolado: es asunto de `codeguard init`
	}
	if _, err := os.Stat(daemon.RulepackDir(raiz, cfg.Rulepack)); err == nil {
		fmt.Printf("  ok    rulepack %s\n", cfg.Rulepack)
		return nil
	}

	disponibles := daemon.RulepacksInstalados(raiz)
	if len(disponibles) == 0 {
		return fmt.Errorf("FALTA rulepack %s y no hay ninguno instalado → reinstala CodeGuard", cfg.Rulepack)
	}
	nueva := disponibles[0]

	ruta := filepath.Join(raiz, ".codeguard", "config.yaml")
	raw, err := os.ReadFile(ruta)
	if err != nil {
		return fmt.Errorf("FALTA rulepack %s y no pude leer %s: %v", cfg.Rulepack, ruta, err)
	}
	re := regexp.MustCompile(`(?m)^rulepack:.*$`)
	if !re.Match(raw) {
		return fmt.Errorf("FALTA rulepack %s; añade a mano `rulepack: \"%s\"` en %s", cfg.Rulepack, nueva, ruta)
	}
	actualizado := re.ReplaceAll(raw, []byte(fmt.Sprintf(`rulepack: "%s"`, nueva)))
	if err := os.WriteFile(ruta, actualizado, 0o644); err != nil {
		return fmt.Errorf("no pude escribir %s: %v", ruta, err)
	}
	fmt.Printf("  ok    rulepack %s → %s (el %s ya no está instalado)\n", cfg.Rulepack, nueva, cfg.Rulepack)
	fmt.Println("        revisa la baseline: las reglas nuevas pueden marcar código preexistente")
	return nil
}

func repairCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "repair",
		Short: "Verifica y repara las dependencias del agente (gitleaks, semgrep...)",
		RunE: func(cmd *cobra.Command, args []string) error {
			ok := true
			for _, tool := range []struct{ bin, hint string }{
				{"gitleaks", "go install github.com/zricethezav/gitleaks/v8@latest"},
				{"semgrep", "pip install semgrep"},
				{"squawk", "pip install squawk-cli"},
				{"ruff", "pip install ruff"},
				{"mypy", "pip install mypy"},
			} {
				if _, err := exec.LookPath(tool.bin); err != nil {
					ok = false
					fmt.Printf("  FALTA %-9s → instala con: %s\n", tool.bin, tool.hint)
				} else {
					fmt.Printf("  ok    %s\n", tool.bin)
				}
			}
			if err := repararRulepack(); err != nil {
				ok = false
				fmt.Println("  " + err.Error())
			}
			// Identidad de los motores descargables: que estén no basta, tienen
			// que ser los que publicaron sus autores.
			for _, r := range identidad.Verificar(DirMotores()) {
				switch r.Estado {
				case identidad.Verificado:
					fmt.Printf("  ok    %s v%s (binario publicado)\n", r.Motor, r.Version)
				case identidad.NoArranca:
					// Avisa SIN tocar `ok`, por el mismo motivo que en `engines`:
					// el artefacto es el publicado —el hash cuadra— y lo que falta
					// es un runtime más nuevo en esta máquina. No es un incidente
					// de cadena de suministro.
					//
					// Y aquí importa más que allí: `dist\instalar-motores.ps1` corre
					// `codeguard repair` como verificación final del asistente y
					// propaga su código de salida. Con esto en `default`, un JDK
					// viejo hacía que el instalador CERRARA EN FALLO —tras un
					// mensaje sobre gitleaks, que estaba impecable— por algo que
					// `repair` no puede arreglar jamás: reinstalar devuelve el mismo
					// jar con el mismo hash.
					fmt.Printf("  aviso %s v%s: es el binario publicado pero no arranca aquí\n", r.Motor, r.Version)
					fmt.Printf("        %s\n", r.Detalle)
				case identidad.Ausente:
					// Ya lo reporta el bloque de herramientas de arriba.
				default:
					ok = false
					fmt.Printf("  ALERTA %s: %s → revisa con `codeguard engines`\n", r.Motor, r.Detalle)
				}
			}
			if !ok {
				fmt.Println("\nsin gitleaks la compuerta de secretos es fail-closed y bloquea los commits")
				return errors.New("faltan dependencias del agente: revisa las líneas FALTA/ALERTA de arriba")
			}
			fmt.Println("todo en orden")
			return nil
		},
	}
}
