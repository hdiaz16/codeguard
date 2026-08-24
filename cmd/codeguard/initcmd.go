package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"codeguard/internal/config"
	"codeguard/internal/fsutil"
	"codeguard/internal/gitdiff"
	"codeguard/internal/ipc"
	"codeguard/internal/migraciones"
	"codeguard/internal/registry"
)

// codeguard init: enrola un repo detectando lenguajes, migraciones y
// exclusiones. Nadie escribe YAML a mano; la config se versiona y el resto
// del equipo la recibe con git pull.

var extToLang = map[string]string{
	".go": "go", ".ts": "typescript", ".tsx": "typescript", ".js": "javascript",
	".jsx": "javascript", ".py": "python", ".cs": "csharp", ".java": "java",
	".kt": "kotlin", ".dart": "dart", ".sql": "sql",
}

func initCmd() *cobra.Command {
	var force, sustituir, rebaseline bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Enrola este repo: detecta lenguajes y genera .codeguard/config.yaml + hooks + baseline",
		RunE: func(cmd *cobra.Command, args []string) error {
			repoRoot, err := gitdiff.RepoRoot(".")
			if err != nil {
				return fmt.Errorf("no estás dentro de un repo git: %w", err)
			}
			// El conflicto de ganchos se mira AQUÍ, antes de escribir la primera
			// línea. `install` corre al final del enrolamiento: negarse allí
			// dejaba una config generada sin ganchos, sin baseline y sin
			// registrar — un repo que parece enrolado y no vigila nada.
			//
			// El valor vigente se conserva aunque NO haya conflicto: es la única
			// forma de devolver los ganchos a su sitio si el enrolamiento falla
			// más abajo, porque después de `install` git config ya dice otra cosa.
			prevHooks, err := hooksPathVigente(repoRoot)
			if err != nil {
				return err
			}
			if !sustituir && prevHooks != nil && !prevHooks.esNuestro(repoRoot) {
				return errors.New(prevHooks.explicar("init"))
			}
			cfgPath := filepath.Join(repoRoot, filepath.FromSlash(config.RelPath))
			// os.Stat tiene TRES respuestas, no dos: existe, no existe de verdad,
			// y "no se pudo saber" (permisos, disco, red). La tercera no es
			// ausencia: tratarla como tal haría que init regenerara y PISARA un
			// config que quizá sí estaba, por un fallo transitorio. Ante la duda
			// se frena y se dice por qué.
			_, errStat := os.Stat(cfgPath)
			switch {
			case errStat == nil && !force:
				// RECONCILIACIÓN ([31] del plan, turnos 89-93): un repo ya
				// enrolado no es un error — es una pregunta («¿sigue bien
				// cableado?»). Se verifica; si todo pasa, NO-OP exitoso que lo
				// dice; si el CABLEADO está roto (hooks, binpath, registro) se
				// repara SOLO lo nuestro y se re-verifica. Lo que JAMÁS se toca
				// por este camino: config.yaml y baseline — su contenido es una
				// decisión del usuario, no un estado comprobable, y para
				// regenerarlos existen --force y --rebaseline explícitos.
				return reconciliar(repoRoot)
			case errStat != nil && !errors.Is(errStat, fs.ErrNotExist):
				return fmt.Errorf("no se pudo comprobar si ya existe %s: %w", config.RelPath, errStat)
			}
			// Si la config ya existía (--force), un fallo más abajo NO la borra:
			// este init pisó una del usuario y ésa no se puede reponer.
			cfgExistia := errStat == nil

			// ── detección sobre los archivos rastreados ──
			rutas, err := gitdiff.Rastreados(repoRoot)
			if err != nil {
				return err
			}
			hasNode, hasDotnet := false, false
			for _, p := range rutas {
				low := strings.ToLower(p)
				if path.Base(low) == "package.json" {
					hasNode = true
				}
				if strings.HasSuffix(low, ".csproj") || strings.HasSuffix(low, ".sln") {
					hasDotnet = true
				}
			}
			// La detección del stack vive en DetectarLenguajes y no aquí: estaba
			// enterrada dentro de este comando, y por eso nunca tuvo una prueba
			// que la sujetara — el día que escribió `[go]` sobre un repo de
			// cuatro lenguajes, nada se puso rojo.
			langs := DetectarLenguajes(rutas)
			if len(langs) == 0 {
				return fmt.Errorf("no encontré ningún archivo de un lenguaje soportado " +
					"(go, python, typescript/javascript, c#, java, sql) entre los archivos rastreados por git.\n" +
					"Si el repo aún no tiene código, haz un primer commit y vuelve a ejecutar `codeguard init`")
			}
			migrations, sqlSinVigilar := migraciones.Globs(rutas)

			// El dialecto NO se adivina, pero sí se lee cuando el DDL lo dice.
			//
			// Escribir `postgres` a ciegas era gratis mientras esta lista salía
			// vacía —squawk no corría igualmente—. Desde que se rellena de
			// verdad, ese default bloquea: medido, un `CREATE INDEX` legal en
			// SQLite salió BLOQUEADO exigiendo CONCURRENTLY, que en SQLite no
			// existe, y el dev se queda con un arreglo imposible de aplicar.
			//
			// Sólo pruebas positivas: sin marca en el DDL se deja el default de
			// siempre. El esquema de este mismo repo es SQLite sin una sola
			// marca que lo delate, así que un detector que ADIVINE erraría
			// callado — que es justo lo que no se quiere.
			archivosMig, textosMig := leerMigraciones(repoRoot, migrations, rutas)
			pistas := migraciones.Analizar(textosMig)
			migBlock := fmt.Sprintf("  migrations: [%s]", quoteList(migrations))
			switch {
			case len(migrations) > 0:
				// El dialecto se escribe SIEMPRE como postgres, aunque el DDL
				// grite otra cosa. Cambiarlo es lo único que apaga esta capa, y
				// una herramienta no debería apagarse sola a partir de una
				// heurística: cuando acierta ahorra una línea de config, y cuando
				// falla deja la compuerta muda con un ✓ verde encima.
				migBlock += `
  # Motor de esas migraciones: el pilar datos (squawk) sólo analiza PostgreSQL.
  # Este valor lo decides tú, no la detección automática: cambiarlo APAGA esta
  # capa, y esa decisión no puede tomarla una herramienta adivinando.
  # Valores: postgres | sqlite | mysql | sqlserver
  migrations_dialect: postgres`
			// El MISMO criterio que dispara el aviso del terminal, no otro.
			//
			// Estaban separados —el terminal miraba los .sql sin vigilar y el
			// config miraba `languages`— y con UN solo .sql que no parece
			// migración el terminal gritaba que la compuerta quedaba apagada
			// mientras el config guardaba un `migrations: []` pelado. El aviso
			// que PERSISTE faltaba justo en el caso más pequeño, y al del
			// terminal se lo lleva el scroll.
			case len(sqlSinVigilar) > 0:
				// Hay SQL y no reconocí ninguna migración. La lista vacía es
				// legítima, pero significa que `migration_unsafe: block` no
				// vigila NADA — y un `[]` a secas no dice eso. Se escribe arriba,
				// donde lo va a leer quien abra el config.
				migBlock = `  # Hay archivos .sql en este repo pero no reconocí ninguna migración, así
  # que la compuerta ` + "`migration_unsafe`" + ` no vigila nada y el peso de riesgo
  # touches_migration nunca suma. Si aquí vive el esquema, añade sus rutas
  # (por ejemplo "db/**/*.sql") y descomenta migrations_dialect.
  migrations: []
  # migrations_dialect: postgres`
			}

			excludes := []string{"**/*.log", "**/*.db", "**/*.exe", "bin/**"}
			if hasNode {
				excludes = append(excludes, "**/node_modules/**", "**/.next/**", "**/dist/**")
			}
			if hasDotnet {
				excludes = append(excludes, "**/obj/**", "**/*.g.cs", "**/*.designer.cs")
			}
			sort.Strings(excludes)

			// ── plantilla de la organización: si el instalador dejó una junto
			// al binario, manda ella (endpoint/modelos del equipo) ──
			llmBlock := defaultLLMBlock
			if exe, err := os.Executable(); err == nil {
				if raw, err := os.ReadFile(filepath.Join(filepath.Dir(exe), "org-llm.yaml")); err == nil {
					llmBlock = strings.TrimRight(string(raw), "\n")
				}
			}

			yaml := fmt.Sprintf(`version: 1
rulepack: "2026.08.3"

languages: [%s]

paths:
  exclude: [%s]
%s
  sensitive: []          # marca aquí rutas de auth/pagos/PII: suben el riesgo
  generated: []

# Complejidad ciclomática por función a partir de la cual se avisa.
# Nunca bloquea: partir una función es decisión de quien la escribe.
max_complexity: 15

gates:
  secrets: block
  format: block
  compile: block
  lint_error: block
  semgrep_error: block
  migration_unsafe: block
  cve_critical: warn_local_block_ci
  llm: never_block

risk:
  threshold: 35
  weights:
    touches_migration: 30
    touches_sensitive: 25
    ai_generated: 20
    touches_security_config: 20
    adds_dependency: 15
    touches_query: 15
    many_files: 10
    tests_only: -20
    docs_only: -40

ui:
  max_visible_findings: 7
  auto_open_panel: on_block

%s

max_diff_lines: 2000
`, strings.Join(langs, ", "), quoteList(excludes), migBlock, llmBlock)

			// El YAML COMPUESTO se valida con el parser común ANTES de escribirse
			// (turno 92): el bloque org-llm.yaml entraba crudo y un typo suyo
			// salía tres pasos después disfrazado de «falló el baseline». Y la
			// escritura es atómica: una config a medias por un crash es un repo
			// que parece enrolado y no parsea.
			if err := config.Validar([]byte(yaml)); err != nil {
				return fmt.Errorf("la config generada no pasa el parser (¿org-llm.yaml inválido junto al binario?): %w", err)
			}
			if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err != nil {
				return err
			}
			if err := fsutil.EscribirAtomico(cfgPath, []byte(yaml), 0o644); err != nil {
				return err
			}
			fmt.Printf("config generada: %s\n", config.RelPath)
			fmt.Printf("  lenguajes detectados: %s\n", strings.Join(langs, ", "))
			if len(migrations) > 0 {
				fmt.Printf("  migraciones vigiladas: %s\n", strings.Join(migrations, ", "))
				avisarDelMotor(pistas, archivosMig)
			}
			// Lo que el pilar datos NO va a mirar se dice aquí, en el único
			// momento en que alguien está leyendo. Callarlo deja al dev creyendo
			// que sus .sql están cubiertos: la compuerta no avisa de lo que no
			// vigila, y desde fuera "sin hallazgos" y "sin mirar" se ven igual.
			if len(sqlSinVigilar) > 0 {
				if len(migrations) == 0 {
					fmt.Printf("\n  AVISO — hay %d archivo(s) .sql y no reconocí ninguna migración:\n",
						len(sqlSinVigilar))
					fmt.Println("  la compuerta de migraciones queda APAGADA (no vigila nada).")
				} else {
					fmt.Printf("\n  aviso — %d archivo(s) .sql quedan fuera de la vigilancia:\n",
						len(sqlSinVigilar))
				}
				for i, p := range sqlSinVigilar {
					if i == 3 {
						fmt.Printf("    … y %d más\n", len(sqlSinVigilar)-3)
						break
					}
					fmt.Printf("    %s\n", p)
				}
				fmt.Printf("  Si alguno cambia el esquema, añade su ruta a paths.migrations en %s\n",
					config.RelPath)
			}

			// ── hooks + baseline: enrolamiento completo en un comando ──
			fmt.Println("\ninstalando hooks…")
			instalar := installCmd()
			// La decisión de sustituir viaja hasta quien la ejecuta. Sin esto,
			// `init --sustituir-hooks` pasaba la puerta de arriba y se estrellaba
			// contra la de `install`, que no se había enterado de nada.
			if sustituir {
				if err := instalar.Flags().Set(banderaSustituir, "true"); err != nil {
					return err
				}
			}
			if err := instalar.RunE(cmd, nil); err != nil {
				return err
			}
			if cfgExistia && !rebaseline {
				// --force regeneraba también la baseline con --si forzado:
				// re-aceptar como deuda TODO lo hallado hoy, en silencio, de
				// regalo con una reinstalación. Es la operación más peligrosa
				// del comando y ahora viaja sola en --rebaseline (turno 92).
				fmt.Println("\nbaseline ANTERIOR conservada (regenerarla es --rebaseline: re-acepta la deuda de hoy)")
				registry.Add(repoRoot, filepath.Base(repoRoot), strings.Join(langs, ","))
				avisarAlAgente(repoRoot)
				return veredictoDeInit(repoRoot)
			}
			bCmd := baselineCmd()
			_ = bCmd.Flags().Set("si", "true")
			if err := bCmd.RunE(cmd, nil); err != nil {
				// La config ya está escrita y los ganchos instalados: dejarlo así es
				// un repo A MEDIAS, y ése es el peor estado que conoce este producto
				// — el próximo commit bloquea con TODA la deuda preexistente, y si
				// la config se versiona sin baseline le pasa lo mismo a quien la
				// reciba por git pull. Un enrolamiento o se completa o se deshace, y
				// lo que este init cambió se sabe porque se miró antes de escribir.
				errDesh := deshacerEnrolamiento(repoRoot, cfgPath, prevHooks, cfgExistia)
				estado := "el enrolamiento se ha deshecho y el repo queda como estaba"
				reintento := "vuelve a correr `codeguard init`"
				if prevHooks != nil && prevHooks.esNuestro(repoRoot) {
					// Re-init de un repo ya enrolado: los ganchos ya eran nuestros y
					// la baseline anterior sigue intacta, porque baseline.Write es
					// atómica y el fallo no la rozó. Nada que deshacer.
					estado = "el repo sigue enrolado con su baseline ANTERIOR (la config sí se regeneró)"
					reintento = "reintenta con `codeguard baseline`"
				}
				if errDesh != nil {
					estado = "no pude deshacerlo del todo: " + errDesh.Error()
				}
				return fmt.Errorf("falló el baseline: %w (%s; resuelve la causa y %s)",
					err, estado, reintento)
			}
			// registrar el proyecto: aparece en el panel y el explorador desde
			// el momento del init, sin esperar al primer commit.
			registry.Add(repoRoot, filepath.Base(repoRoot), strings.Join(langs, ","))
			avisarAlAgente(repoRoot)

			return veredictoDeInit(repoRoot)
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "regenerar la config aunque ya exista (NO regenera la baseline: eso es --rebaseline)")
	cmd.Flags().BoolVar(&rebaseline, "rebaseline", false, "regenerar también la baseline (re-acepta como deuda TODO lo que se halle hoy: decisión aparte a propósito)")
	cmd.Flags().BoolVar(&sustituir, banderaSustituir, false,
		"enrolar aunque el repo use otro gestor de ganchos (husky, lefthook…): los suyos dejan de correr")
	return cmd
}

// deshacerEnrolamiento revierte lo que ESTE init ya escribió cuando el
// enrolamiento falla a mitad (hoy sólo puede ser el baseline).
//
// Sólo se toca lo que este init cambió, y se sabe porque se miró antes de
// escribir:
//   - core.hooksPath vuelve al valor capturado al entrar (otro gestor, o
//     ninguno). Si ya apuntaba a los nuestros —re-init de un repo enrolado— no se
//     toca: esos ganchos no son de este init.
//   - la config se borra SÓLO si no existía antes: con --force se pisó una del
//     usuario, y borrarla destruiría trabajo que no se puede reponer.
//   - el registro se limpia en ese mismo caso, porque un enrolamiento fallido no
//     puede quedarse en el panel como un proyecto más.
//
// Los archivos de .githooks/ y la regla de .gitattributes se quedan: sin
// core.hooksPath apuntándoles son inertes, y el reintento los reaprovecha.
//
// Nada se traga: cada paso que falla vuelve en el error con la orden para hacerlo
// a mano, y el llamador lo dice en su mensaje.
func deshacerEnrolamiento(repoRoot, cfgPath string, prevHooks *gestorDeGanchos, cfgExistia bool) error {
	var fallos []error
	switch {
	case prevHooks == nil:
		// No había ganchos antes de este init: desarmar los nuestros.
		for _, k := range []string{"core.hooksPath", "codeguard.binpath"} {
			if out, err := gitCmd("-C", repoRoot, "config", "--unset", k).CombinedOutput(); err != nil {
				fallos = append(fallos, fmt.Errorf("quitar %s: %v: %s (a mano: git config --unset %s)",
					k, err, strings.TrimSpace(string(out)), k))
			}
		}
	case prevHooks.esNuestro(repoRoot):
		// Re-init: los ganchos ya eran nuestros. Nada que deshacer.
	default:
		// --sustituir-hooks: devolver el mando al gestor que había. Misma lógica
		// que comoVolver(): un valor local o de worktree se reescribe; uno global
		// o de system vuelve solo al quitar el override local que pusimos.
		if prevHooks.Ambito == "local" || prevHooks.Ambito == "worktree" || prevHooks.Ambito == "" {
			if out, err := gitCmd("-C", repoRoot, "config", "core.hooksPath", prevHooks.Valor).CombinedOutput(); err != nil {
				fallos = append(fallos, fmt.Errorf("devolver core.hooksPath a %q: %v: %s (a mano: git config core.hooksPath %s)",
					prevHooks.Valor, err, strings.TrimSpace(string(out)), prevHooks.Valor))
			}
		} else if out, err := gitCmd("-C", repoRoot, "config", "--unset", "core.hooksPath").CombinedOutput(); err != nil {
			fallos = append(fallos, fmt.Errorf("quitar el core.hooksPath local: %v: %s (a mano: git config --unset core.hooksPath)",
				err, strings.TrimSpace(string(out))))
		}
	}
	if !cfgExistia {
		if err := os.Remove(cfgPath); err != nil {
			fallos = append(fallos, fmt.Errorf("borrar %s: %w (bórralo a mano si no vas a reintentar)", cfgPath, err))
		}
		registry.Remove(repoRoot)
	}
	return errors.Join(fallos...)
}

// avisarAlAgente le dice al agente que acaba de entrar un repo al registro,
// para que lo ponga al frente sin esperar a nada más.
//
// Escribir repos.json no basta: el agente ya corriendo tiene su propia copia en
// memoria y sólo relee el registro para SEMBRAR un panel que aún no tiene
// contexto. Con cualquier otro proyecto en pantalla —o sea, siempre salvo recién
// instalado— el repo enrolado no aparecía ni cerrando y abriendo el panel,
// mientras init decía "LISTO".
//
// Es best-effort a propósito: el enrolamiento ya está hecho y guardado cuando se
// llega aquí. Que el agente esté apagado no es un fallo del init —lo verá al
// arrancar, por el sembrado de siempre—, así que se dice en una línea y se sigue.
// Devolver error aquí convertiría un init correcto en uno que parece roto.
func avisarAlAgente(repoRoot string) {
	if _, err := ipc.Call(&ipc.Request{
		Command: "repo-enrolado", RepoRoot: repoRoot, DeadlineMs: 3000,
	}, 3*time.Second); err != nil {
		fmt.Println("\nel agente no está corriendo: mostrará este proyecto cuando arranque")
		return
	}
	// El camino de éxito también habla. Sin esta línea, enrolar un repo con el
	// agente corriendo y con el agente apagado se veían IGUAL en la terminal
	// —los dos callados—, así que el aviso de arriba no distinguía nada.
	fmt.Println("\nel agente ya lo tiene al frente: mira el panel")
}

// veredictoDeInit es la puerta del «LISTO» ([31]: solo entonces «enrolado»).
// Verifica las postcondiciones REALES con la misma lista de verdades que
// status y doctor — hasta aquí init escribía archivos y declaraba LISTO sin
// releer ninguno. El daemon no bloquea el veredicto (el análisis local
// funciona sin él y avisarAlAgente ya dijo lo suyo); el cableado sí.
func veredictoDeInit(repoRoot string) error {
	orden, checks := chequeosDelRepo(repoRoot)
	var rotos []string
	for _, k := range orden {
		// El informe y el estado del pilar datos son calidad-de-vida, no
		// cableado: no retienen el LISTO. Todo lo demás sí.
		if k == "informe" || k == "datos" {
			continue
		}
		if c, existe := checks[k]; existe && !c.ok {
			rotos = append(rotos, fmt.Sprintf("%s: %s", k, c.detalle))
		}
	}
	if len(rotos) > 0 {
		return fmt.Errorf("el enrolamiento NO quedó completo — postcondiciones sin cumplir:\n  %s\n(revisa con `codeguard doctor`)",
			strings.Join(rotos, "\n  "))
	}
	fmt.Println("\nLISTO — postcondiciones verificadas. Versiona .codeguard/ y .githooks/ para que el equipo quede enrolado con git pull.")
	return nil
}

// reconciliar es init sin --force sobre un repo YA enrolado ([31], turnos
// 89-93): verificar, y reparar SOLO el cableado propio. Si todo pasa, NO-OP
// exitoso que lo dice — no error, no reescritura (la idempotencia es de
// ACCIÓN, no solo de resultado: en los tests de crash-injection «¿reparó o
// reescribió?» tiene que poder responderse). config.yaml y baseline no se
// tocan JAMÁS por este camino: su contenido es decisión del usuario, no un
// estado comprobable.
func reconciliar(repoRoot string) error {
	orden, checks := chequeosDelRepo(repoRoot)
	var rotos []string
	for _, k := range orden {
		if k == "informe" || k == "datos" || k == "baseline" {
			continue // no-cableado: se informa por doctor/status, no se repara aquí
		}
		if c, existe := checks[k]; existe && !c.ok {
			rotos = append(rotos, k)
		}
	}
	if len(rotos) == 0 {
		fmt.Println("ya enrolado y sano — nada que hacer (para reinicializar la config: --force; la baseline: --rebaseline)")
		registry.Add(repoRoot, filepath.Base(repoRoot), "") // idempotente: reaparece en el panel si se había olvidado
		return nil
	}
	// La config rota NO es cableado y no se repara sola: regenerarla pisaría
	// las decisiones del usuario. Se dice y se corta.
	for _, k := range rotos {
		if k == "config" {
			return fmt.Errorf("la config existe pero no está sana (%s) — arréglala a mano o regenera con --force", checks[k].detalle)
		}
	}
	fmt.Printf("reconciliando el cableado (%s)…\n", strings.Join(rotos, ", "))
	instalar := installCmd()
	if err := instalar.RunE(nil, nil); err != nil {
		return fmt.Errorf("la reparación del cableado falló: %w", err)
	}
	registry.Add(repoRoot, filepath.Base(repoRoot), "")
	avisarAlAgente(repoRoot)
	return veredictoDeInit(repoRoot)
}
