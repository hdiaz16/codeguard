package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"codeguard/internal/baseline"
	"codeguard/internal/config"
	"codeguard/internal/daemon"
	"codeguard/internal/gitdiff"
	"codeguard/internal/migraciones"
	"codeguard/internal/registry"
)

// codeguard status: verificación de enrolamiento. Responde de un vistazo
// "¿este repo (o todos) tienen CodeGuard bien puesto?" — y qué le falta.

type chequeo struct {
	ok      bool
	detalle string
}

// tieneSQL: si el repo declara SQL entre sus lenguajes hay algo que mirar.
// Es la comprobación BARATA, la que decide si merece la pena preguntar al
// disco; se lee del config para no recorrer archivos de todos los proyectos.
func tieneSQL(cfg *config.Config) bool {
	for _, l := range cfg.Languages {
		if strings.EqualFold(strings.TrimSpace(l), "sql") {
			return true
		}
	}
	return false
}

// migracionesSinVigilar lista los archivos que parecen migraciones en un repo
// cuya lista está vacía. Es la comprobación CARA, y por eso sólo se llega aquí
// cuando el config ya dijo que hay SQL.
//
// Usa el mismo criterio que `init` y que el pipeline (internal/migraciones): si
// cada superficie tuviera el suyo, `status` acusaría de algo que `init --force`
// no arreglaría, que es exactamente el rojo sin salida que esto evita.
func migracionesSinVigilar(root string) []string {
	rutas, err := gitdiff.Rastreados(root)
	if err != nil {
		return nil // sin poder mirar, no se acusa
	}
	var out []string
	for _, p := range rutas {
		if migraciones.Parece(p) {
			out = append(out, migraciones.Normalizar(p))
			if len(out) == 3 {
				break // con un ejemplo basta para el informe
			}
		}
	}
	return out
}

func statusCmd() *cobra.Command {
	var todos bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Verifica el enrolamiento: config, hooks, baseline, rulepack y paridad",
		RunE: func(cmd *cobra.Command, args []string) error {
			var roots []string
			if todos {
				for _, r := range registry.Load() {
					roots = append(roots, r.Root)
				}
				if len(roots) == 0 {
					fmt.Println("no hay proyectos registrados todavía (corre `codeguard init` en uno)")
					return nil
				}
			} else {
				root, err := gitdiff.RepoRoot(".")
				if err != nil {
					return fmt.Errorf("no estás dentro de un repo git (usa --todos): %w", err)
				}
				roots = []string{root}
			}

			problemas := 0
			for i, root := range roots {
				if i > 0 {
					fmt.Println()
				}
				if n := revisarRepo(root); n > 0 {
					problemas += n
				}
			}
			fmt.Println()
			if problemas == 0 {
				fmt.Println("✅ todo en orden")
			} else {
				fmt.Printf("⚠️  %d punto(s) por atender — arriba está el comando de cada uno\n", problemas)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&todos, "todos", false, "revisar todos los proyectos registrados en esta máquina")
	return cmd
}

func revisarRepo(root string) int {
	fmt.Printf("── %s\n   %s\n", filepath.Base(root), filepath.ToSlash(root))
	if _, err := os.Stat(root); err != nil {
		fmt.Println("   ✗ la carpeta ya no existe")
		return 1
	}

	checks := map[string]chequeo{}
	orden := []string{"config", "hooks", "hooksPath", "binpath", "rulepack", "datos", "baseline", "informe"}

	// 1. config del repo
	cfg, err := config.Load(root)
	switch {
	case err != nil:
		checks["config"] = chequeo{false, "ilegible: " + err.Error() + " → revisa .codeguard/config.yaml"}
	case cfg == nil:
		checks["config"] = chequeo{false, "NO enrolado → corre `codeguard init`"}
	default:
		checks["config"] = chequeo{true, fmt.Sprintf("rulepack %s · %s", cfg.Rulepack, strings.Join(cfg.Languages, ", "))}
	}

	// 2. los tres hooks
	faltan := []string{}
	for _, h := range []string{"pre-commit", "prepare-commit-msg", "post-commit"} {
		if _, err := os.Stat(filepath.Join(root, ".githooks", h)); err != nil {
			faltan = append(faltan, h)
		}
	}
	if len(faltan) == 0 {
		checks["hooks"] = chequeo{true, "los 3 presentes"}
	} else {
		checks["hooks"] = chequeo{false, "faltan " + strings.Join(faltan, ", ") + " → `codeguard install`"}
	}

	// 3. git apunta a ellos
	//
	// Las tres respuestas son distintas y antes dos se contaban como una: "no
	// es .githooks" salía como «sin configurar → `codeguard install`» aunque el
	// valor lo hubiera puesto husky. Ni era cierto ni el remedio servía —era la
	// orden que apagaba husky, y desde que `install` se niega ni siquiera corre—.
	// Se pregunta con el MISMO lector que usa `install` para no volver a tener
	// dos opiniones sobre el mismo dato.
	switch vigente, err := hooksPathVigente(root); {
	case err != nil:
		checks["hooksPath"] = chequeo{false, "no pude leer core.hooksPath: " + err.Error()}
	case vigente == nil:
		checks["hooksPath"] = chequeo{false, "core.hooksPath sin configurar → `codeguard install`"}
	case vigente.esNuestro(root):
		checks["hooksPath"] = chequeo{true, "core.hooksPath = " + vigente.Valor}
	default:
		checks["hooksPath"] = chequeo{false, fmt.Sprintf(
			"los ganchos son de %s (core.hooksPath = %s): CodeGuard NO corre en este repo → "+
				"llámalo desde ellos, o `codeguard install --%s` para cambiarlos",
			vigente.nombreCorto(), vigente.Valor, banderaSustituir)}
	}

	// 4. el shim sabe dónde está el binario
	if out, err := gitCmd("-C", root, "config", "codeguard.binpath").Output(); err == nil {
		bin := filepath.Join(strings.TrimSpace(string(out)), "codeguard.exe")
		if _, err := os.Stat(bin); err == nil {
			checks["binpath"] = chequeo{true, filepath.ToSlash(filepath.Dir(bin))}
		} else {
			checks["binpath"] = chequeo{false, "apunta a un binario inexistente → `codeguard install`"}
		}
	} else {
		checks["binpath"] = chequeo{false, "codeguard.binpath sin configurar → `codeguard install`"}
	}

	// 5. rulepack resoluble (esto es la PARIDAD con el CI)
	if cfg != nil {
		dir := daemon.RulepackDir(root, cfg.Rulepack)
		if _, err := os.Stat(dir); err == nil {
			donde := "junto al binario"
			if strings.HasPrefix(filepath.ToSlash(dir), filepath.ToSlash(root)) {
				donde = "vendoreado en el repo"
			}
			checks["rulepack"] = chequeo{true, cfg.Rulepack + " (" + donde + ")"}
		} else {
			checks["rulepack"] = chequeo{false,
				"no encuentro el rulepack " + cfg.Rulepack + " → sin paridad con el CI; reinstala o vendoréalo"}
		}
	}

	// 6. pilar datos: squawk sólo entiende PostgreSQL, así que el dialecto
	// decide si corre. Se muestra siempre que haya migraciones configuradas —
	// un motor apagado en silencio se confunde con un motor que no encuentra
	// nada, y son cosas muy distintas para quien confía en la cobertura.
	if cfg != nil && len(cfg.Paths.Migrations) == 0 && tieneSQL(cfg) {
		// El repo tiene SQL y la lista está vacía: la compuerta no vigila nada.
		//
		// Hasta aquí este chequeo se saltaba entero cuando la lista venía vacía,
		// así que el ÚNICO sitio que podía delatar el pilar datos apagado callaba
		// justo en el caso roto.
		//
		// Pero "tiene SQL" no basta para acusar, y esto también se midió: un repo
		// de sólo consultas (sqlc) salía ✗ para siempre, y el remedio que se le
		// proponía —`init --force`— vuelve a dejar la lista vacía, porque esas
		// consultas NO son migraciones. Un rojo permanente con un arreglo que no
		// puede funcionar es peor que no avisar: enseña a ignorar el informe.
		// Así que se pregunta lo que de verdad importa: ¿hay algo que PAREZCA
		// una migración y nadie lo esté mirando?
		if sueltas := migracionesSinVigilar(root); len(sueltas) > 0 {
			checks["datos"] = chequeo{false, fmt.Sprintf(
				"%s parece una migración y paths.migrations está vacío → `migration_unsafe` "+
					"no la vigila; corre `codeguard init --force` o añade su ruta a mano", sueltas[0])}
		}
	} else if cfg != nil && len(cfg.Paths.Migrations) > 0 {
		if cfg.Paths.MigracionesEnPostgres() {
			nota := "postgres · squawk activo"
			if strings.TrimSpace(cfg.Paths.MigrationsDialect) == "" {
				nota = "postgres por defecto · squawk activo (si no es Postgres, declara paths.migrations_dialect)"
			}
			checks["datos"] = chequeo{true, nota}
		} else {
			// Se enuncia como lo que es —NADA revisado— y no como un ✓ a secas.
			//
			// Decía "squawk no aplica" con marca de correcto, y un validador lo
			// midió sobre un repo mal clasificado: check verde sobre migraciones
			// de producción que ya no miraba nadie. El motor puede no aplicar por
			// una decisión legítima del equipo, así que no es un fallo; pero
			// tampoco es protección, y la línea no puede leerse como si lo fuera.
			checks["datos"] = chequeo{true, cfg.Paths.DialectoMigraciones() +
				" · el pilar datos NO revisa nada en este repo (squawk sólo analiza PostgreSQL)"}
		}
	}

	// 7. baseline
	if n := len(baseline.LoadOrWarn(root)); n > 0 {
		checks["baseline"] = chequeo{true, fmt.Sprintf("%d hallazgos preexistentes suprimidos", n)}
	} else if cfg != nil {
		checks["baseline"] = chequeo{false, "sin baseline → lo viejo bloqueará; corre `codeguard baseline`"}
	}

	// 7. informe para agentes
	if raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(reportFile))); err == nil {
		if strings.Contains(string(raw), "✅ COMPLETADO") {
			checks["informe"] = chequeo{true, "HALLAZGOS.md sin pendientes"}
		} else {
			checks["informe"] = chequeo{false, "HALLAZGOS.md con pendientes → pásaselo a tu agente"}
		}
	} else {
		checks["informe"] = chequeo{true, "sin informe (genera uno con `codeguard report`)"}
	}

	fallos := 0
	for _, k := range orden {
		c, existe := checks[k]
		if !existe {
			continue
		}
		mark := "✓"
		if !c.ok {
			mark = "✗"
			fallos++
		}
		fmt.Printf("   %s %-10s %s\n", mark, k, c.detalle)
	}
	return fallos
}
