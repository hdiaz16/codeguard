package main

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"codeguard/internal/config"
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
	var force, sustituir bool
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
			if !sustituir {
				ajeno, err := hooksPathAjeno(repoRoot)
				if err != nil {
					return err
				}
				if ajeno != nil {
					return errors.New(ajeno.explicar("init"))
				}
			}
			cfgPath := filepath.Join(repoRoot, filepath.FromSlash(config.RelPath))
			if _, err := os.Stat(cfgPath); err == nil && !force {
				return fmt.Errorf("el repo ya está enrolado (%s existe); usa --force para regenerar", config.RelPath)
			}

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
rulepack: "2026.08.2"

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

			if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(cfgPath, []byte(yaml), 0o644); err != nil {
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
			fmt.Println("\ngenerando baseline (los hallazgos preexistentes no bloquearán)…")
			if err := baselineCmd().RunE(cmd, nil); err != nil {
				return err
			}
			// registrar el proyecto: aparece en el panel y el explorador desde
			// el momento del init, sin esperar al primer commit.
			registry.Add(repoRoot, filepath.Base(repoRoot), strings.Join(langs, ","))
			avisarAlAgente(repoRoot)

			fmt.Println("\nLISTO. Versiona .codeguard/ y .githooks/ para que el equipo quede enrolado con git pull.")
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "regenerar aunque ya exista config")
	cmd.Flags().BoolVar(&sustituir, banderaSustituir, false,
		"enrolar aunque el repo use otro gestor de ganchos (husky, lefthook…): los suyos dejan de correr")
	return cmd
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

const defaultLLMBlock = `llm:
  provider: "azure-foundry"
  endpoint: "https://TU-RECURSO.services.ai.azure.com/openai/v1"
  api_key_env: "FOUNDRY_API_KEY"
  model: "FW-Kimi-K3"
  model_fast: "gpt-5.6-sol"
  timeout_ms: 20000
  # Cuánto diff se le manda al modelo. Un 0 aquí no abre el grifo: lo cierra
  # —el modelo recibiría un diff vacío—, así que se ignora y vuelve a 12000.
  max_diff_tokens: 12000
  # monthly_budget_usd: 0 = sin límite. Con un tope, hacen falta las tarifas de
  # abajo para poder convertir tokens en dinero; sin ellas no se puede aplicar.
  monthly_budget_usd: 0
  price_in_per_mtok: 0
  price_out_per_mtok: 0`

// avisarDelMotor cuenta lo que el DDL insinúa sobre su motor, SIN cambiar nada.
//
// La detección informa y el equipo decide. Se probó al revés —que `init`
// escribiera el motor detectado— y falló tres veces seguidas de la misma forma:
// una marca ambigua bastaba para dejar `migrations_dialect` en otro valor, y
// con eso squawk deja de correr y la compuerta de migraciones se apaga sin que
// nada lo diga. Un acierto ahorra una línea de configuración; un fallo apaga
// una capa entera en silencio, que es lo que este producto existe para evitar.
//
// Por eso el aviso NOMBRA el archivo: un "vi marcas de MySQL" sin decir dónde
// no se puede comprobar, y lo que no se puede comprobar se acaba ignorando.
func avisarDelMotor(d migraciones.Deteccion, archivos []string) {
	otros := d.OtrosMotores()
	if len(otros) == 0 {
		return
	}
	nombre := func(i int) string {
		if i < len(archivos) {
			return archivos[i]
		}
		return "?"
	}
	fmt.Printf("\n  AVISO — tu DDL tiene marcas de %s:\n", strings.Join(otros, " y de "))
	for _, motor := range otros {
		idx := d.Pistas[motor]
		ejemplo := nombre(idx[0])
		if len(idx) > 1 {
			fmt.Printf("    %s: %s y %d archivo(s) más de %d\n", motor, ejemplo, len(idx)-1, d.Archivos)
		} else {
			fmt.Printf("    %s: %s (1 de %d)\n", motor, ejemplo, d.Archivos)
		}
	}
	// Que también haya marcas de PostgreSQL es un dato útil, no ruido: suele
	// significar volcado heredado, y ahí el motor real es PostgreSQL.
	if len(d.Pistas["postgres"]) > 0 {
		fmt.Printf("    (y de postgres en %d archivo(s): puede ser un volcado heredado)\n",
			len(d.Pistas["postgres"]))
	}
	fmt.Println("  Dejo migrations_dialect: postgres, que es lo único que garantiza que")
	fmt.Println("  esta capa siga revisando. Si el motor real es otro, cámbialo en")
	fmt.Printf("  %s — hasta entonces vas a recibir bloqueos que no aplican.\n", config.RelPath)
}

// leerMigraciones devuelve las rutas y el texto de los .sql que se van a
// vigilar, para poder buscar en ellos marcas del motor.
//
// Con tope: `init` corre delante de alguien que espera, y un repo con
// trescientas migraciones no tiene por qué pagarlas todas para responder una
// pregunta que casi siempre se contesta con la primera. Se leen las primeras
// por orden, que son las que crean el esquema y donde vive la marca.
func leerMigraciones(repoRoot string, globs, rutas []string) (archivos, textos []string) {
	const (
		topeArchivos = 12
		topeBytes    = 128 << 10
	)
	compilados := migraciones.Compilar(globs)
	for _, p := range rutas {
		if len(textos) >= topeArchivos {
			break
		}
		norm := migraciones.Normalizar(p)
		if !migraciones.EsSQL(norm) || !migraciones.CasaAlguno(compilados, norm) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(norm)))
		if err != nil {
			continue // un archivo ilegible no impide mirar el resto
		}
		if len(raw) > topeBytes {
			raw = raw[:topeBytes]
		}
		archivos = append(archivos, norm)
		textos = append(textos, string(raw))
	}
	return archivos, textos
}

func quoteList(items []string) string {
	quoted := make([]string, len(items))
	for i, s := range items {
		quoted[i] = `"` + s + `"`
	}
	return strings.Join(quoted, ", ")
}
