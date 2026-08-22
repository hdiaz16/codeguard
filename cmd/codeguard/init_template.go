package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"codeguard/internal/config"
	"codeguard/internal/migraciones"
)

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

// quoteList escapa con strconv.Quote en vez de pegar comillas a mano. Hoy los
// globs salen de rutas de git (siempre con «/») y Windows no admite `"` ni `\`
// en un nombre, así que el YAML roto no es alcanzable — pero serializar a mano
// lo vuelve alcanzable en cuanto cambie el origen de los globs, y este archivo
// se versiona: un config.yaml inválido rompe el enrolamiento del equipo entero.
// La salida de Quote (\", \\, \xNN, \uNNNN) es un escalar YAML válido.
func quoteList(items []string) string {
	quoted := make([]string, len(items))
	for i, s := range items {
		quoted[i] = strconv.Quote(s)
	}
	return strings.Join(quoted, ", ")
}
