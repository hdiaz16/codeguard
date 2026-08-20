// Package config carga .codeguard/config.yaml — la fuente única de verdad
// para el agente y el CI (sección 10 de la spec).
package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/rawbytes"
	"github.com/knadh/koanf/v2"
)

type Paths struct {
	Exclude    []string `koanf:"exclude"`
	Migrations []string `koanf:"migrations"`
	// MigrationsDialect es el motor al que van estas migraciones. Squawk, el
	// único linter del pilar datos, parsea exclusivamente PostgreSQL: contra
	// otro dialecto sus hallazgos no son ruido inofensivo sino consejo dañino
	// —CREATE INDEX CONCURRENTLY no existe en SQLite— y además BLOQUEAN, así
	// que el dev queda sin salida. Declarar el dialecto real lo desactiva.
	MigrationsDialect string   `koanf:"migrations_dialect"`
	Sensitive         []string `koanf:"sensitive"`
	Generated         []string `koanf:"generated"`
}

// DialectoMigraciones normaliza paths.migrations_dialect a un identificador
// único (postgres, sqlite, mysql, sqlserver, oracle...).
//
// Vacío = postgres a propósito: el default tiene que preservar lo que hoy
// protege a los repos que sí usan Postgres. Apagar el pilar datos por omisión
// sería quitarles cobertura en silencio, que es peor que el falso positivo
// que este campo viene a resolver.
func (p Paths) DialectoMigraciones() string {
	d := strings.ToLower(strings.TrimSpace(p.MigrationsDialect))
	switch d {
	case "", "postgres", "postgresql", "psql", "pg":
		return "postgres"
	case "sqlite", "sqlite3":
		return "sqlite"
	case "mysql", "mariadb":
		return "mysql"
	case "sqlserver", "mssql", "tsql":
		return "sqlserver"
	}
	return d
}

// MigracionesEnPostgres dice si el pilar datos (squawk) aplica a este repo.
func (p Paths) MigracionesEnPostgres() bool {
	return p.DialectoMigraciones() == "postgres"
}

type Gates struct {
	Secrets         string `koanf:"secrets"`
	Format          string `koanf:"format"`
	Compile         string `koanf:"compile"`
	LintError       string `koanf:"lint_error"`
	SemgrepError    string `koanf:"semgrep_error"`
	MigrationUnsafe string `koanf:"migration_unsafe"`
	CVECritical     string `koanf:"cve_critical"`
	LLM             string `koanf:"llm"`
}

type Risk struct {
	Threshold int            `koanf:"threshold"`
	Weights   map[string]int `koanf:"weights"`
}

type UI struct {
	MaxVisibleFindings int `koanf:"max_visible_findings"`
	// never | on_block (default) | on_findings
	AutoOpenPanel string `koanf:"auto_open_panel"`
}

// LLM define el modelo advisory (fase 3). El default lo fija el equipo aquí,
// versionado en el repo: el dev no configura nada. La API key NUNCA va en
// este archivo — solo el nombre de la variable de entorno que la contiene.
type LLM struct {
	// Provider es el id de un preajuste (ver internal/llm/proveedores.go):
	// azure-foundry, openai, anthropic, ollama... Vacío = se deduce del
	// endpoint, para que las configuraciones anteriores a este campo sigan
	// funcionando sin tocarlas.
	Provider  string `koanf:"provider"`
	Endpoint  string `koanf:"endpoint"`
	APIKeyEnv string `koanf:"api_key_env"` // nombre de la env var con la key
	// Model es el default para los tres pilares; los overrides son opcionales.
	Model         string `koanf:"model"`
	ModelQuality  string `koanf:"model_quality"`
	ModelSecurity string `koanf:"model_security"`
	ModelData     string `koanf:"model_data"`
	// ModelFast: modelo no-razonador para tareas mecánicas (explicar
	// hallazgos, generar reglas). El razonamiento ahí es peso muerto.
	ModelFast        string  `koanf:"model_fast"`
	TimeoutMs        int     `koanf:"timeout_ms"`
	MaxDiffTokens    int     `koanf:"max_diff_tokens"`
	MonthlyBudgetUSD float64 `koanf:"monthly_budget_usd"` // 0 = sin límite
	// Precios por millón de tokens, para convertir el consumo en dinero. Sin
	// ellos MonthlyBudgetUSD no se puede evaluar y el tope queda inactivo:
	// preferimos decirlo a inventar una tarifa.
	PriceInPerMTok  float64 `koanf:"price_in_per_mtok"`
	PriceOutPerMTok float64 `koanf:"price_out_per_mtok"`
}

// ConsumoTokens es el desglose de una llamada tal como lo reporta el proveedor.
//
// PromptTokens es el resto NO cacheado, no el tamaño total del prompt: los
// tokens servidos desde caché viajan aparte. Es un struct y no cuatro enteros
// posicionales a propósito — invertir dos de ellos saldría gratis y falsearía
// el costo en silencio.
type ConsumoTokens struct {
	PromptTokens        int
	CompletionTokens    int
	CacheReadTokens     int
	CacheCreationTokens int
}

// Multiplicadores sobre el precio de ENTRADA. Leer de caché es ~10 veces más
// barato que procesar el token; escribirla cuesta un 25% más. Ignorar ambos
// dejaba el costo corto en cada llamada con caché.
const (
	factorLecturaCache   = 0.1
	factorEscrituraCache = 1.25
)

// CostoMicros convierte un consumo de tokens a millonésimas de dólar.
// Devuelve 0 y false cuando las tarifas no están completas.
func (l LLM) CostoMicros(c ConsumoTokens) (int64, bool) {
	// Basta que falte UNA de las dos tarifas: la mitad sin precio computa a
	// cero y el costo sale sistemáticamente corto: el mismo sesgo a la baja
	// que math.Round evita más abajo, pero de otra magnitud, y justo en la
	// cifra que se compara con el tope mensual. Con datos incompletos el tope
	// no se puede evaluar, y ok=false es cómo se dice eso.
	if l.PriceInPerMTok <= 0 || l.PriceOutPerMTok <= 0 {
		return 0, false
	}
	entrada := float64(c.PromptTokens) +
		float64(c.CacheReadTokens)*factorLecturaCache +
		float64(c.CacheCreationTokens)*factorEscrituraCache
	usd := entrada/1e6*l.PriceInPerMTok +
		float64(c.CompletionTokens)/1e6*l.PriceOutPerMTok
	// math.Round y no la conversión directa: int64(x) trunca hacia cero, y
	// truncar en cada llamada sesga el gasto acumulado siempre a la baja —
	// justo en la cifra contra la que se compara el tope mensual. El importe
	// perdido es minúsculo; el sesgo sistemático en una compuerta de gasto no
	// es una propiedad que convenga tener.
	return int64(math.Round(usd * 1e6)), true
}

// ModelFor devuelve el modelo del pilar: override si existe, default si no.
func (l LLM) ModelFor(pillar string) string {
	switch pillar {
	case "quality":
		if l.ModelQuality != "" {
			return l.ModelQuality
		}
	case "security":
		if l.ModelSecurity != "" {
			return l.ModelSecurity
		}
	case "data":
		if l.ModelData != "" {
			return l.ModelData
		}
	}
	return l.Model
}

// Fast devuelve el modelo rápido para tareas mecánicas; sin override cae al default.
func (l LLM) Fast() string {
	if l.ModelFast != "" {
		return l.ModelFast
	}
	return l.Model
}

type Config struct {
	Version      int      `koanf:"version"`
	Rulepack     string   `koanf:"rulepack"`
	Languages    []string `koanf:"languages"`
	Paths        Paths    `koanf:"paths"`
	Gates        Gates    `koanf:"gates"`
	Risk         Risk     `koanf:"risk"`
	UI           UI       `koanf:"ui"`
	LLM          LLM      `koanf:"llm"`
	MaxDiffLines int      `koanf:"max_diff_lines"`
	// MaxComplexity: complejidad ciclomática por función a partir de la cual
	// se avisa (nunca bloquea). 0 = usar el valor por defecto.
	MaxComplexity int `koanf:"max_complexity"`

	// Hash sha256 del archivo normalizado a LF. Parte del contrato (ci_parity).
	Hash string `koanf:"-"`
	// RepoRoot es la raíz del repo donde se encontró la config.
	RepoRoot string `koanf:"-"`
	// LLMLocal indica que el bloque llm viene del archivo personal del
	// desarrollador y no del que versiona el equipo. La UI tiene que decirlo:
	// si no, alguien puede creer que usa el modelo de la casa cuando no.
	LLMLocal bool `koanf:"-"`
}

const RelPath = ".codeguard/config.yaml"

// maxDiffTokensPorDefecto es el presupuesto de diff que se manda al modelo.
// Está en una constante para que el valor inicial y el saneamiento de Load no
// puedan separarse: si se pisan con números distintos, "volver al default"
// dejaría de significar lo mismo según por dónde se llegue.
const maxDiffTokensPorDefecto = 12000

// timeoutMsPorDefecto: misma disciplina y por el mismo fallo en primo. Un
// `timeout_ms: 0` escrito a mano crea un context que NACE vencido —
// time.Duration(0) en un WithTimeout es un plazo ya agotado— y la explicación
// del panel (cmd/daemon/explain.go) falla al instante. La sombra estaba a
// salvo por el suelo de un minuto de plazoSombra y la UI porque trata el 0
// como este mismo default, pero eso era suerte de cada llamador: el
// saneamiento pertenece a Load, donde nace el cfg, no repartido por los
// consumidores.
const timeoutMsPorDefecto = 20000

// Load lee la config del repo. Si el archivo no existe, el repo no está
// enrolado (etapa 0) y se devuelve (nil, nil).
func Load(repoRoot string) (*Config, error) {
	raw, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(RelPath)))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	// Normalizar a LF antes de hashear: paridad entre máquinas con autocrlf distinto.
	normalized := bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))
	sum := sha256.Sum256(normalized)

	k := koanf.New(".")
	if err := k.Load(rawbytes.Provider(raw), yaml.Parser()); err != nil {
		return nil, fmt.Errorf("config.yaml inválido: %w", err)
	}
	cfg := &Config{
		MaxDiffLines: 2000,
		Risk:         Risk{Threshold: 35},
		UI:           UI{MaxVisibleFindings: 7, AutoOpenPanel: "on_block"},
		//nolint:gosec // G101: es el NOMBRE de la variable de entorno, no una clave — precisamente el diseño que evita guardar credenciales
		LLM: LLM{TimeoutMs: timeoutMsPorDefecto, MaxDiffTokens: maxDiffTokensPorDefecto, APIKeyEnv: "FOUNDRY_API_KEY"},
	}
	if err := k.Unmarshal("", cfg); err != nil {
		return nil, fmt.Errorf("config.yaml no coincide con el esquema: %w", err)
	}
	cfg.Hash = hex.EncodeToString(sum[:])
	cfg.RepoRoot = repoRoot
	if cfg.Rulepack == "" {
		return nil, fmt.Errorf("config.yaml sin 'rulepack': la paridad exige pinnearlo")
	}
	// Un dialecto fuera del conjunto conocido no es "no es postgres": es casi
	// siempre un typo (postgre, posgres). Como MigracionesEnPostgres compara
	// contra "postgres", ese typo apagaba el pilar datos sin decir nada — la
	// cobertura perdida en silencio que el default de DialectoMigraciones
	// existe para evitar. Se rechaza la config y el autor corrige el nombre.
	// Si se añade un dialecto aquí, añadirlo también en DialectoMigraciones.
	switch cfg.Paths.DialectoMigraciones() {
	case "postgres", "sqlite", "mysql", "sqlserver", "oracle":
	default:
		return nil, fmt.Errorf("config.yaml: paths.migrations_dialect %q no es un dialecto conocido "+
			"(postgres, sqlite, mysql, sqlserver, oracle)", cfg.Paths.MigrationsDialect)
	}
	// La anulación local se aplica DESPUÉS del hash: el hash es el contrato de
	// paridad con el CI y sólo cubre lo que está versionado en el repo. Cambiar
	// de modelo no altera qué bloquea —el modelo nunca bloquea (P2)—, así que
	// no puede romper esa paridad.
	aplicarLLMLocal(cfg)
	// Un max_diff_tokens de 0 (o negativo) NO significa "sin límite": significa
	// que no viaja NADA. El truncado de la sombra multiplica este número por 4 y
	// corta el diff a esa longitud, así que con 0 lo que se le manda al modelo es
	// un diff vacío — y el modelo, obediente, no encuentra nada. Lo caro viene
	// después: ese "sin hallazgos" se guarda en la caché bajo el sha del diff
	// COMPLETO, o sea que el commit queda con un análisis vacío archivado como si
	// fuera bueno, y no se vuelve a intentar.
	//
	// El default de arriba sólo sobrevive si el YAML OMITE el campo; un `0`
	// escrito a mano lo pisaba. Y la invitación a escribirlo estaba servida: la
	// plantilla de `codeguard init` ponía un "# 0 = sin límite" —que es de
	// monthly_budget_usd— dos líneas debajo de este campo (ya corregido en
	// cmd/codeguard/initcmd.go).
	//
	// Va DESPUÉS de aplicarLLMLocal a propósito: la anulación personal reescribe
	// el bloque llm entero, así que un 0 en llm-local.yaml se colaría por detrás
	// de una comprobación puesta más arriba.
	if cfg.LLM.MaxDiffTokens <= 0 {
		cfg.LLM.MaxDiffTokens = maxDiffTokensPorDefecto
	}
	if cfg.LLM.TimeoutMs <= 0 {
		cfg.LLM.TimeoutMs = timeoutMsPorDefecto
	}
	return cfg, nil
}

// RutaLLMLocal es donde vive la elección de modelo de ESTE desarrollador.
// Fuera del repo a propósito: es suya, no del equipo, y no debe viajar en un
// commit ni cambiar el hash de la configuración.
//
// Devuelve "" si no puede resolver una ruta ABSOLUTA, y entonces no hay
// anulación personal. Ese "fuera del repo" del párrafo anterior no es una
// aclaración: es la garantía de que quien elige el modelo es el desarrollador y
// no el repositorio que acaba de clonar, y hay que imponerla aquí porque no la
// impone nadie más.
//
// filepath.Join no falla cuando LOCALAPPDATA viene vacía: devuelve
// `codeguard\llm-local.yaml`, que es RELATIVA al directorio de trabajo — y el
// directorio de trabajo, durante un commit, es el repo que se está analizando.
// Un repo ajeno con ese archivo dentro se configuraba a sí mismo el bloque llm:
// bastaba con apuntar el endpoint a un servidor propio para llevarse los diffs
// que se le mandan al modelo, sin que nada lo dijera, porque la anulación se
// aplica DESPUÉS del hash de paridad y no produce diagnóstico.
//
// Y LOCALAPPDATA puede faltar en Windows por causas de todos los días: cuenta
// de servicio, proceso lanzado con un bloque de entorno acotado — este mismo
// repo filtra por lista blanca el entorno con el que corre los motores.
func RutaLLMLocal() string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		return ""
	}
	ruta := filepath.Join(base, "codeguard", "llm-local.yaml")
	// La comprobación no sobra aunque la variable tenga valor: LOCALAPPDATA
	// puede traer algo que no sea una ruta absoluta (un valor puesto a mano, o
	// en blanco). Lo que no puede salir de aquí es una ruta relativa.
	if !filepath.IsAbs(ruta) {
		return ""
	}
	return ruta
}

// aplicarLLMLocal sustituye el bloque llm por el del archivo local, si existe.
// Un archivo ilegible se ignora en silencio a propósito: la capa de consejo
// nunca es requisito, y dejar sin commitear a alguien por un YAML mal escrito
// sería exactamente lo contrario de lo que hace este agente.
func aplicarLLMLocal(cfg *Config) {
	ruta := RutaLLMLocal()
	if ruta == "" {
		// Sin ruta personal resoluble no se lee NADA. Es explícito y no un
		// descuido aprovechado: es verdad que os.ReadFile("") también fallaría,
		// pero dejar que el arreglo dependa de eso es volver a confiar en un
		// accidente, que es justo lo que puso aquí el agujero.
		return
	}
	raw, err := os.ReadFile(ruta)
	if err != nil {
		return
	}
	k := koanf.New(".")
	if err := k.Load(rawbytes.Provider(raw), yaml.Parser()); err != nil {
		return
	}
	local := cfg.LLM // parte de lo que ya había: el archivo sólo cambia lo que nombra
	if err := k.Unmarshal("llm", &local); err != nil {
		return
	}
	cfg.LLM = local
	cfg.LLMLocal = true
}
