package config

import (
	"os"
	"path/filepath"
	"testing"
)

func repoConConfig(t *testing.T, yaml string) string {
	t.Helper()
	dir := t.TempDir()
	if yaml != "" {
		cfgDir := filepath.Join(dir, ".codeguard")
		if err := os.MkdirAll(cfgDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(cfgDir, "config.yaml"), []byte(yaml), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const configMinima = `version: 1
rulepack: "2026.08.2"
languages: [go]
`

// El dialecto decide si corre squawk (sólo entiende PostgreSQL). Omitirlo
// tiene que seguir significando postgres: apagar el pilar datos por defecto
// le quitaría cobertura, sin avisar, a todos los repos ya enrolados.
func TestDialectoMigracionesNormaliza(t *testing.T) {
	for entrada, esperado := range map[string]string{
		"":           "postgres",
		"  ":         "postgres",
		"postgres":   "postgres",
		"PostgreSQL": "postgres",
		"pg":         "postgres",
		"sqlite3":    "sqlite",
		"SQLite":     "sqlite",
		"mariadb":    "mysql",
		"mssql":      "sqlserver",
		"duckdb":     "duckdb", // desconocido: se respeta, y no es postgres
	} {
		p := Paths{MigrationsDialect: entrada}
		if got := p.DialectoMigraciones(); got != esperado {
			t.Errorf("%q → %q, esperaba %q", entrada, got, esperado)
		}
		if got := p.MigracionesEnPostgres(); got != (esperado == "postgres") {
			t.Errorf("%q: MigracionesEnPostgres=%v", entrada, got)
		}
	}
}

// Sin config no hay enrolamiento, y eso NO es un error: es la etapa 0 del
// embudo. Devolver error aquí haría fallar el hook en cada repo ajeno.
func TestSinConfigNoEsError(t *testing.T) {
	// LOCALAPPDATA a un temporal: que la config personal real de esta máquina
	// no se cuele en la prueba.
	t.Setenv("LOCALAPPDATA", t.TempDir())
	cfg, err := Load(repoConConfig(t, ""))
	if err != nil {
		t.Fatalf("repo no enrolado devolvió error: %v", err)
	}
	if cfg != nil {
		t.Fatal("repo no enrolado devolvió config")
	}
}

func TestDefaults(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	cfg, err := Load(repoConConfig(t, configMinima))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxDiffLines != 2000 {
		t.Errorf("MaxDiffLines por defecto: %d", cfg.MaxDiffLines)
	}
	if cfg.Risk.Threshold != 35 {
		t.Errorf("umbral de riesgo por defecto: %d", cfg.Risk.Threshold)
	}
	if cfg.LLM.TimeoutMs != 20000 {
		t.Errorf("timeout del LLM por defecto: %d", cfg.LLM.TimeoutMs)
	}
	if cfg.Rulepack != "2026.08.2" {
		t.Errorf("rulepack: %q", cfg.Rulepack)
	}
	if cfg.Hash == "" || len(cfg.Hash) != 64 {
		t.Errorf("el hash de paridad debe ser sha256 hex: %q", cfg.Hash)
	}
}

// `max_diff_tokens: 0` no es "sin límite": es un diff vacío, y encima cacheado.
//
// La sombra trunca con `maxChars := MaxDiffTokens * 4`, así que con 0 al modelo
// no le llega ni una línea del diff — responde que no ve nada, y ese "sin
// hallazgos" se archiva en la caché bajo el sha del diff COMPLETO. El commit
// queda revisado en falso y no se reintenta. El default sólo aguantaba mientras
// el campo se OMITIERA; un 0 escrito a mano lo pisaba, y la plantilla de `init`
// invitaba a escribirlo con un "# 0 = sin límite" que era de otro campo.
func TestUnMaxDiffTokensDeCeroVuelveAlDefault(t *testing.T) {
	casos := []struct {
		nombre string
		valor  string
		quiero int
	}{
		{"cero escrito a mano", "max_diff_tokens: 0", maxDiffTokensPorDefecto},
		{"negativo", "max_diff_tokens: -1", maxDiffTokensPorDefecto},
		{"campo omitido", "model: \"m\"", maxDiffTokensPorDefecto},
		{"un valor de verdad se respeta", "max_diff_tokens: 500", 500},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			t.Setenv("LOCALAPPDATA", t.TempDir())
			cfg, err := Load(repoConConfig(t, configMinima+"llm:\n  "+c.valor+"\n"))
			if err != nil {
				t.Fatal(err)
			}
			if cfg.LLM.MaxDiffTokens != c.quiero {
				t.Errorf("con `%s` quedó MaxDiffTokens=%d, se esperaba %d",
					c.valor, cfg.LLM.MaxDiffTokens, c.quiero)
			}
		})
	}
}

// Y el saneamiento tiene que ir DESPUÉS de la anulación personal: el archivo
// local reescribe el bloque llm entero, así que un 0 escrito ahí se colaría por
// detrás de cualquier comprobación hecha antes de aplicarlo.
func TestUnCeroEnLaAnulacionPersonalTampocoPasa(t *testing.T) {
	local := t.TempDir()
	t.Setenv("LOCALAPPDATA", local)
	dirLocal := filepath.Join(local, "codeguard")
	if err := os.MkdirAll(dirLocal, 0o755); err != nil {
		t.Fatal(err)
	}
	anulacion := "llm:\n  model: \"modelo-personal\"\n  max_diff_tokens: 0\n"
	if err := os.WriteFile(filepath.Join(dirLocal, "llm-local.yaml"), []byte(anulacion), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(repoConConfig(t, configMinima+"llm:\n  max_diff_tokens: 8000\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.LLMLocal {
		t.Fatal("la anulación personal debía aplicarse: sin eso la prueba no prueba nada")
	}
	if cfg.LLM.MaxDiffTokens != maxDiffTokensPorDefecto {
		t.Errorf("el 0 del archivo personal quedó en pie: MaxDiffTokens=%d", cfg.LLM.MaxDiffTokens)
	}
}

func TestSinRulepackEsError(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	if _, err := Load(repoConConfig(t, "version: 1\nlanguages: [go]\n")); err == nil {
		t.Fatal("sin rulepack no hay paridad que garantizar: debe ser error")
	}
}

func TestYAMLRotoEsError(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	if _, err := Load(repoConConfig(t, "esto: [no cierra")); err == nil {
		t.Fatal("un YAML ilegible debe reportarse, no ignorarse")
	}
}

// El corazón del contrato ci_parity: la MISMA config con CRLF (Windows) y con
// LF (runner de CI) debe dar el MISMO hash. Si esto se rompe, cada commit
// desde Windows aparece como "paridad rota".
func TestElHashNoDependeDeLosFinalesDeLinea(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	conLF, err := Load(repoConConfig(t, configMinima))
	if err != nil {
		t.Fatal(err)
	}
	crlf := ""
	for _, c := range configMinima {
		if c == '\n' {
			crlf += "\r\n"
		} else {
			crlf += string(c)
		}
	}
	conCRLF, err := Load(repoConConfig(t, crlf))
	if err != nil {
		t.Fatal(err)
	}
	if conLF.Hash != conCRLF.Hash {
		t.Errorf("misma config, hashes distintos:\n  LF:   %s\n  CRLF: %s", conLF.Hash, conCRLF.Hash)
	}
}

// La anulación personal del modelo: sustituye el bloque llm, marca LLMLocal,
// y NO toca el hash — el hash es el contrato con el CI y sólo cubre lo
// versionado en el repo.
func TestLaAnulacionLocalNoAlteraElHash(t *testing.T) {
	base := `version: 1
rulepack: "2026.08.2"
languages: [go]
llm:
  provider: "azure-foundry"
  endpoint: "https://equipo.example.com/openai/v1"
  api_key_env: "FOUNDRY_API_KEY"
  model: "modelo-del-equipo"
`
	// Primera carga: sin anulación.
	local := t.TempDir()
	t.Setenv("LOCALAPPDATA", local)
	repo := repoConConfig(t, base)
	sinLocal, err := Load(repo)
	if err != nil {
		t.Fatal(err)
	}
	if sinLocal.LLMLocal {
		t.Fatal("sin archivo local no debe marcarse LLMLocal")
	}
	if sinLocal.LLM.Model != "modelo-del-equipo" {
		t.Fatalf("modelo del equipo: %q", sinLocal.LLM.Model)
	}

	// Segunda carga: con la anulación personal en su sitio.
	dirLocal := filepath.Join(local, "codeguard")
	if err := os.MkdirAll(dirLocal, 0o755); err != nil {
		t.Fatal(err)
	}
	anulacion := "llm:\n  model: \"modelo-personal\"\n"
	if err := os.WriteFile(filepath.Join(dirLocal, "llm-local.yaml"), []byte(anulacion), 0o644); err != nil {
		t.Fatal(err)
	}
	conLocal, err := Load(repo)
	if err != nil {
		t.Fatal(err)
	}
	if !conLocal.LLMLocal {
		t.Error("con archivo local debe marcarse LLMLocal (la UI lo dice en pantalla)")
	}
	if conLocal.LLM.Model != "modelo-personal" {
		t.Errorf("el modelo personal debe ganar: %q", conLocal.LLM.Model)
	}
	// El archivo sólo nombró `model`: lo demás se conserva del equipo.
	if conLocal.LLM.Endpoint != "https://equipo.example.com/openai/v1" {
		t.Errorf("el endpoint del equipo debía conservarse: %q", conLocal.LLM.Endpoint)
	}
	if conLocal.Hash != sinLocal.Hash {
		t.Errorf("la anulación personal NO puede cambiar el hash de paridad:\n  sin: %s\n  con: %s",
			sinLocal.Hash, conLocal.Hash)
	}
}

// Un llm-local.yaml roto se ignora: la capa de consejo nunca es requisito, y
// dejar sin commitear a alguien por un YAML personal mal escrito sería lo
// contrario de P4.
func TestUnaAnulacionRotaNoRompeNada(t *testing.T) {
	local := t.TempDir()
	t.Setenv("LOCALAPPDATA", local)
	dirLocal := filepath.Join(local, "codeguard")
	os.MkdirAll(dirLocal, 0o755)
	os.WriteFile(filepath.Join(dirLocal, "llm-local.yaml"), []byte("llm: [roto"), 0o644)

	cfg, err := Load(repoConConfig(t, configMinima))
	if err != nil {
		t.Fatalf("una anulación ilegible no puede tumbar la carga: %v", err)
	}
	if cfg.LLMLocal {
		t.Error("una anulación que no se aplicó no debe marcarse como aplicada")
	}
}

func TestCostoMicros(t *testing.T) {
	sinTarifas := LLM{}
	if _, ok := sinTarifas.CostoMicros(ConsumoTokens{PromptTokens: 1000, CompletionTokens: 1000}); ok {
		t.Error("sin tarifas no se puede calcular costo: el tope quedaría inventado")
	}

	l := LLM{PriceInPerMTok: 2.0, PriceOutPerMTok: 10.0}
	micros, ok := l.CostoMicros(ConsumoTokens{PromptTokens: 1_000_000, CompletionTokens: 500_000})
	if !ok {
		t.Fatal("con tarifas debe calcular")
	}
	// 1M de entrada a $2/M + 0.5M de salida a $10/M = $7 = 7,000,000 micros
	if micros != 7_000_000 {
		t.Errorf("costo: %d micros, se esperaban 7,000,000", micros)
	}
}

// Los tokens de caché se cobran a tarifas distintas de la entrada normal.
// Omitirlos —como se hacía— no infla el costo: lo deja CORTO, porque
// PromptTokens cuenta sólo el resto no cacheado. Con un tope mensual eso
// significa gastar más de lo autorizado antes de que la compuerta salte.
func TestCostoMicrosCuentaLaCache(t *testing.T) {
	l := LLM{PriceInPerMTok: 2.0, PriceOutPerMTok: 10.0}

	// 1M leído de caché a 0.1x de $2/M = $0.20
	soloLectura, _ := l.CostoMicros(ConsumoTokens{CacheReadTokens: 1_000_000})
	if soloLectura != 200_000 {
		t.Errorf("lectura de caché: %d micros, se esperaban 200,000", soloLectura)
	}

	// 1M escrito en caché a 1.25x de $2/M = $2.50
	soloEscritura, _ := l.CostoMicros(ConsumoTokens{CacheCreationTokens: 1_000_000})
	if soloEscritura != 2_500_000 {
		t.Errorf("escritura de caché: %d micros, se esperaban 2,500,000", soloEscritura)
	}

	// Y el desglose completo suma: $2 + $0.20 + $2.50 + $5 = $9.70
	completo, _ := l.CostoMicros(ConsumoTokens{
		PromptTokens:        1_000_000,
		CompletionTokens:    500_000,
		CacheReadTokens:     1_000_000,
		CacheCreationTokens: 1_000_000,
	})
	if completo != 9_700_000 {
		t.Errorf("desglose completo: %d micros, se esperaban 9,700,000", completo)
	}

	// El caso que motivó el cambio: una llamada servida enteramente desde
	// caché costaba 0 y ahora cuesta lo que cuesta.
	if antes, _ := l.CostoMicros(ConsumoTokens{PromptTokens: 0, CacheReadTokens: 500_000}); antes == 0 {
		t.Error("una llamada servida desde caché no es gratis")
	}
}

// El primo vivo de max_diff_tokens: 0 — lo destapó el arreglo de aquél. Un
// timeout_ms de 0 escrito a mano creaba un context que NACE vencido
// (time.Duration(0) en WithTimeout es un plazo ya agotado) y la explicación
// del panel fallaba al instante. La sombra se salvaba por el suelo de
// plazoSombra y la UI porque trata el 0 aparte — pero eso era suerte de cada
// llamador, no una garantía. La garantía vive en Load, donde nace el cfg.
func TestUnTimeoutMsDeCeroVuelveAlDefault(t *testing.T) {
	casos := []struct {
		nombre string
		valor  string
		quiero int
	}{
		{"cero escrito a mano", "timeout_ms: 0", timeoutMsPorDefecto},
		{"negativo", "timeout_ms: -5", timeoutMsPorDefecto},
		{"un valor de verdad se respeta", "timeout_ms: 90000", 90000},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			t.Setenv("LOCALAPPDATA", t.TempDir())
			cfg, err := Load(repoConConfig(t, configMinima+"llm:\n  "+c.valor+"\n"))
			if err != nil {
				t.Fatal(err)
			}
			if cfg.LLM.TimeoutMs != c.quiero {
				t.Errorf("con `%s` quedó TimeoutMs=%d, se esperaba %d",
					c.valor, cfg.LLM.TimeoutMs, c.quiero)
			}
		})
	}
}
