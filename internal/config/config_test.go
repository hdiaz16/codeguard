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
	if _, ok := sinTarifas.CostoMicros(1000, 1000); ok {
		t.Error("sin tarifas no se puede calcular costo: el tope quedaría inventado")
	}

	l := LLM{PriceInPerMTok: 2.0, PriceOutPerMTok: 10.0}
	micros, ok := l.CostoMicros(1_000_000, 500_000)
	if !ok {
		t.Fatal("con tarifas debe calcular")
	}
	// 1M de entrada a $2/M + 0.5M de salida a $10/M = $7 = 7,000,000 micros
	if micros != 7_000_000 {
		t.Errorf("costo: %d micros, se esperaban 7,000,000", micros)
	}
}
