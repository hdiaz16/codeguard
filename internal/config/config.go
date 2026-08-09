// Package config carga .codeguard/config.yaml — la fuente única de verdad
// para el agente y el CI (sección 10 de la spec).
package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/rawbytes"
	"github.com/knadh/koanf/v2"
)

type Paths struct {
	Exclude    []string `koanf:"exclude"`
	Migrations []string `koanf:"migrations"`
	Sensitive  []string `koanf:"sensitive"`
	Generated  []string `koanf:"generated"`
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
	Endpoint  string `koanf:"endpoint"`    // compatible con la API de OpenAI
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

	// Hash sha256 del archivo normalizado a LF. Parte del contrato (ci_parity).
	Hash string `koanf:"-"`
	// RepoRoot es la raíz del repo donde se encontró la config.
	RepoRoot string `koanf:"-"`
}

const RelPath = ".codeguard/config.yaml"

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
		LLM:          LLM{TimeoutMs: 20000, MaxDiffTokens: 12000, APIKeyEnv: "FOUNDRY_API_KEY"},
	}
	if err := k.Unmarshal("", cfg); err != nil {
		return nil, fmt.Errorf("config.yaml no coincide con el esquema: %w", err)
	}
	cfg.Hash = hex.EncodeToString(sum[:])
	cfg.RepoRoot = repoRoot
	if cfg.Rulepack == "" {
		return nil, fmt.Errorf("config.yaml sin 'rulepack': la paridad exige pinnearlo")
	}
	return cfg, nil
}
