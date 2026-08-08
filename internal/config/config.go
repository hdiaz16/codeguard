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

type Config struct {
	Version      int      `koanf:"version"`
	Rulepack     string   `koanf:"rulepack"`
	Languages    []string `koanf:"languages"`
	Paths        Paths    `koanf:"paths"`
	Gates        Gates    `koanf:"gates"`
	Risk         Risk     `koanf:"risk"`
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
