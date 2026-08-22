package baseline_test

import (
	"os"
	"path/filepath"
	"testing"

	"codeguard/internal/baseline"
	"codeguard/internal/finding"
)

func TestLoad_NoFile(t *testing.T) {
	tmpDir := t.TempDir()
	m, err := baseline.Load(tmpDir)
	if err != nil {
		t.Fatalf("Load en directorio sin baseline debió retornar nil error, obtenido: %v", err)
	}
	if len(m) != 0 {
		t.Errorf("mapa esperado vacío, obtenido len %d", len(m))
	}
}

func TestWriteAndLoad_RoundTrip(t *testing.T) {
	tmpDir := t.TempDir()

	findings := []finding.Finding{
		{
			Engine:      "semgrep",
			RuleKey:     "rule-a",
			File:        "src/a.go",
			Line:        10,
			Fingerprint: "fp_aaa_111",
		},
		{
			Engine:      "gosec",
			RuleKey:     "G201",
			File:        "src/b.go",
			Line:        20,
			Fingerprint: "fp_bbb_222",
		},
		{
			Engine:      "gitleaks",
			RuleKey:     "aws-secret",
			File:        "config.json",
			Line:        5,
			Fingerprint: "fp_secret_should_not_baseline",
		},
		{
			Engine:      "semgrep",
			RuleKey:     "rule-duplicate",
			File:        "src/c.go",
			Line:        30,
			Fingerprint: "fp_aaa_111", // Duplicado de fingerprint
		},
	}

	count, err := baseline.Write(tmpDir, findings)
	if err != nil {
		t.Fatalf("baseline.Write falló: %v", err)
	}

	// Solo deben haberse escrito 2 fingerprints únicos (gitleaks omitido, duplicado filtrado)
	if count != 2 {
		t.Fatalf("se esperaban 2 fingerprints escritos, obtenidos %d", count)
	}

	loaded, err := baseline.Load(tmpDir)
	if err != nil {
		t.Fatalf("baseline.Load falló: %v", err)
	}

	if len(loaded) != 2 {
		t.Fatalf("se esperaban 2 fingerprints cargados, obtenidos %d", len(loaded))
	}

	if !loaded["fp_aaa_111"] || !loaded["fp_bbb_222"] {
		t.Errorf("fingerprints esperados no encontrados en baseline cargada: %+v", loaded)
	}

	if loaded["fp_secret_should_not_baseline"] {
		t.Errorf("ERROR CRÍTICO: el secreto de gitleaks fue escrito en la baseline")
	}
}

func TestWrite_RejectsInvalidFields(t *testing.T) {
	tmpDir := t.TempDir()

	// Intento de inyección de saltos de línea en RuleKey
	badFindings := []finding.Finding{
		{
			Engine:      "semgrep",
			RuleKey:     "bad\nrule",
			File:        "src/a.go",
			Line:        10,
			Fingerprint: "fp_good_123",
		},
	}

	_, err := baseline.Write(tmpDir, badFindings)
	if err == nil {
		t.Errorf("se esperaba error ante inyección de salto de línea en RuleKey")
	}

	// Intento de inyección de espacios en Fingerprint
	badFindings2 := []finding.Finding{
		{
			Engine:      "semgrep",
			RuleKey:     "rule-ok",
			File:        "src/a.go",
			Line:        10,
			Fingerprint: "fp with spaces",
		},
	}

	_, err = baseline.Write(tmpDir, badFindings2)
	if err == nil {
		t.Errorf("se esperaba error ante espacios en Fingerprint")
	}
}

func TestLoadOrWarn_DegradesGracefully(t *testing.T) {
	tmpDir := t.TempDir()
	// Crear baseline inválida (directorio en vez de archivo)
	baselineDir := filepath.Join(tmpDir, ".codeguard", "baseline.txt")
	os.MkdirAll(baselineDir, 0o755)

	m := baseline.LoadOrWarn(tmpDir)
	if m != nil {
		t.Errorf("LoadOrWarn ante error de lectura debió retornar nil, obtenido: %+v", m)
	}
}
