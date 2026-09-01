package sarif_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"codeguard/internal/finding"
	"codeguard/internal/pipeline"
	"codeguard/internal/sarif"
)

func TestWrite_DeterministicAndSchemaConformant(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "report.sarif")

	findings := []finding.Finding{
		{
			Engine:      "semgrep",
			RuleKey:     "sqli-concat",
			Severity:    finding.Error,
			Message:     "SQL Injection detectado",
			File:        "pkg/db/query.go",
			Line:        42,
			EndLine:     45,
			Why:         "Entrada de usuario concatenada directamente en SQL",
			FixHint:     "Usa consultas parametrizadas",
			Fingerprint: "fp_sqli_42",
		},
		{
			Engine:      "gosec",
			RuleKey:     "G101",
			Severity:    finding.Warning,
			Message:     "Hardcoded credentials",
			File:        "pkg/auth/token.go",
			Line:        10,
			EndLine:     10,
			Why:         "Credencial encontrada en el código fuente",
			FixHint:     "Usa variables de entorno",
			Fingerprint: "fp_g101_10",
		},
		{
			Engine:      "semgrep",
			RuleKey:     "empty-catch",
			Severity:    finding.Info,
			Message:     "Bloque catch vacío",
			File:        "pkg/util/helper.go",
			Line:        0,  // Edge case: line 0 -> must map to 1
			EndLine:     -1, // Edge case: endLine < line -> must map to 0
			Why:         "",
			FixHint:     "",
			Fingerprint: "fp_catch_0",
		},
	}

	outcome := pipeline.Finalizar(&pipeline.Result{Verdict: pipeline.Block, BlockingFindings: 1}, "", nil)
	err := sarif.Write(outPath, "2026.08.2", findings, outcome)
	if err != nil {
		t.Fatalf("sarif.Write falló: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("no se pudo leer el archivo SARIF generado: %v", err)
	}

	var sarifLog sarif.Log
	if err := json.Unmarshal(data, &sarifLog); err != nil {
		t.Fatalf("el SARIF generado no es JSON válido: %v", err)
	}

	if sarifLog.Version != "2.1.0" {
		t.Errorf("versión esperada 2.1.0, obtenida %q", sarifLog.Version)
	}

	if len(sarifLog.Runs) != 1 {
		t.Fatalf("se esperaba 1 run, obtenidos %d", len(sarifLog.Runs))
	}

	run := sarifLog.Runs[0]
	if run.Tool.Driver.Name != "CodeGuard" || run.Tool.Driver.Version != "2026.08.2" {
		t.Errorf("tool driver inconsistente: %+v", run.Tool.Driver)
	}
	if run.Properties["codeguardOutcome"] != "blocked" {
		t.Errorf("SARIF perdió el outcome canónico: %+v", run.Properties)
	}

	// Verificar orden determinista de reglas
	if len(run.Tool.Driver.Rules) != 3 {
		t.Fatalf("se esperaban 3 reglas, obtenidas %d", len(run.Tool.Driver.Rules))
	}
	expectedRules := []string{"gosec/G101", "semgrep/empty-catch", "semgrep/sqli-concat"}
	for i, expectedID := range expectedRules {
		if run.Tool.Driver.Rules[i].ID != expectedID {
			t.Errorf("regla [%d] esperada %q, obtenida %q", i, expectedID, run.Tool.Driver.Rules[i].ID)
		}
	}

	// Verificar resultados y corrección de líneas límite
	if len(run.Results) != 3 {
		t.Fatalf("se esperaban 3 resultados, obtenidos %d", len(run.Results))
	}

	// Verificar edge case de línea 0
	catchResult := run.Results[2]
	if catchResult.RuleID != "semgrep/empty-catch" {
		t.Errorf("resultado 2 esperado empty-catch, obtenido %s", catchResult.RuleID)
	}
	loc := catchResult.Locations[0].PhysicalLocation
	if loc.Region.StartLine != 1 {
		t.Errorf("StartLine para línea 0 debió ajustarse a 1, obtenido %d", loc.Region.StartLine)
	}
	if loc.Region.EndLine != 0 {
		t.Errorf("EndLine negativo debió ajustarse a 0, obtenido %d", loc.Region.EndLine)
	}
	// La primaria viaja bajo /v2 (huellas v2); /v1 queda para el alias legacy
	// de la ventana dual, y este fixture no lo trae.
	if catchResult.PartialFingerprints["codeguardFingerprint/v2"] != "fp_catch_0" {
		t.Errorf("fingerprint incorrecto en resultado SARIF")
	}
	if _, tieneV1 := catchResult.PartialFingerprints["codeguardFingerprint/v1"]; tieneV1 {
		t.Errorf("sin alias legacy no se emite clave /v1: emitir la primaria ahí renacería cada alerta de GitHub")
	}

	// Segunda corrida para verificar que el JSON es 100% idéntico byte a byte
	outPath2 := filepath.Join(tmpDir, "report2.sarif")
	if err := sarif.Write(outPath2, "2026.08.2", findings, outcome); err != nil {
		t.Fatalf("segunda corrida de sarif.Write falló: %v", err)
	}
	data2, _ := os.ReadFile(outPath2)
	if string(data) != string(data2) {
		t.Fatalf("la salida SARIF no es determinista entre ejecuciones sucesivas")
	}
}

func TestWrite_EmptyFindings(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "empty.sarif")

	outcome := pipeline.Finalizar(&pipeline.Result{
		Verdict: pipeline.Pass, Degraded: []string{"semgrep:error"},
	}, "", nil)
	if err := sarif.Write(outPath, "1.0.0", nil, outcome); err != nil {
		t.Fatalf("sarif.Write con findings vacíos falló: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("no se pudo leer el archivo: %v", err)
	}

	var sarifLog sarif.Log
	if err := json.Unmarshal(data, &sarifLog); err != nil {
		t.Fatalf("JSON inválido: %v", err)
	}

	if len(sarifLog.Runs[0].Results) != 0 {
		t.Errorf("se esperaban 0 resultados, obtenidos %d", len(sarifLog.Runs[0].Results))
	}
	props := sarifLog.Runs[0].Properties
	if props["codeguardOutcome"] != "degraded" {
		t.Fatalf("cero hallazgos con cobertura rota se presentó como limpio: %+v", props)
	}
}
