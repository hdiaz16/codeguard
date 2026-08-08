package linters

import (
	"encoding/json"
	"testing"
)

// Contrato con tsc --pretty false: "src/mod7.ts(19,14): error TS2322: mensaje"
func TestTscLine(t *testing.T) {
	m := tscLine.FindStringSubmatch("src/mod7.ts(19,14): error TS2322: Type 'number' is not assignable to type 'string'.")
	if m == nil {
		t.Fatal("no parseó la línea real de tsc")
	}
	if m[1] != "src/mod7.ts" || m[2] != "19" || m[3] != "TS2322" {
		t.Errorf("campos mal extraídos: %v", m[1:4])
	}
	if tscLine.MatchString("src/mod7.ts(19,14): warning TS9999: algo") {
		t.Error("solo los 'error' de tsc bloquean; los warning no deben matchear")
	}
}

// Contrato con go vet: "path.go:12:3: mensaje" (a veces sin columna)
func TestVetLine(t *testing.T) {
	for _, line := range []string{
		"util.go:10:2: result of fmt.Sprintf call not used",
		"internal/x/y.go:33: unreachable code",
	} {
		if vetLine.FindStringSubmatch(line) == nil {
			t.Errorf("no parseó: %s", line)
		}
	}
}

// Contrato con ruff check --output-format json (v0.14):
const recordedRuff = `[{"cell":null,"code":"F821","end_location":{"column":31,"row":4},
 "filename":"C:\\repo\\calc.py","fix":null,
 "location":{"column":18,"row":4},"message":"Undefined name 'precio_unitario'",
 "noqa_row":4,"url":"https://docs.astral.sh/ruff/rules/undefined-name"}]`

func TestParseRuffDiag(t *testing.T) {
	var diags []ruffDiag
	if err := json.Unmarshal([]byte(recordedRuff), &diags); err != nil {
		t.Fatalf("el JSON grabado de ruff no parsea: %v", err)
	}
	if diags[0].Code != "F821" || diags[0].Location.Row != 4 {
		t.Errorf("campos mal leídos: %+v", diags[0])
	}
}
