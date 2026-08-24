package linters

import "testing"

// Fuzz de los parsers de salida de herramientas externas (W6, defecto #2 de
// GPT). El contrato que fijan es UNO: por muy corrupta que llegue la salida
// —JSON truncado, campos con tipos inesperados, bytes basura—, el parser
// DEVUELVE (findings, error), nunca hace panic. Un panic en el parser tumba el
// motor entero y con él la capa; una entrada hostil no puede tener ese poder.
//
// Cada crash que el nightly encuentre queda como semilla en testdata/fuzz/ y se
// vuelve una regresión: `go test` la reproduce sin -fuzz.
//
// El repoRoot es un string fijo a propósito: estos parsers NO leen del disco
// (arman los hallazgos desde la salida; la línea real la carga AsignarHuellas
// después), así que no hace falta un árbol de verdad y el fuzz corre rápido.

const raizFuzz = "repo"

// semillas típicas: el caso vacío, uno válido mínimo y basura.
func sembrar(f *testing.F, validos ...string) {
	f.Add([]byte(""))
	f.Add([]byte("{"))
	f.Add([]byte("[]"))
	f.Add([]byte("basura no json \x00\xff"))
	for _, v := range validos {
		f.Add([]byte(v))
	}
}

func FuzzHallazgosESLint(f *testing.F) {
	sembrar(f, `[{"filePath":"a.js","messages":[{"ruleId":"no-eq","line":1,"column":1,"message":"m","severity":2}]}]`)
	f.Fuzz(func(t *testing.T, raw []byte) { _, _ = hallazgosESLint(raizFuzz, ".", raw) })
}

func FuzzHallazgosBiome(f *testing.F) {
	sembrar(f, `{"diagnostics":[{"location":{"path":{"file":"a.ts"}},"category":"lint","description":"d","severity":"error"}]}`)
	f.Fuzz(func(t *testing.T, raw []byte) { _, _ = hallazgosBiome(raizFuzz, ".", raw) })
}

func FuzzHallazgosMypy(f *testing.F) {
	sembrar(f, `a.py:1: error: algo [name]`)
	f.Fuzz(func(t *testing.T, raw []byte) { _, _ = hallazgosMypy(raizFuzz, ".", raw) })
}

func FuzzHallazgosPMD(f *testing.F) {
	sembrar(f, `{"files":[{"filename":"A.java","violations":[{"beginline":1,"rule":"R","description":"d","priority":1}]}]}`)
	f.Fuzz(func(t *testing.T, raw []byte) { _, _ = hallazgosPMD(raizFuzz, ".", raw) })
}

func FuzzParseBanditJSON(f *testing.F) {
	sembrar(f, `{"results":[{"filename":"a.py","line_number":1,"test_id":"B101","issue_text":"t","issue_severity":"HIGH","code":"x"}]}`)
	f.Fuzz(func(t *testing.T, raw []byte) { _, _ = parseBanditJSON(string(raw), raizFuzz) })
}

func FuzzParseGosecJSON(f *testing.F) {
	sembrar(f, `{"Issues":[{"file":"a.go","line":"1","rule_id":"G101","details":"d","severity":"HIGH","code":"x"}]}`)
	f.Fuzz(func(t *testing.T, raw []byte) { _, _ = parseGosecJSON(string(raw), raizFuzz) })
}

func FuzzHallazgosDelJSONDeVet(f *testing.F) {
	sembrar(f, `{"pkg":{"vet":[{"posn":"a.go:1:2","message":"m"}]}}`)
	f.Fuzz(func(t *testing.T, raw []byte) { _, _ = hallazgosDelJSONDeVet(raizFuzz, string(raw)) })
}

func FuzzHallazgosDelTextoDeVet(f *testing.F) {
	f.Add([]byte("# pkg\n./a.go:1:2: algo mal\n"))
	f.Add([]byte(""))
	f.Add([]byte("basura\x00"))
	f.Fuzz(func(t *testing.T, raw []byte) { _ = hallazgosDelTextoDeVet(raizFuzz, string(raw)) })
}

func FuzzDotnetVulnInterpretar(f *testing.F) {
	sembrar(f, `{"projects":[{"frameworks":[{"topLevelPackages":[{"id":"X","resolvedVersion":"1.0","vulnerabilities":[{"severity":"High","advisoryurl":"u"}]}]}]}]}`)
	f.Fuzz(func(t *testing.T, raw []byte) { _, _ = (DotnetVuln{}).interpretar(raw, raizFuzz, "a.csproj") })
}

func FuzzHallazgosActionLint(f *testing.F) {
	sembrar(f, `[{"message":"m","filepath":".github/workflows/ci.yml","line":1,"column":1,"kind":"expression","snippet":"x"}]`)
	f.Fuzz(func(t *testing.T, raw []byte) { _, _ = hallazgosActionLint(raizFuzz, string(raw)) })
}

func FuzzHallazgosPSSA(f *testing.F) {
	sembrar(f, `[{"RuleName":"PSAvoidUsingWriteHost","Severity":1,"Line":1,"Column":1,"Message":"m","ScriptPath":"a.ps1"}]`)
	sembrar(f, `{"RuleName":"R","Severity":2,"Line":1,"Column":1,"Message":"m","ScriptPath":"a.ps1"}`)
	f.Fuzz(func(t *testing.T, raw []byte) { _, _ = hallazgosPSSA(raizFuzz, raw) })
}

func FuzzHallazgosShellCheck(f *testing.F) {
	sembrar(f, `[{"file":"a.sh","line":1,"column":1,"level":"info","code":2086,"message":"m"}]`)
	f.Fuzz(func(t *testing.T, raw []byte) { _, _ = hallazgosShellCheck(raizFuzz, string(raw)) })
}
