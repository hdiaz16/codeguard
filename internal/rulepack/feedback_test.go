package rulepack

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

type archivoSemgrepFeedback struct {
	Rules []struct {
		ID       string         `yaml:"id"`
		Message  string         `yaml:"message"`
		Metadata map[string]any `yaml:"metadata"`
	} `yaml:"rules"`
}

// Un hallazgo sin explicación o sin una corrección concreta transfiere el
// costo del análisis al desarrollador. Este contrato cubre el rulepack que se
// distribuye y evita que una regla nueva vuelva a entregar sólo una alarma.
func TestRulepackDistribuidoTieneFeedbackAccionable(t *testing.T) {
	raiz := filepath.Join("..", "..", "rulepacks")
	versiones, err := os.ReadDir(raiz)
	if err != nil {
		t.Fatal(err)
	}
	var dirs []string
	for _, entrada := range versiones {
		if entrada.IsDir() {
			dirs = append(dirs, entrada.Name())
		}
	}
	if len(dirs) == 0 {
		t.Fatal("no hay rulepack distribuible que auditar")
	}
	sort.Strings(dirs)
	dir := filepath.Join(raiz, dirs[len(dirs)-1], "semgrep")

	archivos, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	reglas := 0
	for _, archivo := range archivos {
		raw, err := os.ReadFile(archivo)
		if err != nil {
			t.Fatal(err)
		}
		var pack archivoSemgrepFeedback
		if err := yaml.Unmarshal(raw, &pack); err != nil {
			t.Fatalf("%s: YAML inválido: %v", filepath.Base(archivo), err)
		}
		for _, regla := range pack.Rules {
			reglas++
			if strings.TrimSpace(regla.ID) == "" {
				t.Errorf("%s: regla sin id", filepath.Base(archivo))
				continue
			}
			if strings.TrimSpace(regla.Message) == "" {
				t.Errorf("%s/%s: falta message", filepath.Base(archivo), regla.ID)
			}
			for _, campo := range []string{"why", "fix_hint"} {
				valor, ok := regla.Metadata[campo].(string)
				if !ok || strings.TrimSpace(valor) == "" {
					t.Errorf("%s/%s: falta metadata.%s", filepath.Base(archivo), regla.ID, campo)
				}
			}
		}
	}
	if reglas == 0 {
		t.Fatal("el rulepack distribuible no contiene reglas")
	}
}
