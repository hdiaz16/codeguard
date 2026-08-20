package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codeguard/internal/config"
)

// La plantilla que escribe `init` es lo único que la mayoría va a leer del
// bloque llm, así que un comentario mal colocado ahí no es un detalle de
// estilo: es la causa de una configuración rota.
//
// El "# 0 = sin límite" pertenece a monthly_budget_usd, pero estaba escrito
// DOS líneas debajo de max_diff_tokens, y en YAML el ojo lo atribuye al campo
// que tiene encima. La invitación era a poner `max_diff_tokens: 0` esperando
// "sin límite" y conseguir lo contrario: un diff vacío camino del modelo, y su
// "no encuentro nada" archivado en la caché bajo el sha del diff COMPLETO.
//
// Por eso la regla no es de posición —la posición ya era la convencional y aun
// así engañaba— sino de contenido: quien diga "sin límite" tiene que NOMBRAR el
// campo del que habla.
func TestLaPlantillaNoInvitaAPonerMaxDiffTokensEnCero(t *testing.T) {
	lineas := strings.Split(defaultLLMBlock, "\n")

	for i, l := range lineas {
		if strings.Contains(l, "sin límite") && !strings.Contains(l, "monthly_budget_usd") {
			t.Errorf("línea %d dice «sin límite» sin decir de qué campo habla, y el de arriba "+
				"es otro:\n  %s", i+1, l)
		}
	}

	iMax := -1
	for i, l := range lineas {
		if strings.HasPrefix(strings.TrimSpace(l), "max_diff_tokens:") {
			iMax = i
		}
	}
	if iMax < 0 {
		t.Fatal("la plantilla ya no trae max_diff_tokens")
	}
	// El comentario pegado encima del campo: es el que se lee al editarlo.
	var encima []string
	for i := iMax - 1; i >= 0 && strings.HasPrefix(strings.TrimSpace(lineas[i]), "#"); i-- {
		encima = append(encima, lineas[i])
	}
	if !strings.Contains(strings.Join(encima, "\n"), "Un 0 aquí no abre el grifo") {
		t.Errorf("max_diff_tokens no lleva encima el comentario que desmiente el 0; "+
			"lo que hay es:\n%s", strings.Join(encima, "\n"))
	}
}

// Y la plantilla tiene que seguir siendo YAML que carga y da el default: sin
// esto, cualquier retoque al bloque podría dejar un config.yaml recién generado
// que no parsea, y eso se descubriría en el primer commit de alguien.
func TestLaPlantillaLLMCargaYDaElDefault(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, ".codeguard"), 0o755); err != nil {
		t.Fatal(err)
	}
	yaml := "version: 1\nrulepack: \"2026.08.2\"\nlanguages: [go]\n" + defaultLLMBlock + "\n"
	if err := os.WriteFile(filepath.Join(repo, ".codeguard", "config.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(repo)
	if err != nil {
		t.Fatalf("la plantilla de init no carga: %v", err)
	}
	if cfg.LLM.MaxDiffTokens != 12000 {
		t.Errorf("max_diff_tokens de la plantilla quedó en %d", cfg.LLM.MaxDiffTokens)
	}
	if cfg.LLM.Endpoint == "" || cfg.LLM.Model == "" {
		t.Errorf("el bloque llm de la plantilla no llegó entero: %+v", cfg.LLM)
	}
}
