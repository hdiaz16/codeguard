// Package lock define .codeguard.lock: la PRUEBA reproducible de que dos
// entornos analizarían igual (W6 Q4, consejo t.128).
//
// No es una frontera de confianza —una PR lo edita como cualquier archivo—,
// sino una foto de las entradas que DETERMINAN el veredicto: el binario, el
// rulepack, la config, la baseline y la fórmula de riesgo. Si el agente local
// corre con una versión de codeguard, un rulepack o una baseline distintos de
// los que vio el CI, «si pasa aquí pasa allá» deja de ser verdad —y hasta ahora
// eso no se veía—. El lock lo hace visible ANTES de analizar: el CI rechaza el
// skew (su trabajo es la garantía), el gancho local solo lo declara (bloquear
// al dev por esto le enseñaría el reflejo --no-verify).
//
// Lo que NO lleva: rutas, nombres de máquina ni nada de entorno — el lock se
// versiona en el repo y viaja en las PRs, así que solo contiene identidades
// estables y compartibles. Las versiones de los MOTORES externos (eslint, tsc…)
// quedan FUERA por ahora: capturarlas exige sondear cada herramienta, y
// re-sondearlas en cada commit para validar es un coste en el camino caliente
// que su valor todavía no justifica; el esquema las admitirá cuando se resuelva
// ese sondeo barato (anotado para una tanda posterior).
package lock

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"codeguard/internal/fsutil"
)

// Schema versiona el FORMATO del lock (no su contenido). Un consumidor que lea
// un schema que no entiende debe decirlo, no adivinar — la lección de siempre.
const Schema = 1

// RelPath es la ruta del lock relativa a la raíz del repo. Se versiona.
const RelPath = ".codeguard.lock"

// Lock es la foto de las entradas deterministas del análisis. El orden de los
// campos ES el orden de serialización (json.Marshal respeta la declaración), y
// de ahí sale la propiedad clave: regenerar sin cambios da bytes idénticos.
type Lock struct {
	Schema             int    `json:"schema"`
	CodeguardVersion   string `json:"codeguard_version"`
	RulepackVersion    string `json:"rulepack_version"`
	RulepackDigest     string `json:"rulepack_digest"`
	ConfigDigest       string `json:"config_digest"`
	BaselineDigest     string `json:"baseline_digest"`
	RiskFormulaVersion int    `json:"risk_formula_version"`
	RiskConfigHash     string `json:"risk_config_hash"`
}

// Bytes serializa el lock de forma DETERMINISTA (mismo contenido ⇒ mismos
// bytes): es la propiedad de la que depende que `lock --update` sin cambios no
// ensucie el diff. Con salto final para que sea un archivo de texto POSIX.
func (l Lock) Bytes() ([]byte, error) {
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// Cargar lee el lock del repo. El bool es false (sin error) cuando no existe:
// un repo sin lock todavía no es un error, es un repo que no lo ha generado.
func Cargar(repoRoot string) (Lock, bool, error) {
	ruta := filepath.Join(repoRoot, filepath.FromSlash(RelPath))
	raw, err := os.ReadFile(ruta)
	if err != nil {
		if os.IsNotExist(err) {
			return Lock{}, false, nil
		}
		return Lock{}, false, fmt.Errorf("lock ilegible (%s): %w", RelPath, err)
	}
	var l Lock
	if err := json.Unmarshal(raw, &l); err != nil {
		return Lock{}, false, fmt.Errorf("lock corrupto (%s): %w", RelPath, err)
	}
	return l, true, nil
}

// Escribir guarda el lock atómico: se versiona y lo leen gancho y CI, así que un
// archivo a medias por un crash a mitad de escritura sería peor que no tenerlo.
func Escribir(repoRoot string, l Lock) error {
	data, err := l.Bytes()
	if err != nil {
		return err
	}
	ruta := filepath.Join(repoRoot, filepath.FromSlash(RelPath))
	return fsutil.EscribirAtomico(ruta, data, 0o644)
}

// Diferencias compara el lock ESPERADO (el del repo) contra el ACTUAL (lo que
// esta máquina calcularía) y devuelve, en texto humano, cada campo que difiere.
// Vacío ⇒ coherentes. El orden es estable para logs reproducibles.
func Diferencias(esperado, actual Lock) []string {
	var d []string
	cmp := func(nombre, a, b string) {
		if a != b {
			d = append(d, fmt.Sprintf("%s: el repo fijó %q, esta máquina tiene %q", nombre, a, b))
		}
	}
	if esperado.Schema != actual.Schema {
		d = append(d, fmt.Sprintf("schema: el repo fijó %d, este binario entiende %d", esperado.Schema, actual.Schema))
	}
	cmp("codeguard", esperado.CodeguardVersion, actual.CodeguardVersion)
	cmp("rulepack (versión)", esperado.RulepackVersion, actual.RulepackVersion)
	cmp("rulepack (digest)", esperado.RulepackDigest, actual.RulepackDigest)
	cmp("config", esperado.ConfigDigest, actual.ConfigDigest)
	cmp("baseline", esperado.BaselineDigest, actual.BaselineDigest)
	if esperado.RiskFormulaVersion != actual.RiskFormulaVersion {
		d = append(d, fmt.Sprintf("fórmula de riesgo: el repo fijó v%d, esta máquina usa v%d",
			esperado.RiskFormulaVersion, actual.RiskFormulaVersion))
	}
	cmp("pesos de riesgo", esperado.RiskConfigHash, actual.RiskConfigHash)
	return d
}
