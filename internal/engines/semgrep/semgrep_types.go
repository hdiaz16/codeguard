package semgrep

import (
	"encoding/json"
	"strings"

	"codeguard/internal/textutil"
)

type sgResult struct {
	Results []struct {
		CheckID string `json:"check_id"`
		Path    string `json:"path"`
		Start   struct {
			Line int `json:"line"`
		} `json:"start"`
		End struct {
			Line int `json:"line"`
		} `json:"end"`
		Extra struct {
			Message  string `json:"message"`
			Severity string `json:"severity"`
			Lines    string `json:"lines"`
			Metadata struct {
				Pillar  string `json:"pillar"`
				Why     string `json:"why"`
				FixHint string `json:"fix_hint"`
			} `json:"metadata"`
		} `json:"extra"`
	} `json:"results"`
	Errors []sgError `json:"errors"`
}

// sgError es un error del propio semgrep, no un hallazgo.
//
// El campo que decide es Type, NO Level: un "Rule parse error" también llega
// con level "error" y sin embargo el escaneo corrió y sus resultados valen.
type sgError struct {
	Code    int       `json:"code"`
	Level   string    `json:"level"`
	Type    tipoError `json:"type"`
	RuleID  string    `json:"rule_id"`
	Path    string    `json:"path"`
	Message string    `json:"message"`
}

// tipoError tolera las DOS formas con que semgrep serializa el tipo de un
// error: un string plano ("Rule parse error") o, para las variantes con
// argumentos, un arreglo cuyo primer elemento es el nombre —
// ["PartialParsing", [ubicaciones…]].
//
// Declararlo string a secas hizo que UN archivo parcialmente parseado en
// bds.portal tumbara el unmarshal del JSON completo, y con él la capa entera:
// 45 hallazgos válidos descartados por no poder leer el tipo de un aviso.
type tipoError string

func (t *tipoError) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*t = tipoError(s)
		return nil
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(b, &arr); err == nil && len(arr) > 0 {
		if err := json.Unmarshal(arr[0], &s); err == nil {
			*t = tipoError(s)
			return nil
		}
	}
	// Forma que no conocemos: el tipo es informativo, y perderlo no justifica
	// invalidar un escaneo que sí corrió. El mensaje del error se conserva.
	*t = ""
	return nil
}

// tipoFatal marca los errores en los que semgrep no analizó lo que se le pidió
// —una raíz de escaneo inválida, una config ilegible— y devuelve un JSON
// perfectamente válido con cero resultados.
//
// Ese silencio fue el peor fallo del agente: `codeguard report` anunciaba
// "0 bloqueantes · COMPLETADO" mientras 28 hallazgos reales existían, porque un
// archivo de documentación con acentos en el nombre invalidaba el escaneo
// entero. Cero hallazgos y "no pude mirar" son cosas opuestas, y hasta aquí se
// contaban como la misma.
const tipoFatal = "SemgrepError"

// fatal devuelve el primer error que invalida el escaneo completo.
//
// Se comprueba aunque haya resultados: si una raíz fue inválida, lo analizado
// es un subconjunto desconocido, y presentarlo como cobertura completa es
// exactamente la mentira que esto viene a impedir.
func (r sgResult) fatal() *sgError {
	for i := range r.Errors {
		if r.Errors[i].Type == tipoFatal {
			return &r.Errors[i]
		}
	}
	return nil
}

// noAnalizados devuelve los errores que significan «este objetivo (o parte de
// él) quedó SIN analizar»: nivel error que no sea ni el fatal (ya tratado) ni
// una regla rota (cobertura del pack, no del objetivo). Aquí caían en silencio
// los Timeout con que semgrep SALTA archivos lentos, los OutOfMemory y los
// errores de sintaxis del objetivo: exit 0, JSON válido, cero resultados para
// ese archivo — «corrió y limpio» sobre algo que nadie miró. Medido en el CI
// con -race: el e2e cazó a semgrep sin ver el subprocess shell=True plantado.
//
// Un tipo desconocido con nivel error también entra: ante la duda, decirlo.
func (r sgResult) noAnalizados() []sgError {
	var out []sgError
	for _, e := range r.Errors {
		if e.Type == tipoFatal || e.Type == "Rule parse error" {
			continue
		}
		if strings.EqualFold(e.Level, "error") {
			out = append(out, e)
		}
	}
	return out
}

// parciales son los avisos (nivel warn) de análisis incompleto, PartialParsing
// el primero: parte del archivo quedó sin mirar. Se DICEN sin tumbar la capa:
// en bds.portal un solo archivo parcialmente parseado convivía con 45
// hallazgos válidos, y descartarlos por el aviso era el remedio peor que el
// silencio. El tratamiento completo (cobertura declarada por motor) es W6 del
// plan.
func (r sgResult) parciales() []sgError {
	var out []sgError
	for _, e := range r.Errors {
		if e.Type == tipoFatal || e.Type == "Rule parse error" {
			continue
		}
		if !strings.EqualFold(e.Level, "error") {
			out = append(out, e)
		}
	}
	return out
}

// reglasRotas lista las reglas del pack que no compilan. No invalidan el
// escaneo —las demás corrieron— pero cada una es cobertura perdida en silencio,
// aquí y en el CI por igual, así que se registran.
func (r sgResult) reglasRotas() []string {
	var ids []string
	for _, e := range r.Errors {
		if e.Type == "Rule parse error" && e.RuleID != "" {
			ids = append(ids, shortRuleID(e.RuleID))
		}
	}
	return ids
}

// shortRuleID recorta el prefijo de ruta que semgrep antepone al id de la regla.
func shortRuleID(checkID string) string {
	if i := strings.LastIndex(checkID, "."); i >= 0 {
		return checkID[i+1:]
	}
	return checkID
}

// truncar acota el mensaje del proveedor: un "Rule parse error" trae el patrón
// entero y llenaría la terminal del dev en el peor momento.
func truncar(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return textutil.TruncarRunas(s, n) + "…"
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
