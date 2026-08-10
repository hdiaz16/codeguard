// Package semgrep adapta Semgrep CE con el rule pack de la casa (etapa 2).
package semgrep

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"codeguard/internal/engines"
	"codeguard/internal/engines/proc"
	"codeguard/internal/finding"
)

type Engine struct {
	Binary string // vacío = buscar en PATH
}

// ErrSinRulepack: el repo apunta a una versión de rulepack que no está
// instalada. Merece su propio error porque no es "semgrep falló": es la
// promesa de paridad con el CI rota, y el desarrollador necesita saberlo
// con esas palabras.
var ErrSinRulepack = errors.New("no encuentro el rulepack al que apunta este repo")

func (e *Engine) Name() string { return "semgrep" }

func (e *Engine) Applies(in engines.Input) bool {
	for _, f := range in.Files {
		if f.Status != "D" {
			return true
		}
	}
	return false
}

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
	Code    int    `json:"code"`
	Level   string `json:"level"`
	Type    string `json:"type"`
	RuleID  string `json:"rule_id"`
	Message string `json:"message"`
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

func (e *Engine) Run(ctx context.Context, in engines.Input) ([]finding.Finding, error) {
	bin := e.Binary
	if bin == "" {
		bin = "semgrep"
	}
	rules := filepath.Join(in.RulepackDir, "semgrep")
	if _, err := os.Stat(rules); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrSinRulepack, rules)
	}

	// Solo archivos tocados (sección 5, etapa 2): targets explícitos.
	args := []string{"scan", "--config", rules, "--json", "--metrics=off", "--quiet", "--disable-version-check"}
	targets := 0
	for _, f := range in.Files {
		if f.Status == "D" {
			continue
		}
		args = append(args, filepath.Join(in.RepoRoot, filepath.FromSlash(f.Path)))
		targets++
	}
	if targets == 0 {
		return nil, nil
	}

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = in.RepoRoot
	// Sin esto, el CLI de Python lee las reglas YAML con la codificación
	// regional de Windows (cp1252) y los mensajes con acentos salen rotos.
	cmd.Env = proc.Entorno("PYTHONUTF8=1", "PYTHONIOENCODING=utf-8")
	salida, runErr := proc.Correr(ctx, cmd, proc.MaxSalida)
	out := salida.Stdout
	// Semgrep sale con 1 cuando hay hallazgos bloqueantes; el JSON sigue siendo válido.
	if runErr != nil && len(out) == 0 {
		return nil, fmt.Errorf("semgrep no corrió: %v", runErr)
	}
	// Un JSON recortado no se puede parsear; decirlo es mejor que un error de sintaxis.
	if salida.Recortada {
		return nil, fmt.Errorf("semgrep devolvió más de %d MB de salida; revisa el alcance de las reglas", proc.MaxSalida>>20)
	}

	var res sgResult
	if err := json.Unmarshal(out, &res); err != nil {
		return nil, fmt.Errorf("salida de semgrep ilegible: %v", err)
	}
	// Antes de mirar un solo hallazgo: ¿llegó semgrep a analizar? Un JSON válido
	// con cero resultados es indistinguible de un repo limpio salvo por aquí.
	if e := res.fatal(); e != nil {
		return nil, fmt.Errorf("semgrep no llegó a analizar (%s): %s",
			e.Type, truncar(e.Message, 300))
	}
	if rotas := res.reglasRotas(); len(rotas) > 0 {
		log.Printf("semgrep: %d regla(s) del rulepack no compilan y no se aplicaron: %s",
			len(rotas), strings.Join(rotas, ", "))
	}

	findings := make([]finding.Finding, 0, len(res.Results))
	for _, r := range res.Results {
		sev := finding.Warning
		if strings.EqualFold(r.Extra.Severity, "ERROR") {
			sev = finding.Error
		}
		pillar := finding.Quality
		switch strings.ToLower(r.Extra.Metadata.Pillar) {
		case "security":
			pillar = finding.Security
		case "data":
			pillar = finding.Data
		}
		rel, err := filepath.Rel(in.RepoRoot, r.Path)
		if err != nil {
			rel = r.Path
		}
		f := finding.Finding{
			Engine:  "semgrep",
			RuleKey: shortRuleID(r.CheckID),
			Pillar:  pillar,
			// Política de compuertas §7: semgrep ERROR bloquea, WARNING avisa.
			Severity:    sev,
			Blocking:    sev == finding.Error,
			File:        filepath.ToSlash(rel),
			Line:        r.Start.Line,
			EndLine:     r.End.Line,
			Message:     r.Extra.Message,
			Why:         r.Extra.Metadata.Why,
			FixHint:     r.Extra.Metadata.FixHint,
			Verified:    true,
			Source:      finding.Deterministic,
			LineContent: firstLine(r.Extra.Lines),
		}
		f.ComputeFingerprint()
		findings = append(findings, f)
	}
	return findings, nil
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
	return s[:n] + "…"
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
