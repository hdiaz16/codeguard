// Package sarif serializa hallazgos a SARIF 2.1.0 para la pestaña Security
// y las anotaciones de PR de GitHub (sección 11).
package sarif

import (
	"encoding/json"
	"os"

	"codeguard/internal/finding"
)

type Log struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

type Tool struct {
	Driver Driver `json:"driver"`
}

type Driver struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	InformationURI string `json:"informationUri,omitempty"`
	Rules          []Rule `json:"rules"`
}

type Rule struct {
	ID   string `json:"id"`
	Help *Text  `json:"help,omitempty"`
}

type Text struct {
	Text string `json:"text"`
}

type Result struct {
	RuleID    string     `json:"ruleId"`
	Level     string     `json:"level"`
	Message   Text       `json:"message"`
	Locations []Location `json:"locations"`
	// Fingerprint estable para que GitHub no duplique alertas entre corridas.
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           Region           `json:"region"`
}

type ArtifactLocation struct {
	URI string `json:"uri"`
}

type Region struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine,omitempty"`
}

func level(s finding.Severity) string {
	switch s {
	case finding.Error:
		return "error"
	case finding.Warning:
		return "warning"
	default:
		return "note"
	}
}

// Write serializa los hallazgos a un archivo SARIF.
func Write(path, version string, findings []finding.Finding) error {
	rules := map[string]Rule{}
	results := make([]Result, 0, len(findings))
	for _, f := range findings {
		ruleID := f.Engine + "/" + f.RuleKey
		if _, ok := rules[ruleID]; !ok {
			var help *Text
			if f.Why != "" || f.FixHint != "" {
				help = &Text{Text: f.Why + "\n\n" + f.FixHint}
			}
			rules[ruleID] = Rule{ID: ruleID, Help: help}
		}
		line := f.Line
		if line < 1 {
			line = 1
		}
		results = append(results, Result{
			RuleID:  ruleID,
			Level:   level(f.Severity),
			Message: Text{Text: f.Message},
			Locations: []Location{{PhysicalLocation: PhysicalLocation{
				ArtifactLocation: ArtifactLocation{URI: f.File},
				Region:           Region{StartLine: line, EndLine: f.EndLine},
			}}},
			PartialFingerprints: map[string]string{"codeguardFingerprint/v1": f.Fingerprint},
		})
	}

	ruleList := make([]Rule, 0, len(rules))
	for _, r := range rules {
		ruleList = append(ruleList, r)
	}

	log := Log{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []Run{{
			Tool:    Tool{Driver: Driver{Name: "CodeGuard", Version: version, Rules: ruleList}},
			Results: results,
		}},
	}
	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
