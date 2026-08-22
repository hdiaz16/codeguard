package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"codeguard/internal/finding"
	"codeguard/internal/pipeline"
)

func (s *Store) UpsertRepo(id, remoteURL, name string) error {
	_, err := s.db.Exec(`INSERT INTO repos (id, remote_url, name, first_seen_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET last_seen_at = excluded.last_seen_at`,
		id, remoteURL, name, nowISO(), nowISO())
	return err
}

type RunMeta struct {
	RunID       string
	RepoID      string
	Branch      string
	RulepackVer string
	ConfigHash  string
	Environment string // local | ci
	Bypassed    bool
}

// SaveRun persiste el run y sus hallazgos en modo sombra.
func (s *Store) SaveRun(meta RunMeta, res *pipeline.Result, filesChanged int) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	verdict := string(res.Verdict)
	if len(res.Degraded) > 0 && res.Verdict == pipeline.Pass {
		verdict = "degraded"
	}
	_, err = tx.Exec(`INSERT INTO runs
		(id, repo_id, branch, started_at, finished_at, verdict, files_changed,
		 lines_changed, bypassed, degraded_layers, rulepack_ver, config_hash, elapsed_ms, environment)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		meta.RunID, meta.RepoID, meta.Branch, nowISO(), nowISO(), verdict,
		filesChanged, 0, b2i(meta.Bypassed), strings.Join(res.Degraded, ","),
		meta.RulepackVer, meta.ConfigHash, res.ElapsedMs, meta.Environment)
	if err != nil {
		return err
	}
	for i := range res.Findings {
		f := &res.Findings[i]
		if f.ID == "" {
			f.ID = NewULID()
		}
		_, err = tx.Exec(`INSERT INTO findings
			(id, run_id, engine, rule_key, pillar, severity, source, blocking,
			 verified, shown, file_path, line_start, line_end, fingerprint,
			 message, why, fix_hint, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?)`,
			f.ID, meta.RunID, f.Engine, f.RuleKey, string(f.Pillar), string(f.Severity),
			string(f.Source), b2i(f.Blocking), b2i(f.Verified),
			f.File, f.Line, f.EndLine, f.Fingerprint, f.Message, f.Why, f.FixHint, nowISO())
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

type LLMCall struct {
	RunID            string
	Pillar           string
	Model            string
	PromptTokens     int
	CompletionTokens int
	LatencyMs        int64
	Status           string // ok | timeout | error | skipped
	FindingsReturned int
	FindingsRejected int
	CostMicros       int64
}

// GastoDelMesUSD suma lo gastado en llamadas al modelo en el mes en curso.
func (s *Store) GastoDelMesUSD() (float64, error) {
	inicio := time.Now().UTC().Format("2006-01") + "-01T00:00:00Z"
	var micros sql.NullInt64
	err := s.db.QueryRow(
		`SELECT SUM(cost_micros) FROM llm_calls WHERE created_at >= ?`, inicio,
	).Scan(&micros)
	if err != nil {
		return 0, err
	}
	return float64(micros.Int64) / 1e6, nil
}

// SaveLLMCall registra la telemetría de una llamada al modelo.
func (s *Store) SaveLLMCall(c LLMCall) error {
	_, err := s.db.Exec(`INSERT INTO llm_calls
		(id, run_id, pillar, model, prompt_tokens, completion_tokens, cost_micros,
		 latency_ms, status, findings_returned, findings_rejected, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		NewULID(), c.RunID, c.Pillar, c.Model, c.PromptTokens, c.CompletionTokens,
		c.CostMicros, c.LatencyMs, c.Status, c.FindingsReturned, c.FindingsRejected, nowISO())
	return err
}

// SaveLLMFindings persiste hallazgos del modelo en sombra.
func (s *Store) SaveLLMFindings(runID string, fs []finding.Finding) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, f := range fs {
		id := f.ID
		if id == "" {
			id = NewULID()
		}
		_, err := tx.Exec(`INSERT INTO findings
			(id, run_id, engine, rule_key, pillar, severity, source, blocking,
			 verified, shown, file_path, line_start, line_end, fingerprint,
			 message, why, fix_hint, created_at)
			VALUES (?, ?, ?, ?, ?, ?, 'llm', 0, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, runID, f.Engine, f.RuleKey, string(f.Pillar), string(f.Severity),
			b2i(f.Verified), f.File, f.Line, f.EndLine, f.Fingerprint,
			f.Message, f.Why, f.FixHint, nowISO())
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

var ErrRunNoExiste = errors.New("el run todavía no está en la base")

// UpdateRunLLM anota el puntaje de riesgo y si se usó el modelo.
func (s *Store) UpdateRunLLM(runID string, riskScore int, llmUsed bool) error {
	res, err := s.db.Exec(`UPDATE runs SET risk_score = ?, llm_used = ? WHERE id = ?`,
		riskScore, b2i(llmUsed), runID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("no se pudo saber si el run %s se actualizó: %w", runID, err)
	}
	if n == 0 {
		return fmt.Errorf("anotando riesgo del run %s: %w", runID, ErrRunNoExiste)
	}
	if err := s.reencolarRunParaCentral(runID); err != nil {
		return fmt.Errorf("riesgo anotado, pero el run %s no se pudo reencolar para el central: %w", runID, err)
	}
	return nil
}

func (s *Store) reencolarRunParaCentral(runID string) error {
	var anterior sql.NullString
	if err := s.db.QueryRow(`SELECT MAX(id) FROM runs WHERE id < ?`, runID).Scan(&anterior); err != nil {
		return err
	}
	_, err := s.db.Exec(`UPDATE sync_marcas SET ultima = ?, actualizada_at = ?
		WHERE tabla = 'runs' AND ultima >= ?`, anterior.String, nowISO(), runID)
	return err
}

// RunExiste dice si la fila del run ya está escrita.
func (s *Store) RunExiste(runID string) (bool, error) {
	var uno int
	err := s.db.QueryRow(`SELECT 1 FROM runs WHERE id = ?`, runID).Scan(&uno)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}
