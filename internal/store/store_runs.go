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
	// repos es padre de runs (FK) y hoy se empuja primero abortando el sync si
	// falla — un poison pill (t.122). Entra al outbox como todo lo demás, con
	// su fila y su evento en la misma tx. Es idempotente: si el repo ya está,
	// se refresca last_seen_at y NO se re-encola (el evento previo basta; el
	// central lo deduplica igual).
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var yaExiste bool
	if err = tx.QueryRow(`SELECT 1 FROM repos WHERE id = ?`, id).Scan(new(int)); err == nil {
		yaExiste = true
	} else if err != sql.ErrNoRows {
		return err
	}
	if _, err = tx.Exec(`INSERT INTO repos (id, remote_url, name, first_seen_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET last_seen_at = excluded.last_seen_at`,
		id, remoteURL, name, nowISO(), nowISO()); err != nil {
		return err
	}
	if !yaExiste {
		if err = encolarEvento(tx, EntRepos, id, "insert", 1); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type RunMeta struct {
	RunID       string
	RepoID      string
	Branch      string
	RulepackVer string
	ConfigHash  string
	Environment string // local | ci
	Bypassed    bool
	// RiskFormulaVersion y RiskConfigHash identifican CÓMO se calculará el
	// risk_score de este run (W6, defecto #1): el algoritmo y los pesos. Cero /
	// vacío = el llamador no los trae (legacy), y se guardan como NULL.
	RiskFormulaVersion int
	RiskConfigHash     string
}

// SaveRun persiste el run y sus hallazgos en modo sombra.
//
// El outcome llega YA DERIVADO (pipeline.Finalizar) y se guarda tal cual:
// esta función no re-infiere nada (condición de GPT, turno 67). La columna
// verdict conserva el vocabulario viejo —con su "degraded" sintetizado al
// escribir, que fue la mentira medida: un cuarto estado que ningún lector
// entendía— porque las filas históricas y el central lo hablan; los lectores
// nuevos leen outcome y tratan NULL como "legacy", nunca como un estado.
func (s *Store) SaveRun(meta RunMeta, res *pipeline.Result, outcome pipeline.AnalysisOutcome, filesChanged int) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	verdict := string(res.Verdict)
	if len(res.Degraded) > 0 && res.Verdict == pipeline.Pass {
		verdict = "degraded"
	}
	// Identidad del rulepack (005): NULL entero cuando la corrida no la trae
	// (llamador viejo o rulepack irresoluble) — legacy explícito, jamás se
	// re-infiere. Con digest presente, las tres viajan juntas.
	var rpDigest, rpSource, rpVerified any
	if res.Rulepack.Digest != "" {
		rpDigest = res.Rulepack.Digest
		rpSource = string(res.Rulepack.Source)
		rpVerified = b2i(res.Rulepack.Verified)
	}
	// aislamiento_degradado (006): '' = contención completa; NULL solo en
	// filas legacy. Se distingue del degraded_layers de cobertura a propósito.
	_, err = tx.Exec(`INSERT INTO runs
		(id, repo_id, branch, started_at, finished_at, verdict, outcome, failure_code,
		 files_changed, lines_changed, bypassed, degraded_layers, rulepack_ver, config_hash, elapsed_ms, environment,
		 rulepack_digest, rulepack_source, rulepack_verified, aislamiento_degradado,
		 risk_formula_version, risk_config_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		meta.RunID, meta.RepoID, meta.Branch, nowISO(), nowISO(), verdict,
		nulo(string(outcome.Estado)), nulo(string(outcome.FalloEn)),
		filesChanged, 0, b2i(meta.Bypassed), strings.Join(res.Degraded, ","),
		meta.RulepackVer, meta.ConfigHash, res.ElapsedMs, meta.Environment,
		rpDigest, rpSource, rpVerified, strings.Join(res.AislamientoDegradado, ","),
		nuloInt(meta.RiskFormulaVersion), nulo(meta.RiskConfigHash))
	if err != nil {
		return err
	}
	// El run nace con revisión de sync 1 y su evento de outbox en LA MISMA tx
	// (W5): el evento no puede existir sin la fila ni la fila sin el evento.
	if _, err = tx.Exec(`UPDATE runs SET sync_revision = 1 WHERE id = ?`, meta.RunID); err != nil {
		return err
	}
	if err = encolarEvento(tx, EntRuns, meta.RunID, "insert", 1); err != nil {
		return err
	}
	for i := range res.Findings {
		f := &res.Findings[i]
		if f.ID == "" {
			f.ID = NewULID()
		}
		_, err = tx.Exec(`INSERT INTO findings
			(id, run_id, engine, rule_key, pillar, severity, source, blocking,
			 verified, shown, file_path, line_start, line_end, fingerprint, fingerprint_legacy,
			 message, why, fix_hint, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			f.ID, meta.RunID, f.Engine, f.RuleKey, string(f.Pillar), string(f.Severity),
			string(f.Source), b2i(f.Blocking), b2i(f.Verified),
			f.File, f.Line, f.EndLine, f.Fingerprint, nulo(f.LegacyFingerprint),
			f.Message, f.Why, f.FixHint, nowISO())
		if err != nil {
			return err
		}
		if err = encolarEvento(tx, EntFindings, f.ID, "insert", 1); err != nil {
			return err
		}
	}
	// Cobertura por capa (W6 Q3): una fila de run_layers por motor y la racha de
	// salud acumulada de cada (repo, motor), en LA MISMA tx. Es local (sin
	// evento de outbox): el historial de salud lo lee el doctor aquí.
	if err = guardarCapas(tx, meta.RunID, meta.RepoID, res.Capas); err != nil {
		return err
	}
	return tx.Commit()
}

// nulo guarda NULL en vez de cadena vacía: un valor que no se midió no es un
// valor de longitud cero (y un outcome vacío violaría además su CHECK).
func nulo(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// nuloInt guarda NULL en vez de 0: un entero que el llamador no trae (legacy) no
// es el valor cero, igual que nulo() para las cadenas.
func nuloInt(n int) any {
	if n == 0 {
		return nil
	}
	return n
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
	// Antes single-Exec; ahora tx para escribir la fila Y su evento de outbox
	// juntos (W5): telemetría sin evento no viaja sin pérdida.
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	id := NewULID()
	if _, err = tx.Exec(`INSERT INTO llm_calls
		(id, run_id, pillar, model, prompt_tokens, completion_tokens, cost_micros,
		 latency_ms, status, findings_returned, findings_rejected, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, c.RunID, c.Pillar, c.Model, c.PromptTokens, c.CompletionTokens,
		c.CostMicros, c.LatencyMs, c.Status, c.FindingsReturned, c.FindingsRejected, nowISO()); err != nil {
		return err
	}
	if err = encolarEvento(tx, EntLLMCalls, id, "insert", 1); err != nil {
		return err
	}
	return tx.Commit()
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
			 verified, shown, file_path, line_start, line_end, fingerprint, fingerprint_legacy,
			 message, why, fix_hint, created_at)
			VALUES (?, ?, ?, ?, ?, ?, 'llm', 0, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, runID, f.Engine, f.RuleKey, string(f.Pillar), string(f.Severity),
			b2i(f.Verified), f.File, f.Line, f.EndLine, f.Fingerprint, nulo(f.LegacyFingerprint),
			f.Message, f.Why, f.FixHint, nowISO())
		if err != nil {
			return err
		}
		if err = encolarEvento(tx, EntFindings, id, "insert", 1); err != nil {
			return err
		}
	}
	return tx.Commit()
}

var ErrRunNoExiste = errors.New("el run todavía no está en la base")

// UpdateRunLLM anota el puntaje de riesgo y si se usó el modelo. runs es la
// ÚNICA entidad mutable: el risk_score llega tarde (la sombra). Antes esto
// eran DOS operaciones sueltas (UPDATE + reencolar la marca global, que
// re-empujaba TODO lo posterior); ahora es UNA tx que incrementa la revisión
// de sync Y crea un evento `update` propio (W5, t.122). El central acepta solo
// revisión >= la suya, así un retry viejo del `insert` no pisa este cambio.
func (s *Store) UpdateRunLLM(runID string, riskScore int, llmUsed bool) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.Exec(`UPDATE runs SET risk_score = ?, llm_used = ?,
		sync_revision = COALESCE(sync_revision, 1) + 1 WHERE id = ?`,
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
	var rev int64
	if err := tx.QueryRow(`SELECT sync_revision FROM runs WHERE id = ?`, runID).Scan(&rev); err != nil {
		return err
	}
	// Un evento update posterior deja SUPERSEDED cualquier evento pendiente
	// de este run (el central querrá la última revisión, no la intermedia).
	if _, err := tx.Exec(`UPDATE outbox SET state = ?, updated_at = ?
		WHERE entity = ? AND row_id = ? AND state IN (?, ?)`,
		EstSuperseded, nowISO(), EntRuns, runID, EstPending, EstRetry); err != nil {
		return err
	}
	if err := encolarEvento(tx, EntRuns, runID, "update", rev); err != nil {
		return err
	}
	return tx.Commit()
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
