// Package store persiste runs y findings en SQLite local (modernc, sin cgo).
// DDL portable SQLite → PostgreSQL según las reglas de la sección 9.
package store

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
	_ "modernc.org/sqlite"

	"codeguard/internal/finding"
	"codeguard/internal/pipeline"
	"codeguard/migrations"
)

type Store struct {
	db *sql.DB
}

func NewULID() string {
	return ulid.MustNew(ulid.Timestamp(time.Now().UTC()), rand.Reader).String()
}

func nowISO() string { return time.Now().UTC().Format(time.RFC3339) }

// CanonicalRepoID normaliza la URL del remote (sección 8): host en minúsculas,
// sin protocolo, sin credenciales, sin sufijo .git — ssh y https del mismo
// repo producen el mismo id.
func CanonicalRepoID(remoteURL string) string {
	s := strings.TrimSpace(remoteURL)
	// forma ssh scp-like: git@host:org/repo.git
	if strings.Contains(s, "@") && !strings.Contains(s, "://") {
		if i := strings.Index(s, "@"); i >= 0 {
			s = s[i+1:]
		}
		s = strings.Replace(s, ":", "/", 1)
	} else if u, err := url.Parse(s); err == nil && u.Host != "" {
		s = u.Host + u.Path
	}
	s = strings.TrimSuffix(strings.ToLower(s), ".git")
	s = strings.TrimSuffix(s, "/")
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return err
	}
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		var exists int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, name).Scan(&exists); err != nil {
			return err
		}
		if exists > 0 {
			continue
		}
		ddl, err := fs.ReadFile(migrations.FS, name)
		if err != nil {
			return err
		}
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(string(ddl)); err != nil {
			_ = tx.Rollback() // el error de la migración ya va en el return
			return fmt.Errorf("migración %s: %w", name, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`, name, nowISO()); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

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

// SaveRun persiste el run y sus hallazgos (modo sombra: se registra todo,
// shown queda en 0 — nada se muestra aún).
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
	CostMicros       int64 // millonésimas de dólar; 0 si no hay tarifas configuradas
}

// GastoDelMesUSD suma lo gastado en llamadas al modelo desde el día 1 del mes
// en curso. Es la base del tope de presupuesto: sin esto, monthly_budget_usd
// era un campo de configuración que nadie leía.
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

// SaveLLMCall registra la telemetría de una llamada al modelo (fase 3 sombra).
func (s *Store) SaveLLMCall(c LLMCall) error {
	_, err := s.db.Exec(`INSERT INTO llm_calls
		(id, run_id, pillar, model, prompt_tokens, completion_tokens, cost_micros,
		 latency_ms, status, findings_returned, findings_rejected, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		NewULID(), c.RunID, c.Pillar, c.Model, c.PromptTokens, c.CompletionTokens,
		c.CostMicros, c.LatencyMs, c.Status, c.FindingsReturned, c.FindingsRejected, nowISO())
	return err
}

// SaveLLMFindings persiste hallazgos del modelo en sombra: shown=0 siempre.
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

// UpdateRunLLM anota el puntaje de riesgo y si se usó el modelo.
func (s *Store) UpdateRunLLM(runID string, riskScore int, llmUsed bool) error {
	_, err := s.db.Exec(`UPDATE runs SET risk_score = ?, llm_used = ? WHERE id = ?`,
		riskScore, b2i(llmUsed), runID)
	return err
}

// DiffCacheGet / DiffCachePut: caché de resultados LLM por diff (§9).
func (s *Store) DiffCacheGet(repoID, diffSHA, rulepack, configHash, model string) (string, bool) {
	var result string
	err := s.db.QueryRow(`SELECT result_json FROM diff_cache
		WHERE repo_id=? AND diff_sha256=? AND rulepack_ver=? AND config_hash=? AND model=?`,
		repoID, diffSHA, rulepack, configHash, model).Scan(&result)
	return result, err == nil
}

func (s *Store) DiffCachePut(repoID, diffSHA, rulepack, configHash, model, resultJSON string) error {
	_, err := s.db.Exec(`INSERT INTO diff_cache
		(id, repo_id, diff_sha256, rulepack_ver, config_hash, model, result_json, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (repo_id, diff_sha256, rulepack_ver, config_hash, model)
		DO UPDATE SET result_json = excluded.result_json, created_at = excluded.created_at`,
		NewULID(), repoID, diffSHA, rulepack, configHash, model, resultJSON, nowISO())
	return err
}

// RuleStat es la precisión medida de una regla según el feedback del equipo.
type RuleStat struct {
	Engine, RuleKey  string
	Useful, FalsePos int
}

// RuleStats agrega el feedback por regla, opcionalmente filtrado por repo.
func (s *Store) RuleStats(repoID string) ([]RuleStat, error) {
	q := `SELECT f.engine, f.rule_key,
	       SUM(CASE WHEN fb.verdict = 'useful' THEN 1 ELSE 0 END),
	       SUM(CASE WHEN fb.verdict = 'false_positive' THEN 1 ELSE 0 END)
	  FROM feedback fb
	  JOIN findings f ON f.id = fb.finding_id
	  JOIN runs r ON r.id = f.run_id
	 WHERE (? = '' OR r.repo_id = ?)
	 GROUP BY f.engine, f.rule_key
	 ORDER BY 4 DESC, 3 DESC`
	rows, err := s.db.Query(q, repoID, repoID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RuleStat
	for rows.Next() {
		var st RuleStat
		if err := rows.Scan(&st.Engine, &st.RuleKey, &st.Useful, &st.FalsePos); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// DemotedRules devuelve las reglas auto-degradadas para un repo: con al
// menos minVotes votos y tasa de falsos positivos sobre el umbral, dejan de
// bloquear (§17: precisión < 80% se corrige o se desactiva — aquí, se degrada
// sola con el feedback del equipo, sin esperar a la calibración formal).
func (s *Store) DemotedRules(repoID string, minVotes int, maxFPRate float64) (map[string]bool, error) {
	stats, err := s.RuleStats(repoID)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, st := range stats {
		total := st.Useful + st.FalsePos
		if total >= minVotes && float64(st.FalsePos)/float64(total) > maxFPRate {
			out[st.Engine+"/"+st.RuleKey] = true
		}
	}
	return out, nil
}

// DefaultPath es la BD local por usuario, compartida por hook, ci y daemon.
func DefaultPath() string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		base = os.TempDir()
	}
	dir := filepath.Join(base, "codeguard")
	_ = os.MkdirAll(dir, 0o755) // best-effort: Open dará el error real si no se puede escribir
	return filepath.Join(dir, "codeguard.db")
}

// SaveFeedback registra el veredicto del dev sobre un hallazgo (§5 etapa 9:
// la única palanca de calibración del sistema).
func (s *Store) SaveFeedback(findingID, verdict, comment string) error {
	if verdict != "useful" && verdict != "false_positive" && verdict != "unclear" {
		return fmt.Errorf("veredicto inválido: %q", verdict)
	}
	_, err := s.db.Exec(`INSERT INTO feedback (id, finding_id, verdict, comment, created_at)
		VALUES (?, ?, ?, ?, ?)`, NewULID(), findingID, verdict, comment, nowISO())
	return err
}

var _ = finding.Finding{} // referencia explícita al modelo del contrato
