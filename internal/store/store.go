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
			tx.Rollback()
			return fmt.Errorf("migración %s: %w", name, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`, name, nowISO()); err != nil {
			tx.Rollback()
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
}

// SaveRun persiste el run y sus hallazgos (modo sombra: se registra todo,
// shown queda en 0 — nada se muestra aún).
func (s *Store) SaveRun(meta RunMeta, res *pipeline.Result, filesChanged int) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	verdict := string(res.Verdict)
	if len(res.Degraded) > 0 && res.Verdict == pipeline.Pass {
		verdict = "degraded"
	}
	_, err = tx.Exec(`INSERT INTO runs
		(id, repo_id, branch, started_at, finished_at, verdict, files_changed,
		 lines_changed, degraded_layers, rulepack_ver, config_hash, elapsed_ms, environment)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		meta.RunID, meta.RepoID, meta.Branch, nowISO(), nowISO(), verdict,
		filesChanged, 0, strings.Join(res.Degraded, ","),
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

var _ = finding.Finding{} // referencia explícita al modelo del contrato
