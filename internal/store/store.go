// Package store persiste runs y findings en SQLite local (modernc, sin cgo).
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
	_ "modernc.org/sqlite"

	"codeguard/migrations"
)

type Store struct {
	db *sql.DB
}

func NewULID() string {
	return ulid.MustNew(ulid.Timestamp(time.Now().UTC()), rand.Reader).String()
}

func nowISO() string { return time.Now().UTC().Format(time.RFC3339) }

func CanonicalRepoID(remoteURL string) string {
	s := strings.TrimSpace(remoteURL)
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

func RepoIDDe(repoRoot, remote string) string {
	if strings.TrimSpace(remote) != "" {
		return CanonicalRepoID(remote)
	}
	realPath := repoRoot
	if eval, err := filepath.EvalSymlinks(repoRoot); err == nil && eval != "" {
		realPath = eval
	} else if abs, err := filepath.Abs(repoRoot); err == nil && abs != "" {
		realPath = abs
	}
	limpia := strings.TrimRight(filepath.ToSlash(filepath.Clean(realPath)), "/")
	return CanonicalRepoID("local/" + limpia)
}

const busyTimeoutMS = 5000

func Open(path string) (*Store, error) { return abrir(path, busyTimeoutMS) }

func dsnSQLite(path string, busyMS int) string {
	if path == ":memory:" || strings.HasPrefix(path, "file::memory:") {
		return fmt.Sprintf("file::memory:?mode=memory&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(%d)", busyMS)
	}
	v := url.Values{}
	v.Add("_pragma", "foreign_keys(1)")
	v.Add("_pragma", "journal_mode(WAL)")
	v.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", busyMS))

	base := filepath.ToSlash(path)
	if strings.ContainsAny(base, "?#") {
		base = url.PathEscape(base)
	}
	return fmt.Sprintf("%s?%s", base, v.Encode())
}

func abrir(path string, busyMS int) (*Store, error) {
	if path == "" {
		return nil, errors.New("store: ruta de base de datos vacía")
	}
	if path != ":memory:" && !strings.HasPrefix(path, "file::memory:") {
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	dsn := dsnSQLite(path, busyMS)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.Migrate(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migraciones: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) Migrate() error {
	ctx := context.Background()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return fmt.Errorf("tomando el lock de migraciones: %w", err)
	}
	confirmado := false
	defer func() {
		if !confirmado {
			_, _ = conn.ExecContext(ctx, `ROLLBACK`)
		}
	}()
	if _, err := conn.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
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
	sort.SliceStable(names, func(i, j int) bool {
		numI, errI := extraerNumeroVersion(names[i])
		numJ, errJ := extraerNumeroVersion(names[j])
		if errI == nil && errJ == nil && numI != numJ {
			return numI < numJ
		}
		return names[i] < names[j]
	})
	for _, name := range names {
		var exists int
		if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, name).Scan(&exists); err != nil {
			return err
		}
		if exists > 0 {
			continue
		}
		ddl, err := fs.ReadFile(migrations.FS, name)
		if err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, string(ddl)); err != nil {
			return fmt.Errorf("migración %s: %w", name, err)
		}
		if _, err := conn.ExecContext(ctx, `INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`, name, nowISO()); err != nil {
			return err
		}
	}
	if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
		return err
	}
	confirmado = true
	return nil
}

func DefaultPath() string {
	dir := filepath.Join(os.Getenv("LOCALAPPDATA"), "codeguard")
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(os.TempDir(), "codeguard")
	}
	if !filepath.IsAbs(dir) {
		return ""
	}
	_ = os.MkdirAll(dir, 0o700)
	if runtime.GOOS != "windows" {
		_ = os.Chmod(dir, 0o700)
	}
	return filepath.Join(dir, "codeguard.db")
}

func extraerNumeroVersion(nombre string) (uint64, error) {
	base := nombre
	if i := strings.LastIndexAny(base, `/\`); i >= 0 {
		base = base[i+1:]
	}
	fin := 0
	for fin < len(base) && base[fin] >= '0' && base[fin] <= '9' {
		fin++
	}
	if fin == 0 {
		return 0, fmt.Errorf("sin prefijo numérico en %q", nombre)
	}
	return strconv.ParseUint(base[:fin], 10, 64)
}
