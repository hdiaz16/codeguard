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
	"log"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
	_ "modernc.org/sqlite"

	"codeguard/migrations"
)

type Store struct {
	db *sql.DB
	// ruta es la del archivo de la BD: la necesita el mutex nombrado de las
	// migraciones para derivar un nombre canónico por base de datos.
	ruta string
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
	s := &Store{db: db, ruta: path}
	if err := s.Migrate(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migraciones: %w", err)
	}
	if err := s.bootstrapOutbox(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("bootstrap outbox: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) Migrate() error {
	// El lock INTER-PROCESO va primero y es un mutex nombrado del SO ([07] del
	// plan): BEGIN IMMEDIATE arbitra bien, pero al agotarse el busy_timeout el
	// perdedor fallaba seco con «database is locked» y cero diagnóstico. El
	// mutex da espera acotada CON nombre del culpable probable. Ámbito Local\
	// a propósito (turnos 89/92): la BD vive en %LOCALAPPDATA% —por usuario—
	// y Global\ exigiría privilegios que un usuario estándar en Terminal
	// Server no tiene; el nombre sale de la ruta CANÓNICA case-insensitive,
	// porque dos grafías de la misma ruta serían dos mutex y ningún lock.
	suelta, err := lockDeMigraciones(s.ruta)
	if err != nil {
		return err
	}
	defer suelta()

	catalogo, err := migrations.Catalogo()
	if err != nil {
		return err
	}
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
	// El checksum llega por ALTER imperativo y no por migración numerada:
	// huevo-y-gallina — la tabla que registra migraciones no puede migrarse a
	// sí misma. "duplicate column" = ya estaba, cualquier otro error es real.
	for _, alter := range []string{
		`ALTER TABLE schema_migrations ADD COLUMN checksum TEXT`,
		`ALTER TABLE schema_migrations ADD COLUMN checksum_adopted_at TEXT`,
	} {
		if _, err := conn.ExecContext(ctx, alter); err != nil &&
			!strings.Contains(err.Error(), "duplicate column") {
			return fmt.Errorf("preparando schema_migrations: %w", err)
		}
	}
	for _, m := range catalogo {
		var aplicadaEl string
		var checksum sql.NullString
		err := conn.QueryRowContext(ctx,
			`SELECT applied_at, checksum FROM schema_migrations WHERE version = ?`, m.Nombre).
			Scan(&aplicadaEl, &checksum)
		switch {
		case err == sql.ErrNoRows:
			if _, err := conn.ExecContext(ctx, m.SQL); err != nil {
				return fmt.Errorf("migración %s: %w", m.Nombre, err)
			}
			if _, err := conn.ExecContext(ctx,
				`INSERT INTO schema_migrations (version, applied_at, checksum) VALUES (?, ?, ?)`,
				m.Nombre, nowISO(), m.Checksum); err != nil {
				return err
			}
		case err != nil:
			return err
		case !checksum.Valid:
			// Fila anterior al checksum: el SQL original se perdió con el
			// binario viejo, así que verificar la historia es imposible. Se
			// ADOPTA el embebido actual como verdad UNA sola vez, con fecha y
			// log — es adopción, no verificación, y se llama por su nombre
			// (trust-on-first-use, turno 92).
			if _, err := conn.ExecContext(ctx,
				`UPDATE schema_migrations SET checksum = ?, checksum_adopted_at = ? WHERE version = ?`,
				m.Checksum, nowISO(), m.Nombre); err != nil {
				return err
			}
			log.Printf("migraciones: checksum de %s ADOPTADO (fila anterior al versionado; no es verificación histórica)", m.Nombre)
		case checksum.String != m.Checksum:
			// Corrupción LÓGICA: el SQL embebido difiere del aplicado, así que
			// el esquema real ya no corresponde a ninguna versión conocida y
			// todo lo que se escriba encima hereda la ambigüedad. Se aborta
			// Open — P4 se conserva: los llamadores ya toleran store ausente
			// (el análisis corre sin persistencia y se dice). Con remedio,
			// porque «abortar» sin remedio es un ladrillo (turno 89).
			return fmt.Errorf("la migración %s difiere de la aplicada el %s: el esquema de esta BD "+
				"ya no corresponde a ninguna versión conocida y no se escribirá encima. "+
				"Remedio: restaura la BD desde una copia, o retírala para empezar una nueva "+
				"(se pierde el historial local, no el código)", m.Nombre, aplicadaEl)
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

// VerificarEsquema OBSERVA el estado de la BD sin tocarla: doctor la consume
// y por eso NO migra (Open migra; un doctor que repara al mirar no es un
// doctor — turno 92, defecto 1). Devuelve el detalle humano y, si el esquema
// divergió (checksum distinto en migración aplicada), un error.
func VerificarEsquema(path string) (string, error) {
	if path == "" {
		return "", errors.New("sin ruta de BD")
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return "sin BD todavía (se crea sola en el primer análisis)", nil
	}
	db, err := sql.Open("sqlite", dsnSQLite(path, busyTimeoutMS))
	if err != nil {
		return "", err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	catalogo, err := migrations.Catalogo()
	if err != nil {
		return "", err
	}
	var tieneTabla int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_migrations'`).
		Scan(&tieneTabla); err != nil {
		return "", fmt.Errorf("la BD no responde: %w", err)
	}
	if tieneTabla == 0 {
		return fmt.Sprintf("BD sin inicializar (%d migraciones se aplican al primer uso)", len(catalogo)), nil
	}
	// La columna checksum puede no existir aún (BD de un binario anterior):
	// eso no es divergencia, es una BD que el próximo Open pondrá al día.
	var tieneChecksum int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('schema_migrations') WHERE name='checksum'`).
		Scan(&tieneChecksum); err != nil {
		return "", err
	}
	pendientes, adoptables := 0, 0
	for _, m := range catalogo {
		var checksum sql.NullString
		var err error
		if tieneChecksum == 1 {
			err = db.QueryRow(`SELECT checksum FROM schema_migrations WHERE version = ?`, m.Nombre).Scan(&checksum)
		} else {
			var uno int
			err = db.QueryRow(`SELECT 1 FROM schema_migrations WHERE version = ?`, m.Nombre).Scan(&uno)
		}
		switch {
		case err == sql.ErrNoRows:
			pendientes++
		case err != nil:
			return "", err
		case tieneChecksum == 1 && !checksum.Valid:
			adoptables++
		case tieneChecksum == 1 && checksum.String != m.Checksum:
			return "", fmt.Errorf("la migración %s difiere de la aplicada: el esquema de esta BD "+
				"ya no corresponde a ninguna versión conocida (restaura desde copia o retira la BD)", m.Nombre)
		}
	}
	switch {
	case pendientes > 0:
		return fmt.Sprintf("%d migración(es) pendientes — se aplican solas en el próximo uso", pendientes), nil
	case adoptables > 0 || tieneChecksum == 0:
		return "esquema al día (checksums por adoptar en el próximo uso)", nil
	}
	return fmt.Sprintf("esquema al día (%d migraciones verificadas por checksum)", len(catalogo)), nil
}
