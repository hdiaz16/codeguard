// La telemetría central (fase 5): el SQLite local de cada máquina acumula
// runs, hallazgos y feedback; este archivo los EMPUJA a un Postgres
// compartido para que la precisión por regla y la tasa de bypass se midan a
// nivel organización, no dev por dev. El DDL de 001 se escribió portable
// SQLite → PostgreSQL a propósito (§9): el central se crea con las MISMAS
// migraciones embebidas, no con un DDL paralelo que divergiría.
//
// El DSN llega por CODEGUARD_TELEMETRY_DSN. Es un secreto con contraseña:
// vive en el entorno y jamás en el config del repo. Vacío significa "no hay
// central" — nada falla y nada avisa a cada rato.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib" // driver "pgx" para el Postgres central

	"codeguard/migrations"
)

// EnvTelemetriaDSN es la variable de entorno con el DSN del central. El
// prefijo "sqlite:" abre un archivo SQLite en su lugar: es el modo de prueba
// y también un central-de-pobres legítimo (un share de red compartido).
const EnvTelemetriaDSN = "CODEGUARD_TELEMETRY_DSN"

// Resumen dice cuántas filas viajaron al central en un empuje, por tabla.
// Los conteos son de filas que DE VERDAD entraron (RowsAffected): un
// reintento que choca contra ON CONFLICT cuenta cero, que es la verdad.
type Resumen struct {
	Repos, Runs, Findings, Feedback, LLMCalls int
}

func (r Resumen) Total() int {
	return r.Repos + r.Runs + r.Findings + r.Feedback + r.LLMCalls
}

// Las consultas van con '?' y rebind() las numera para Postgres. Cada tabla
// lleva su SELECT local y su INSERT central escritos completos: nada de armar
// SQL concatenando listas de columnas — una consulta que se arma con + es una
// consulta que otro editará mal (y el rulepack de la casa la bloquearía, con
// razón).
type tablaSync struct {
	nombre string
	sel    string // corre en el SQLite LOCAL: siempre con '?'
	ins    string // corre en el central: pasa por rb()
}

// El orden respeta las claves foráneas: repos → runs → findings → feedback y
// llm_calls. feedback referencia findings por finding_id, así que findings
// viaja antes; si aun así un feedback apuntara a un finding que no viajó (no
// debería: el orden lo impide), el INSERT falla con la FK y el error se oye —
// mejor un sync ruidoso que un central con huérfanos silenciosos.
var tablasIncrementales = []tablaSync{
	{
		nombre: "runs",
		sel: `SELECT id, repo_id, branch, started_at, finished_at, verdict, risk_score,
		             files_changed, lines_changed, ai_generated, llm_used, bypassed, ci_parity,
		             degraded_layers, rulepack_ver, config_hash, elapsed_ms, environment
		        FROM runs WHERE id > ? ORDER BY id LIMIT 500`,
		ins: `INSERT INTO runs (id, repo_id, branch, started_at, finished_at, verdict, risk_score,
		             files_changed, lines_changed, ai_generated, llm_used, bypassed, ci_parity,
		             degraded_layers, rulepack_ver, config_hash, elapsed_ms, environment)
		      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		      ON CONFLICT (id) DO NOTHING`,
	},
	{
		nombre: "findings",
		sel: `SELECT id, run_id, rule_id, engine, rule_key, pillar, severity, source,
		             blocking, verified, shown, file_path, line_start, line_end,
		             fingerprint, message, why, fix_hint, created_at
		        FROM findings WHERE id > ? ORDER BY id LIMIT 500`,
		ins: `INSERT INTO findings (id, run_id, rule_id, engine, rule_key, pillar, severity, source,
		             blocking, verified, shown, file_path, line_start, line_end,
		             fingerprint, message, why, fix_hint, created_at)
		      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		      ON CONFLICT (id) DO NOTHING`,
	},
	{
		nombre: "feedback",
		sel: `SELECT id, finding_id, verdict, comment, created_at
		        FROM feedback WHERE id > ? ORDER BY id LIMIT 500`,
		ins: `INSERT INTO feedback (id, finding_id, verdict, comment, created_at)
		      VALUES (?, ?, ?, ?, ?)
		      ON CONFLICT (id) DO NOTHING`,
	},
	{
		nombre: "llm_calls",
		sel: `SELECT id, run_id, pillar, model, prompt_tokens, completion_tokens, cost_micros,
		             latency_ms, status, findings_returned, findings_rejected, created_at
		        FROM llm_calls WHERE id > ? ORDER BY id LIMIT 500`,
		ins: `INSERT INTO llm_calls (id, run_id, pillar, model, prompt_tokens, completion_tokens,
		             cost_micros, latency_ms, status, findings_returned, findings_rejected, created_at)
		      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		      ON CONFLICT (id) DO NOTHING`,
	},
}

// repos va aparte y SIEMPRE completa: es diminuta, no crece con el uso y sus
// ids son sha256 — no ordenan por tiempo, así que una marca de agua ahí no
// significa nada. El upsert refresca last_seen_at de paso.
const selRepos = `SELECT id, remote_url, name, first_seen_at, last_seen_at FROM repos ORDER BY id`

const insRepos = `INSERT INTO repos (id, remote_url, name, first_seen_at, last_seen_at)
	VALUES (?, ?, ?, ?, ?)
	ON CONFLICT (id) DO UPDATE SET last_seen_at = excluded.last_seen_at`

// SyncCentral empuja lo local al central y devuelve cuántas filas viajaron.
// Es idempotente y reanudable: cada tabla incremental guarda en sync_marcas
// el último id confirmado, la marca avanza SOLO tras confirmar el lote, y el
// INSERT central lleva ON CONFLICT — si el proceso muere entre empujar y
// marcar, el reintento re-empuja y no duplica nada.
//
// Se apoya en que los ULID crecen con el tiempo. Dentro de un mismo
// milisegundo el orden es aleatorio, así que una fila escrita EXACTAMENTE en
// el milisegundo de la última empujada, mientras el sync corre, podría quedar
// detrás de la marca. Telemetría best-effort: se acepta y se deja escrito
// antes que complicar la marca por un caso de milisegundos.
func (s *Store) SyncCentral(ctx context.Context, dsn string) (Resumen, error) {
	var res Resumen
	central, rb, err := abrirCentral(dsn)
	if err != nil {
		return res, fmt.Errorf("abriendo el central: %w", err)
	}
	defer central.Close()

	if err := migrarCentral(ctx, central, rb); err != nil {
		return res, fmt.Errorf("esquema central: %w", err)
	}

	if res.Repos, err = s.empujarRepos(ctx, central, rb); err != nil {
		return res, fmt.Errorf("repos: %w", err)
	}

	destinos := map[string]*int{
		"runs": &res.Runs, "findings": &res.Findings,
		"feedback": &res.Feedback, "llm_calls": &res.LLMCalls,
	}
	for _, t := range tablasIncrementales {
		n, err := s.empujarIncremental(ctx, central, rb, t)
		*destinos[t.nombre] += n
		if err != nil {
			// El resumen parcial sale junto al error: lo que ya viajó, viajó,
			// y la marca lo recuerda — el siguiente intento sigue desde ahí.
			return res, fmt.Errorf("%s: %w", t.nombre, err)
		}
	}
	return res, nil
}

// abrirCentral distingue el destino por el DSN: el prefijo "sqlite:" abre un
// archivo con el driver modernc (pruebas, o un share de red como central de
// pobres); cualquier otra cosa va al driver pgx. El SQLite central va SIN WAL
// a propósito: WAL no funciona sobre sistemas de archivos de red, que es
// justo donde viviría.
func abrirCentral(dsn string) (*sql.DB, func(string) string, error) {
	if ruta, ok := strings.CutPrefix(dsn, "sqlite:"); ok {
		db, err := sql.Open("sqlite", ruta+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
		return db, func(q string) string { return q }, err
	}
	db, err := sql.Open("pgx", dsn)
	return db, rebind, err
}

// rebind numera los placeholders para Postgres: cada '?' pasa a ser $1..$N en
// orden de aparición. Es ingenuo a propósito: NO entiende literales de
// string, así que un '?' entre comillas también se numeraría. Las consultas
// de este archivo no llevan literales con '?' — mantenlo así antes que
// enseñarle comillas a esta función.
func rebind(consulta string) string {
	var b strings.Builder
	b.Grow(len(consulta) + 32)
	n := 0
	for i := 0; i < len(consulta); i++ {
		if consulta[i] != '?' {
			b.WriteByte(consulta[i])
			continue
		}
		n++
		b.WriteByte('$')
		b.WriteString(strconv.Itoa(n))
	}
	return b.String()
}

// migrarCentral aplica al central las MISMAS migraciones embebidas que
// Store.migrate() aplica en local: misma tabla schema_migrations, mismos
// archivos, misma aplicación transaccional e idempotente. Se reescribe aquí
// en vez de reutilizar el método porque el central necesita rebind en las
// consultas parametrizadas; el DDL va sin argumentos y pgx lo manda por el
// protocolo simple, que sí acepta varias sentencias por Exec.
func migrarCentral(ctx context.Context, db *sql.DB, rb func(string) string) error {
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
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
		if err := db.QueryRowContext(ctx,
			rb(`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`), name).Scan(&exists); err != nil {
			return err
		}
		if exists > 0 {
			continue
		}
		ddl, err := fs.ReadFile(migrations.FS, name)
		if err != nil {
			return err
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(ddl)); err != nil {
			_ = tx.Rollback() // el error de la migración ya va en el return
			return fmt.Errorf("migración central %s: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx,
			rb(`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`), name, nowISO()); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) empujarRepos(ctx context.Context, central *sql.DB, rb func(string) string) (int, error) {
	filas, err := leerFilas(ctx, s.db, selRepos, strings.Count(insRepos, "?"))
	if err != nil {
		return 0, err
	}
	return insertarLote(ctx, central, rb(insRepos), filas)
}

// empujarIncremental mueve una tabla por lotes de 500 (el LIMIT vive en el
// SELECT de cada tabla). El ciclo: leer lo que sigue a la marca, empujar el
// lote en una transacción del central, y SOLO entonces avanzar la marca
// local. Morir a media faena deja la marca atrás; el reintento re-empuja lo
// mismo y el ON CONFLICT (id) DO NOTHING lo deja pasar sin duplicar.
func (s *Store) empujarIncremental(ctx context.Context, central *sql.DB, rb func(string) string, t tablaSync) (int, error) {
	marca, err := s.leerMarca(t.nombre)
	if err != nil {
		return 0, err
	}
	ins := rb(t.ins)
	// El número de columnas es el de placeholders del INSERT: mismas columnas
	// en el SELECT y en el INSERT por construcción.
	ncols := strings.Count(t.ins, "?")
	total := 0
	for {
		filas, err := leerFilas(ctx, s.db, t.sel, ncols, marca)
		if err != nil {
			return total, err
		}
		if len(filas) == 0 {
			return total, nil
		}
		n, err := insertarLote(ctx, central, ins, filas)
		total += n
		if err != nil {
			return total, err
		}
		ultimo, ok := filas[len(filas)-1][0].(string)
		if !ok {
			return total, fmt.Errorf("el id de %s no es texto: %T", t.nombre, filas[len(filas)-1][0])
		}
		marca = ultimo
		if err := s.guardarMarca(t.nombre, marca); err != nil {
			return total, err
		}
	}
}

// leerFilas trae filas del SQLite local como valores crudos (string, int64 o
// nil según la columna): lo que sale de un driver entra tal cual en el otro.
// La primera columna de toda consulta de sync es el id — la marca sale de ahí.
func leerFilas(ctx context.Context, db *sql.DB, consulta string, ncols int, args ...any) ([][]any, error) {
	rows, err := db.QueryContext(ctx, consulta, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][]any
	for rows.Next() {
		vals := make([]any, ncols)
		ptrs := make([]any, ncols)
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		out = append(out, vals)
	}
	return out, rows.Err()
}

// insertarLote empuja las filas una a una dentro de UNA transacción del
// central y cuenta las que de verdad entraron (RowsAffected: las que chocan
// con ON CONFLICT no suman). Fila a fila a propósito: es lo simple, y no se
// pasa a multi-VALUES sin un número que lo pida.
func insertarLote(ctx context.Context, central *sql.DB, ins string, filas [][]any) (int, error) {
	if len(filas) == 0 {
		return 0, nil
	}
	tx, err := central.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	n := 0
	for _, f := range filas {
		r, err := tx.ExecContext(ctx, ins, f...)
		if err != nil {
			return 0, err
		}
		if a, aerr := r.RowsAffected(); aerr == nil {
			n += int(a)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return n, nil
}

// leerMarca y guardarMarca administran la marca de agua local (sync_marcas):
// el último id ULID que el central confirmó para cada tabla.
func (s *Store) leerMarca(tabla string) (string, error) {
	var ultima string
	err := s.db.QueryRow(`SELECT ultima FROM sync_marcas WHERE tabla = ?`, tabla).Scan(&ultima)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil // nunca se ha empujado: se viaja desde el principio
	}
	return ultima, err
}

func (s *Store) guardarMarca(tabla, ultima string) error {
	_, err := s.db.Exec(`INSERT INTO sync_marcas (tabla, ultima, actualizada_at)
		VALUES (?, ?, ?)
		ON CONFLICT (tabla) DO UPDATE SET ultima = excluded.ultima, actualizada_at = excluded.actualizada_at`,
		tabla, ultima, nowISO())
	return err
}
