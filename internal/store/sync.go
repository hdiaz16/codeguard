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
	"fmt"
	"log"
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
// Los conteos son de filas que DE VERDAD se escribieron (RowsAffected): un
// reintento que choca contra ON CONFLICT DO NOTHING cuenta cero, que es la
// verdad. Runs es la excepción y también por decir la verdad: su ON CONFLICT
// es DO UPDATE (ver tablasIncrementales), así que un run re-empujado sí escribe
// —corrige risk_score y llm_used— y sí cuenta.
type Resumen struct {
	Repos, Runs, Findings, Feedback, LLMCalls int
}

func (r Resumen) Total() int {
	return r.Repos + r.Runs + r.Findings + r.Feedback + r.LLMCalls
}

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
	central, rb, esPG, err := abrirCentral(dsn)
	if err != nil {
		return res, fmt.Errorf("abriendo el central: %w", err)
	}
	defer central.Close()

	if err := migrarCentral(ctx, central, rb, esPG); err != nil {
		return res, fmt.Errorf("esquema central: %w", err)
	}

	// El empuje por OUTBOX (W5): reemplaza el barrido por marca de agua que
	// perdía filas del mismo milisegundo y se envenenaba con un error
	// permanente de una fila. Un error de transporte GLOBAL (el central caído)
	// sí aborta la pasada —no tiene sentido quemar 500 intentos idénticos—;
	// los errores atribuibles a UNA fila la ponen en retry/cuarentena y el
	// resto sigue.
	if err := s.empujarOutbox(ctx, central, rb, &res); err != nil {
		return res, fmt.Errorf("outbox: %w", err)
	}
	return res, nil
}

// abrirCentral distingue el destino por el DSN: el prefijo "sqlite:" abre un
// archivo con el driver modernc (pruebas, o un share de red como central de
// pobres); cualquier otra cosa va al driver pgx. El SQLite central va SIN WAL
// a propósito: WAL no funciona sobre sistemas de archivos de red, que es
// justo donde viviría. El tercer valor dice si el destino es Postgres: el
// migrador central lo usa para elegir el lock correcto de cada dialecto.
func abrirCentral(dsn string) (*sql.DB, func(string) string, bool, error) {
	if ruta, ok := strings.CutPrefix(dsn, "sqlite:"); ok {
		db, err := sql.Open("sqlite", ruta+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
		return db, func(q string) string { return q }, false, err
	}
	db, err := sql.Open("pgx", dsn)
	return db, rebind, true, err
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
// Store.Migrate() aplica en local: EL MISMO catálogo (migrations.Catalogo —
// parser, orden y validación de duplicados únicos; había DOS criterios de
// orden que coincidían de casualidad), la misma verificación por checksum y
// el mismo trust-on-first-use para filas anteriores al versionado.
//
// El lock es por dialecto y por eso abrirCentral declara cuál es el destino:
//   - Postgres: pg_advisory_xact_lock DENTRO de la única transacción — un
//     lock de sesión tomado desde *sql.DB podría vivir en OTRA conexión del
//     pool y no proteger nada (turno 92). La clave deriva del nombre de la
//     BD, no es una constante del binario: dos centrales en el mismo cluster
//     no comparten lock, y nadie hereda un falso aislamiento reutilizándola.
//   - SQLite: BEGIN IMMEDIATE, que es el lock nativo del archivo.
//
// Antes no había NINGUNO y el COUNT iba fuera de la transacción: dos `sync`
// simultáneos veían ambos exists==0 y el segundo reventaba contra el PRIMARY
// KEY — el check-then-act de libro.
func migrarCentral(ctx context.Context, db *sql.DB, rb func(string) string, esPG bool) error {
	catalogo, err := migrations.Catalogo()
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	confirmado := false
	defer func() {
		if !confirmado {
			_ = tx.Rollback()
		}
	}()
	if esPG {
		if _, err := tx.ExecContext(ctx,
			`SELECT pg_advisory_xact_lock(hashtextextended(current_database() || ':codeguard:schema', 0))`); err != nil {
			return fmt.Errorf("tomando el advisory lock del central: %w", err)
		}
	}
	// SQLite central: la transacción ya está abierta (BeginTx) y el primer
	// write de abajo (CREATE TABLE IF NOT EXISTS) toma el lock del archivo;
	// el perdedor espera su busy_timeout y falla VISIBLE, no corrompe. No se
	// intenta BEGIN IMMEDIATE dentro de una transacción ya empezada.
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return err
	}
	for _, alter := range []string{
		`ALTER TABLE schema_migrations ADD COLUMN checksum TEXT`,
		`ALTER TABLE schema_migrations ADD COLUMN checksum_adopted_at TEXT`,
	} {
		if _, err := tx.ExecContext(ctx, alter); err != nil {
			// "duplicate column" (sqlite) / "already exists" (pg) = ya estaba.
			if !strings.Contains(err.Error(), "duplicate column") && !strings.Contains(err.Error(), "already exists") {
				return fmt.Errorf("preparando schema_migrations central: %w", err)
			}
		}
	}
	for _, m := range catalogo {
		var aplicadaEl string
		var checksum sql.NullString
		err := tx.QueryRowContext(ctx,
			rb(`SELECT applied_at, checksum FROM schema_migrations WHERE version = ?`), m.Nombre).
			Scan(&aplicadaEl, &checksum)
		switch {
		case err == sql.ErrNoRows:
			if _, err := tx.ExecContext(ctx, m.SQL); err != nil {
				return fmt.Errorf("migración central %s: %w", m.Nombre, err)
			}
			if _, err := tx.ExecContext(ctx,
				rb(`INSERT INTO schema_migrations (version, applied_at, checksum) VALUES (?, ?, ?)`),
				m.Nombre, nowISO(), m.Checksum); err != nil {
				return err
			}
		case err != nil:
			return err
		case !checksum.Valid:
			if _, err := tx.ExecContext(ctx,
				rb(`UPDATE schema_migrations SET checksum = ?, checksum_adopted_at = ? WHERE version = ?`),
				m.Checksum, nowISO(), m.Nombre); err != nil {
				return err
			}
			log.Printf("central: checksum de %s ADOPTADO (fila anterior al versionado)", m.Nombre)
		case checksum.String != m.Checksum:
			return fmt.Errorf("la migración %s difiere de la aplicada en el central el %s: "+
				"su esquema ya no corresponde a ninguna versión conocida — nada se empuja encima. "+
				"Remedio: restaura el central desde copia o migra a una BD central nueva", m.Nombre, aplicadaEl)
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	confirmado = true
	return nil
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
