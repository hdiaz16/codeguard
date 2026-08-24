package store

import (
	"database/sql"
	"fmt"
)

// Estados y clases de error del outbox (W5, t.119-123). El estado es la
// fuente de verdad de la elegibilidad para empujar, NO una marca de agua: un
// evento en retry no arrastra a los posteriores ni se pierde.
const (
	EstPending     = "pending"
	EstRetry       = "retry"
	EstSent        = "sent"
	EstSuperseded  = "superseded"
	EstQuarantined = "quarantined"

	ErrTransient  = "transient"  // red/timeout/lock: reintento con backoff
	ErrDependency = "dependency" // FK con padre aún no enviado: espera al padre
	ErrPermanent  = "permanent"  // constraint/tipo: cuarentena con causa
	ErrUnknown    = "unknown"    // reintenta con techo, luego cuarentena
)

// entidades del outbox — el orden es el de las claves foráneas
// (repos→runs→findings→feedback/llm_calls), que la siembra y el empuje
// respetan para no violar FK en el central.
const (
	EntRepos    = "repos"
	EntRuns     = "runs"
	EntFindings = "findings"
	EntFeedback = "feedback"
	EntLLMCalls = "llm_calls"
)

// siguienteSeq incrementa y devuelve la secuencia monotónica DENTRO de la tx
// del alta. Es la raíz del fix: el seq refleja el orden de commit real (bajo
// el escritor serializado del local), sin las colisiones de milisegundo del
// ULID. Toda alta que quiera un evento pasa por aquí, en su misma tx.
func siguienteSeq(tx *sql.Tx) (int64, error) {
	var seq int64
	// UPDATE ... RETURNING no es portable al SQLite viejo; se hace el par
	// leer+incrementar, seguro porque la tx tiene el lock de escritura (un
	// solo escritor). El singleton siempre existe (lo inserta la migración).
	if err := tx.QueryRow(`SELECT next_seq FROM outbox_sequence WHERE singleton = 1`).Scan(&seq); err != nil {
		return 0, fmt.Errorf("outbox: leyendo secuencia: %w", err)
	}
	if _, err := tx.Exec(`UPDATE outbox_sequence SET next_seq = next_seq + 1 WHERE singleton = 1`); err != nil {
		return 0, fmt.Errorf("outbox: avanzando secuencia: %w", err)
	}
	return seq, nil
}

// encolarEvento escribe un evento pending en la MISMA tx que el alta. op es
// insert o update; revision es 1 para inmutables y el número creciente de la
// entidad mutable (runs). La creación es idempotente por
// UNIQUE(entity,row_id,revision): si el evento ya existe (reintento de una tx
// que no llegó a commitear), no se duplica.
func encolarEvento(tx *sql.Tx, entity, rowID, op string, revision int64) error {
	seq, err := siguienteSeq(tx)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO outbox
		(seq, entity, row_id, revision, operation, state, attempts, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)
		ON CONFLICT (entity, row_id, revision) DO NOTHING`,
		seq, entity, rowID, revision, op, EstPending, nowISO(), nowISO())
	if err != nil {
		return fmt.Errorf("outbox: encolando %s/%s: %w", entity, rowID, err)
	}
	return nil
}

// bootstrapOutbox siembra los eventos de las filas que YA existían antes de la
// migración 007 (runs/findings/feedback/llm_calls/repos escritos por binarios
// previos), y reconcilia lo que un binario N-1 pudiera escribir SIN evento
// tras la migración (una actualización a medias de daemon/CLI). Es la red de
// seguridad; las escrituras nuevas crean su evento en su propia tx.
//
// Corre en Store.Open, SOLO en el local (el central nunca abre por aquí con
// datos de negocio propios). NO se traduce ninguna marca vieja de sync_marcas:
// un ULID potencialmente perdido no da un seq honesto. Se siembra en orden de
// FK (repos→runs→findings→feedback/llm_calls) para que el empuje no viole
// claves foráneas en el central; el replay es absorbido por el ON CONFLICT del
// central (un reenvío único, sin duplicación semántica).
func (s *Store) bootstrapOutbox() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	// entidad → SELECT de las filas SIN evento (LEFT JOIN por row_id), en orden
	// de FK. Consultas FIJAS por entidad (nada de concatenar el nombre de tabla
	// en SQL — la regla de la casa lo prohíbe, con razón): así el bootstrap
	// inicial y la reconciliación de escritores viejos son EL MISMO barrido
	// idempotente.
	selSinEvento := []struct {
		ent string
		sel string
	}{
		{EntRepos, `SELECT t.id FROM repos t LEFT JOIN outbox o ON o.entity = ? AND o.row_id = t.id WHERE o.seq IS NULL ORDER BY t.id`},
		{EntRuns, `SELECT t.id FROM runs t LEFT JOIN outbox o ON o.entity = ? AND o.row_id = t.id WHERE o.seq IS NULL ORDER BY t.id`},
		{EntFindings, `SELECT t.id FROM findings t LEFT JOIN outbox o ON o.entity = ? AND o.row_id = t.id WHERE o.seq IS NULL ORDER BY t.id`},
		{EntFeedback, `SELECT t.id FROM feedback t LEFT JOIN outbox o ON o.entity = ? AND o.row_id = t.id WHERE o.seq IS NULL ORDER BY t.id`},
		{EntLLMCalls, `SELECT t.id FROM llm_calls t LEFT JOIN outbox o ON o.entity = ? AND o.row_id = t.id WHERE o.seq IS NULL ORDER BY t.id`},
	}
	for _, e := range selSinEvento {
		rows, err := tx.Query(e.sel, e.ent)
		if err != nil {
			return fmt.Errorf("bootstrap %s: %w", e.ent, err)
		}
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		for _, id := range ids {
			// runs viejo sin sync_revision se normaliza a 1 (la revisión con la
			// que nace un insert). El bootstrap encola siempre op=insert: es la
			// primera vez que el central ve la fila.
			if e.ent == EntRuns {
				if _, err := tx.Exec(`UPDATE runs SET sync_revision = COALESCE(sync_revision, 1) WHERE id = ?`, id); err != nil {
					return err
				}
			}
			if err := encolarEvento(tx, e.ent, id, "insert", 1); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}
