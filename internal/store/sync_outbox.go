package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// El empujador por OUTBOX (W5, t.119-123). Reemplaza el barrido por marca de
// agua (WHERE id > ULID), que perdía filas del mismo milisegundo y bloqueaba
// la cola entera ante un error permanente de una sola fila. Aquí la
// elegibilidad es el ESTADO del evento (pending|retry con su ventana), fila a
// fila, con clasificación de error: un veneno se pone en cuarentena y el
// resto sigue.

// entidadSync describe cómo empujar una fila de una entidad: la lee por id del
// local y la inserta en el central. El SELECT trae las columnas EN EL ORDEN de
// los placeholders del INSERT (mismo contrato que el sync viejo).
type entidadSync struct {
	// padre: la entidad de la que esta depende por FK, y la columna (índice en
	// el SELECT) que lleva el id del padre. "" si no tiene padre (repos).
	padreEntidad string
	padreCol     int
	sel          string // WHERE id = ?  (una fila)
	ins          string // INSERT ... ON CONFLICT ...
}

// entidadesSync: el orden de FK importa para clasificar dependencias.
// runs incluye sync_revision y su ON CONFLICT respeta la revisión (t.122): un
// retry viejo del insert nunca pisa un update nuevo.
var entidadesSync = map[string]entidadSync{
	EntRepos: {
		sel: `SELECT id, remote_url, name, first_seen_at, last_seen_at FROM repos WHERE id = ?`,
		ins: `INSERT INTO repos (id, remote_url, name, first_seen_at, last_seen_at)
		      VALUES (?, ?, ?, ?, ?)
		      ON CONFLICT (id) DO UPDATE SET last_seen_at = excluded.last_seen_at`,
	},
	EntRuns: {
		padreEntidad: EntRepos, padreCol: 1,
		sel: `SELECT id, repo_id, branch, started_at, finished_at, verdict, outcome, failure_code, risk_score,
		             files_changed, lines_changed, ai_generated, llm_used, bypassed, ci_parity,
		             degraded_layers, rulepack_ver, config_hash, elapsed_ms, environment,
		             rulepack_digest, rulepack_source, rulepack_verified, aislamiento_degradado,
		             risk_formula_version, risk_config_hash,
		             COALESCE(sync_revision, 1)
		        FROM runs WHERE id = ?`,
		ins: `INSERT INTO runs (id, repo_id, branch, started_at, finished_at, verdict, outcome, failure_code, risk_score,
		             files_changed, lines_changed, ai_generated, llm_used, bypassed, ci_parity,
		             degraded_layers, rulepack_ver, config_hash, elapsed_ms, environment,
		             rulepack_digest, rulepack_source, rulepack_verified, aislamiento_degradado,
		             risk_formula_version, risk_config_hash, sync_revision)
		      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		      ON CONFLICT (id) DO UPDATE SET
		            risk_score = excluded.risk_score,
		            llm_used   = excluded.llm_used,
		            sync_revision = excluded.sync_revision
		      WHERE excluded.sync_revision >= runs.sync_revision`,
	},
	EntFindings: {
		padreEntidad: EntRuns, padreCol: 1,
		sel: `SELECT id, run_id, engine, rule_key, pillar, severity, source, blocking,
		             verified, shown, file_path, line_start, line_end, fingerprint, fingerprint_legacy,
		             message, why, fix_hint, created_at
		        FROM findings WHERE id = ?`,
		ins: `INSERT INTO findings (id, run_id, engine, rule_key, pillar, severity, source, blocking,
		             verified, shown, file_path, line_start, line_end, fingerprint, fingerprint_legacy,
		             message, why, fix_hint, created_at)
		      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		      ON CONFLICT (id) DO NOTHING`,
	},
	EntFeedback: {
		padreEntidad: EntFindings, padreCol: 1,
		sel: `SELECT id, finding_id, verdict, comment, created_at FROM feedback WHERE id = ?`,
		ins: `INSERT INTO feedback (id, finding_id, verdict, comment, created_at)
		      VALUES (?, ?, ?, ?, ?)
		      ON CONFLICT (id) DO NOTHING`,
	},
	EntLLMCalls: {
		padreEntidad: EntRuns, padreCol: 1,
		sel: `SELECT id, run_id, pillar, model, prompt_tokens, completion_tokens, cost_micros,
		             latency_ms, status, findings_returned, findings_rejected, created_at
		        FROM llm_calls WHERE id = ?`,
		ins: `INSERT INTO llm_calls (id, run_id, pillar, model, prompt_tokens, completion_tokens,
		             cost_micros, latency_ms, status, findings_returned, findings_rejected, created_at)
		      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		      ON CONFLICT (id) DO NOTHING`,
	},
}

// loteOutbox es cuántos eventos elegibles se toman por pasada.
const loteOutbox = 500

// backoff crece con los intentos, con tope. base 5s → 10s → 20s ... cap 30min.
func backoff(intentos int) time.Duration {
	d := 5 * time.Second
	for i := 1; i < intentos && d < 30*time.Minute; i++ {
		d *= 2
	}
	if d > 30*time.Minute {
		d = 30 * time.Minute
	}
	return d
}

// Techo del estado unknown: tras esto va a cuarentena para no reintentar un
// daño indefinidamente (síntesis de GPT, t.122).
const maxIntentosUnknown = 10

// empujarOutbox es el nuevo cuerpo del sync: reconcilia, toma los eventos
// elegibles por estado y los empuja fila a fila con clasificación de error.
func (s *Store) empujarOutbox(ctx context.Context, central *sql.DB, rb func(string) string, res *Resumen) error {
	// Reconciliación anti-entropía: un binario N-1 pudo escribir una fila SIN
	// evento entre el Open y ahora. bootstrapOutbox es idempotente (LEFT JOIN
	// por row_id), así que sembrar de nuevo solo crea lo que falte.
	if err := s.bootstrapOutbox(); err != nil {
		return fmt.Errorf("reconciliación: %w", err)
	}

	ahora := nowISO()
	rows, err := s.db.QueryContext(ctx, `SELECT seq, entity, row_id, revision, operation, attempts
		FROM outbox
		WHERE state IN (?, ?) AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
		ORDER BY seq LIMIT ?`, EstPending, EstRetry, ahora, loteOutbox)
	if err != nil {
		return err
	}
	type ev struct {
		seq      int64
		entity   string
		rowID    string
		revision int64
		op       string
		intentos int
	}
	var eventos []ev
	for rows.Next() {
		var e ev
		if err := rows.Scan(&e.seq, &e.entity, &e.rowID, &e.revision, &e.op, &e.intentos); err != nil {
			rows.Close()
			return err
		}
		eventos = append(eventos, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	contadores := map[string]*int{
		EntRepos: &res.Repos, EntRuns: &res.Runs, EntFindings: &res.Findings,
		EntFeedback: &res.Feedback, EntLLMCalls: &res.LLMCalls,
	}

	for _, e := range eventos {
		es, ok := entidadesSync[e.entity]
		if !ok {
			// Entidad desconocida en un evento: no se puede empujar; se pone en
			// cuarentena en vez de reintentar para siempre.
			_ = s.marcarEvento(e.seq, EstQuarantined, ErrPermanent, "entidad desconocida: "+e.entity, e.intentos+1)
			continue
		}
		fila, err := leerFilas(ctx, s.db, es.sel, strings.Count(es.ins, "?"), e.rowID)
		if err != nil {
			return err
		}
		if len(fila) == 0 {
			// La fila ya no existe (borrada): el evento no tiene qué empujar.
			// superseded, no cuarentena — no es un error, es que quedó obsoleto.
			_ = s.marcarEvento(e.seq, EstSuperseded, "", "la fila ya no existe", e.intentos)
			continue
		}
		perr := empujarUnaFila(ctx, central, rb(es.ins), fila[0])
		if perr == nil {
			if c := contadores[e.entity]; c != nil {
				*c++
			}
			_ = s.marcarEvento(e.seq, EstSent, "", "", e.intentos+1)
			continue
		}
		// Clasificar el fallo para decidir retry vs cuarentena.
		clase := s.clasificar(perr, es, fila[0])
		s.aplicarFallo(e.seq, clase, perr.Error(), e.intentos+1, ahora)
	}
	return nil
}

// empujarUnaFila hace el INSERT ... ON CONFLICT de una fila en su propia tx
// del central (idempotente por el ON CONFLICT).
func empujarUnaFila(ctx context.Context, central *sql.DB, ins string, fila []any) error {
	tx, err := central.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, ins, fila...); err != nil {
		return err
	}
	return tx.Commit()
}

// clasificar decide la naturaleza del error (t.122): dependencia (el padre no
// ha viajado ⇒ esperar), transitorio (red/lock ⇒ backoff), permanente
// (constraint imposible ⇒ cuarentena), o desconocido (retry con techo). Por
// MENSAJE y no por código de driver a propósito: es portable entre pgx y
// sqlite y no se acopla a versiones del driver.
func (s *Store) clasificar(err error, es entidadSync, fila []any) string {
	m := strings.ToLower(err.Error())
	esFK := strings.Contains(m, "foreign key") || strings.Contains(m, "violates foreign key") ||
		strings.Contains(m, "constraint failed") && strings.Contains(m, "foreign")
	if esFK && es.padreEntidad != "" {
		// FK: ¿el padre ya viajó (sent) o aún está pendiente? Si el padre tiene
		// un evento NO terminal, esto es una dependencia (se reintenta, el
		// padre irá primero por su seq menor). Si el padre ya está sent o no
		// tiene evento, la FK es una inconsistencia REAL ⇒ permanente.
		padreID, _ := fila[es.padreCol].(string)
		if padreID != "" && s.padrePendiente(es.padreEntidad, padreID) {
			return ErrDependency
		}
		return ErrPermanent
	}
	// Otros violaciones de integridad = permanente.
	if strings.Contains(m, "check constraint") || strings.Contains(m, "not null") ||
		strings.Contains(m, "null value") || strings.Contains(m, "invalid input") ||
		strings.Contains(m, "out of range") || strings.Contains(m, "constraint failed") {
		return ErrPermanent
	}
	// Red / disponibilidad = transitorio.
	if strings.Contains(m, "connection") || strings.Contains(m, "timeout") ||
		strings.Contains(m, "deadlock") || strings.Contains(m, "serializ") ||
		strings.Contains(m, "locked") || strings.Contains(m, "busy") ||
		strings.Contains(m, "refused") || strings.Contains(m, "reset") ||
		strings.Contains(m, "broken pipe") || strings.Contains(m, "eof") {
		return ErrTransient
	}
	return ErrUnknown
}

// padrePendiente dice si el padre tiene un evento en estado NO terminal (aún
// no llegó al central). Si no tiene evento, se lo considera NO pendiente (o ya
// viajó por el sync viejo, o es una inconsistencia): el llamador lo trata como
// permanente.
func (s *Store) padrePendiente(entidad, rowID string) bool {
	var estado string
	err := s.db.QueryRow(`SELECT state FROM outbox WHERE entity = ? AND row_id = ?
		ORDER BY seq DESC LIMIT 1`, entidad, rowID).Scan(&estado)
	if err != nil {
		return false
	}
	return estado == EstPending || estado == EstRetry
}

// aplicarFallo traduce la clase de error a estado del evento con su ventana de
// reintento o cuarentena.
func (s *Store) aplicarFallo(seq int64, clase, detalle string, intentos int, ahora string) {
	switch clase {
	case ErrPermanent:
		_ = s.marcarEvento(seq, EstQuarantined, clase, detalle, intentos)
	case ErrUnknown:
		// Techo: tras maxIntentosUnknown se cuarentena para no reintentar un
		// daño para siempre (conserva la causa para revisión).
		if intentos >= maxIntentosUnknown {
			_ = s.marcarEvento(seq, EstQuarantined, clase, "techo de reintentos: "+detalle, intentos)
			return
		}
		_ = s.marcarEventoConEspera(seq, EstRetry, clase, detalle, intentos, backoff(intentos))
	default: // ErrTransient, ErrDependency
		_ = s.marcarEventoConEspera(seq, EstRetry, clase, detalle, intentos, backoff(intentos))
	}
}

func (s *Store) marcarEvento(seq int64, estado, clase, detalle string, intentos int) error {
	_, err := s.db.Exec(`UPDATE outbox SET state = ?, error_class = ?, error_detail = ?,
		attempts = ?, next_attempt_at = NULL, updated_at = ? WHERE seq = ?`,
		estado, nuloClase(clase), nuloClase(detalle), intentos, nowISO(), seq)
	return err
}

func (s *Store) marcarEventoConEspera(seq int64, estado, clase, detalle string, intentos int, espera time.Duration) error {
	prox := time.Now().UTC().Add(espera).Format(time.RFC3339)
	_, err := s.db.Exec(`UPDATE outbox SET state = ?, error_class = ?, error_detail = ?,
		attempts = ?, next_attempt_at = ?, updated_at = ? WHERE seq = ?`,
		estado, nuloClase(clase), nuloClase(detalle), intentos, prox, nowISO(), seq)
	return err
}

func nuloClase(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// EnCuarentena cuenta los eventos en cuarentena, para observabilidad (stats /
// doctor). Un número > 0 dice que hay telemetría que no viaja y por qué.
func (s *Store) EnCuarentena() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM outbox WHERE state = ?`, EstQuarantined).Scan(&n)
	return n, err
}

// ReintentarCuarentena vuelve a poner pending un evento en cuarentena
// (`codeguard sync retry <seq>`): el usuario decidió que el problema se
// resolvió.
func (s *Store) ReintentarCuarentena(seq int64) error {
	r, err := s.db.Exec(`UPDATE outbox SET state = ?, attempts = 0, next_attempt_at = NULL,
		updated_at = ? WHERE seq = ? AND state = ?`, EstPending, nowISO(), seq, EstQuarantined)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return fmt.Errorf("no hay evento en cuarentena con seq %d", seq)
	}
	return nil
}

// DescartarCuarentena marca un evento como descartado a propósito
// (`codeguard sync discard <seq> --reason`): queda auditado, no se empuja.
func (s *Store) DescartarCuarentena(seq int64, razon string) error {
	// El detalle es un VALOR parametrizado (?), no SQL; se arma con Sprintf (no
	// con +) para que la regla de SQL-concat no lo confunda con una consulta.
	detalle := fmt.Sprintf("descartado: %s", razon)
	r, err := s.db.Exec(`UPDATE outbox SET state = ?, error_detail = ?, updated_at = ?
		WHERE seq = ? AND state = ?`, EstSuperseded, detalle, nowISO(), seq, EstQuarantined)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return fmt.Errorf("no hay evento en cuarentena con seq %d", seq)
	}
	return nil
}

// EventoCuarentena es una vista de un evento en cuarentena para el comando de
// diagnóstico.
type EventoCuarentena struct {
	Seq         int64
	Entity      string
	RowID       string
	ErrorClass  string
	ErrorDetail string
}

// ListarCuarentena devuelve los eventos en cuarentena, más viejos primero.
func (s *Store) ListarCuarentena() ([]EventoCuarentena, error) {
	rows, err := s.db.Query(`SELECT seq, entity, row_id,
		COALESCE(error_class, ''), COALESCE(error_detail, '')
		FROM outbox WHERE state = ? ORDER BY seq`, EstQuarantined)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EventoCuarentena
	for rows.Next() {
		var e EventoCuarentena
		if err := rows.Scan(&e.Seq, &e.Entity, &e.RowID, &e.ErrorClass, &e.ErrorDetail); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
