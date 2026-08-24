package store

import (
	"database/sql"
	"os"
	"time"

	"codeguard/internal/capas"
)

// guardarCapas escribe, DENTRO de la tx del run, una fila de run_layers por cada
// capa y actualiza la salud acumulada de cada (repo, motor). Es LOCAL: no encola
// eventos de outbox (el historial de salud lo lee el doctor en esta máquina; la
// agregación de flota es trabajo posterior). W6 Q3.
func guardarCapas(tx *sql.Tx, runID, repoID string, cs []capas.Capa) error {
	ahora := nowISO()
	for _, c := range cs {
		// unit_kind: los motores que DECLARAN cobertura fina (planearon
		// objetivos) miran «file»; el resto corrió como capa entera («layer»).
		unitKind := "layer"
		if c.Planeadas > 0 {
			unitKind = "file"
		}
		if _, err := tx.Exec(`INSERT INTO run_layers
			(run_id, engine, unit_kind, state, reason_code, planned_count, complete_count, partial_count, findings, ms, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			runID, c.Motor, unitKind, c.Estado, nulo(c.MotivoCodigo),
			c.Planeadas, c.Completas, c.Parciales, c.Hallazgos, c.Ms, ahora); err != nil {
			return err
		}
		if err := actualizarSalud(tx, repoID, c, ahora); err != nil {
			return err
		}
	}
	return nil
}

// actualizarSalud lleva la racha de fallos consecutivos de una capa. La regla,
// firmada en la síntesis (Q3): la racha se reinicia SOLO cuando la capa aplica Y
// completa; un no-aplica NI CURA NI ROMPE (la capa no tenía nada que mirar), así
// que ni toca la fila. Un fallo (degradada/ausente) incrementa la racha y
// conserva el inicio de la racha; el motivo vigente se guarda como reason_code
// (los detalles libres no cuentan: «misma reason_code con detalles distintos es
// la misma»).
func actualizarSalud(tx *sql.Tx, repoID string, c capas.Capa, ahora string) error {
	if c.Estado == capas.NoAplica {
		return nil // ni cura ni rompe
	}

	var reason, firstFail sql.NullString
	var racha int
	err := tx.QueryRow(`SELECT reason_code, consecutive_failures, first_failure_at
		FROM layer_health WHERE repo_id = ? AND engine = ?`, repoID, c.Motor).
		Scan(&reason, &racha, &firstFail)
	existe := err == nil
	if err != nil && err != sql.ErrNoRows {
		return err
	}

	if c.Cayo() {
		// Fallo: por defecto empieza una racha nueva (1) con first_failure =
		// ahora; si ya venía fallando, incrementa y conserva el inicio. El
		// incremento va con ++ y no con `racha + 1` a propósito: la regla
		// go-sql-concat marca cualquier `x + y` que fluya a un Exec como fuente
		// de taint, aunque aquí sea un contador entero que viaja como PLACEHOLDER
		// (inyección imposible). Ver nota de la regla en la bitácora.
		nueva := 1
		inicio := sql.NullString{String: ahora, Valid: true}
		if existe && racha > 0 {
			nueva = racha
			nueva++
			inicio = firstFail
		}
		if existe {
			_, err = tx.Exec(`UPDATE layer_health
				SET reason_code=?, consecutive_failures=?, first_failure_at=?, last_failure_at=?, updated_at=?
				WHERE repo_id=? AND engine=?`,
				c.MotivoCodigo, nueva, inicio, ahora, ahora, repoID, c.Motor)
			return err
		}
		_, err = tx.Exec(`INSERT INTO layer_health
			(repo_id, engine, reason_code, consecutive_failures, first_failure_at, last_failure_at, last_success_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, NULL, ?)`,
			repoID, c.Motor, c.MotivoCodigo, nueva, ahora, ahora, ahora)
		return err
	}

	// Éxito (Corrió: aplicó y completó): reinicia la racha.
	if existe {
		_, err = tx.Exec(`UPDATE layer_health
			SET reason_code=NULL, consecutive_failures=0, first_failure_at=NULL, last_success_at=?, updated_at=?
			WHERE repo_id=? AND engine=?`,
			ahora, ahora, repoID, c.Motor)
		return err
	}
	_, err = tx.Exec(`INSERT INTO layer_health
		(repo_id, engine, reason_code, consecutive_failures, first_failure_at, last_failure_at, last_success_at, updated_at)
		VALUES (?, ?, NULL, 0, NULL, NULL, ?, ?)`,
		repoID, c.Motor, ahora, ahora)
	return err
}

// SaludCapa es el estado acumulado de una capa en un repo, ya con las fechas
// parseadas (hora cero = sin dato). Lo consume el doctor para decidir recurrente
// o persistente (W6 Q4/tanda e).
type SaludCapa struct {
	Motor        string
	MotivoCodigo string
	RachaFallos  int
	PrimerFallo  time.Time
	UltimoFallo  time.Time
	UltimoExito  time.Time
}

const consultaSalud = `SELECT engine, reason_code, consecutive_failures,
	first_failure_at, last_failure_at, last_success_at
	FROM layer_health WHERE repo_id = ? ORDER BY engine`

// SaludDeCapas devuelve el estado de salud de todas las capas del repo, ordenado
// por motor. Solo trae las que tienen fila (las que han corrido alguna vez).
func (s *Store) SaludDeCapas(repoID string) ([]SaludCapa, error) {
	rows, err := s.db.Query(consultaSalud, repoID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return escanearSalud(rows)
}

// SaludDeCapasSoloLectura lee el historial de salud SIN migrar ni escribir: el
// doctor OBSERVA, no repara. Devuelve vacío (sin error) cuando la BD o la tabla
// aún no existen —una máquina recién instalada o una BD de un binario anterior
// a la migración 008—, que para el doctor es «todavía no hay historial», no una
// avería.
func SaludDeCapasSoloLectura(path, repoID string) ([]SaludCapa, error) {
	if path == "" {
		return nil, nil
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, nil
	}
	db, err := sql.Open("sqlite", dsnSQLite(path, busyTimeoutMS))
	if err != nil {
		return nil, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var tiene int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='layer_health'`).
		Scan(&tiene); err != nil {
		return nil, err
	}
	if tiene == 0 {
		return nil, nil
	}
	rows, err := db.Query(consultaSalud, repoID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return escanearSalud(rows)
}

func escanearSalud(rows *sql.Rows) ([]SaludCapa, error) {
	var out []SaludCapa
	for rows.Next() {
		var sc SaludCapa
		var reason, first, lastFail, lastOk sql.NullString
		if err := rows.Scan(&sc.Motor, &reason, &sc.RachaFallos, &first, &lastFail, &lastOk); err != nil {
			return nil, err
		}
		sc.MotivoCodigo = reason.String
		sc.PrimerFallo = parseISO(first)
		sc.UltimoFallo = parseISO(lastFail)
		sc.UltimoExito = parseISO(lastOk)
		out = append(out, sc)
	}
	return out, rows.Err()
}

// parseISO devuelve la hora RFC3339 guardada, o la hora cero si es NULL o no
// parsea (un timestamp corrupto no debe tumbar la lectura de salud).
func parseISO(s sql.NullString) time.Time {
	if !s.Valid {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s.String)
	if err != nil {
		return time.Time{}
	}
	return t
}
