package store

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"time"
)

// ExportarRuns saca el historial de análisis a CSV para poder mirarlo en una
// hoja de cálculo: cuántos commits se bloquearon, por qué regla, en qué repo.

type FiltroExport struct {
	Repo    string
	Desde   string
	Hasta   string
	Solo    string // "block" | "pass" | ""
	Limite  int
	Detalle bool
}

func (s *Store) ExportarRuns(destino string, f FiltroExport) (int, error) {
	// La cláusula sigue siendo condicional; lo que nunca se concatena son los
	// VALORES. Van como parámetros, así que da igual lo que traigan.
	//
	// Los conteos salen de la tabla findings: runs no guarda totales — la
	// primera versión de esto consultaba columnas que no existían y compiló
	// igual, porque el SQL es texto. Lo atrapó el primer test del paquete.
	consulta := `SELECT r.id, r.repo_id, r.branch, r.verdict,
	       (SELECT COUNT(*) FROM findings f WHERE f.run_id = r.id AND f.blocking = 1),
	       (SELECT COUNT(*) FROM findings f WHERE f.run_id = r.id AND f.blocking = 0),
	       r.started_at
	  FROM runs r WHERE 1=1`
	var args []any
	if f.Repo != "" {
		consulta += " AND r.repo_id = ?"
		args = append(args, f.Repo)
	}
	if f.Desde != "" {
		consulta += " AND r.started_at >= ?"
		args = append(args, f.Desde)
	}
	if f.Hasta != "" {
		consulta += " AND r.started_at <= ?"
		args = append(args, f.Hasta)
	}
	if f.Solo != "" {
		consulta += " AND r.verdict = ?"
		args = append(args, f.Solo)
	}
	consulta += " ORDER BY r.started_at DESC"
	if f.Limite > 0 {
		consulta += " LIMIT ?"
		args = append(args, f.Limite)
	}

	filas, err := s.db.Query(consulta, args...)
	if err != nil {
		return 0, err
	}
	defer filas.Close()

	out, err := os.Create(destino)
	if err != nil {
		return 0, err
	}

	w := csv.NewWriter(out)
	if err := w.Write([]string{"id", "repo", "rama", "veredicto", "bloqueantes", "avisos", "fecha"}); err != nil {
		out.Close()
		return 0, err
	}

	n := 0
	for filas.Next() {
		var id, repo, rama, veredicto, fecha string
		var bloq, avisos int
		// Una fila ilegible es un dato corrupto, no un CSV a medias sin avisar.
		if err := filas.Scan(&id, &repo, &rama, &veredicto, &bloq, &avisos, &fecha); err != nil {
			out.Close()
			return n, fmt.Errorf("fila %d ilegible: %w", n+1, err)
		}
		if err := w.Write([]string{id, repo, rama, veredicto,
			strconv.Itoa(bloq), strconv.Itoa(avisos), fecha}); err != nil {
			out.Close()
			return n, err
		}
		n++
	}
	if err := filas.Err(); err != nil {
		out.Close()
		return n, err
	}
	w.Flush()
	if err := w.Error(); err != nil {
		out.Close()
		return n, err
	}
	// Cerrar es donde afloran los errores de escritura diferidos: un CSV
	// truncado que se anuncia como completo es peor que no tenerlo.
	if err := out.Close(); err != nil {
		return n, fmt.Errorf("el CSV quedó incompleto: %w", err)
	}
	return n, nil
}

// ResumenSemanal describe la salud del repo en la última semana.
func (s *Store) ResumenSemanal(repoID string) (string, error) {
	desde := time.Now().AddDate(0, 0, -7).Format(time.RFC3339)
	filas, err := s.db.Query(`SELECT r.verdict,
	       (SELECT COUNT(*) FROM findings f WHERE f.run_id = r.id AND f.blocking = 1)
	  FROM runs r WHERE r.repo_id = ? AND r.started_at >= ?`, repoID, desde)
	if err != nil {
		return "", err
	}
	defer filas.Close()

	var total, bloqueados, limpios, conAvisos, muyMalos, sinNada int
	for filas.Next() {
		var v string
		var b int
		// Misma regla que el CSV: una fila ilegible es dato corrupto, no un
		// resumen que cuenta de menos sin avisar.
		if err := filas.Scan(&v, &b); err != nil {
			return "", fmt.Errorf("run ilegible en el resumen semanal: %w", err)
		}
		total++
		switch v {
		case "block":
			bloqueados++
			if b > 5 {
				muyMalos++
			}
		case "pass":
			if b == 0 {
				limpios++
			} else {
				conAvisos++
			}
		default: // skipped, degraded, vacío: no cuentan como limpio ni bloqueado
			sinNada++
		}
	}
	// Un cursor que murió a mitad de camino dejaría un conteo parcial que se
	// lee igual que uno completo; los otros lectores del store ya lo comprueban.
	if err := filas.Err(); err != nil {
		return "", err
	}
	if total == 0 {
		return "sin análisis esta semana", nil
	}
	pct := float64(bloqueados) / float64(total) * 100
	if pct > 40 && muyMalos > 2 {
		return fmt.Sprintf("%d de %d commits bloqueados (%.0f%%), %d con más de cinco problemas: algo va mal",
			bloqueados, total, pct, muyMalos), nil
	} else if pct > 40 {
		return fmt.Sprintf("%d de %d commits bloqueados (%.0f%%)", bloqueados, total, pct), nil
	} else if limpios == total {
		return fmt.Sprintf("los %d commits de la semana pasaron limpios", total), nil
	}
	return fmt.Sprintf("%d commits: %d limpios, %d con avisos, %d bloqueados, %d omitidos",
		total, limpios, conAvisos, bloqueados, sinNada), nil
}

// comentario nuevo
