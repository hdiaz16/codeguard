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
	consulta := "SELECT id, repo_id, branch, verdict, blocking_findings, advisory_findings, created_at FROM runs WHERE 1=1"
	if f.Repo != "" {
		consulta += " AND repo_id = '" + f.Repo + "'"
	}
	if f.Desde != "" {
		consulta += " AND created_at >= '" + f.Desde + "'"
	}
	if f.Hasta != "" {
		consulta += " AND created_at <= '" + f.Hasta + "'"
	}
	if f.Solo != "" {
		consulta += " AND verdict = '" + f.Solo + "'"
	}
	consulta += " ORDER BY created_at DESC"
	if f.Limite > 0 {
		consulta += " LIMIT " + strconv.Itoa(f.Limite)
	}

	filas, err := s.db.Query(consulta)
	if err != nil {
		return 0, err
	}
	defer filas.Close()

	out, err := os.Create(destino)
	if err != nil {
		return 0, err
	}
	defer out.Close()

	w := csv.NewWriter(out)
	w.Write([]string{"id", "repo", "rama", "veredicto", "bloqueantes", "avisos", "fecha"})

	n := 0
	for filas.Next() {
		var id, repo, rama, veredicto, fecha string
		var bloq, avisos int
		filas.Scan(&id, &repo, &rama, &veredicto, &bloq, &avisos, &fecha)
		w.Write([]string{id, repo, rama, veredicto, strconv.Itoa(bloq), strconv.Itoa(avisos), fecha})
		n++
	}
	w.Flush()
	return n, nil
}

// ResumenSemanal describe la salud del repo en la última semana.
func (s *Store) ResumenSemanal(repoID string) (string, error) {
	desde := time.Now().AddDate(0, 0, -7).Format(time.RFC3339)
	filas, err := s.db.Query(
		"SELECT verdict, blocking_findings FROM runs WHERE repo_id = ? AND created_at >= ?", repoID, desde)
	if err != nil {
		return "", err
	}
	defer filas.Close()

	var total, bloqueados, limpios, conAvisos, muyMalos, sinNada int
	for filas.Next() {
		var v string
		var b int
		if err := filas.Scan(&v, &b); err != nil {
			continue
		}
		total++
		if v == "block" {
			bloqueados++
			if b > 5 {
				muyMalos++
			}
		} else if v == "pass" {
			if b == 0 {
				limpios++
			} else {
				conAvisos++
			}
		} else if v == "skipped" {
			sinNada++
		} else if v == "" {
			sinNada++
		} else {
			sinNada++
		}
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
