package store

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// ExportarRuns saca el historial de análisis a CSV para poder mirarlo en una
// hoja de cálculo: cuántos commits se bloquearon, por qué regla, en qué repo.

type FiltroExport struct {
	Repo   string
	Desde  string
	Hasta  string
	Solo   string // "block" | "pass" | ""
	Limite int
}

func (s *Store) ExportarRuns(destino string, f FiltroExport) (int, error) {
	// La cláusula sigue siendo condicional; lo que nunca se concatena son los
	// VALORES. Van como parámetros, así que da igual lo que traigan.
	//
	// Los conteos salen de la tabla findings: runs no guarda totales — la
	// primera versión de esto consultaba columnas que no existían y compiló
	// igual, porque el SQL es texto. Lo atrapó el primer test del paquete.
	// outcome sale con 'legacy' explícito en las filas anteriores a la columna
	// (003_outcome.sql): esas corridas se midieron con el vocabulario viejo y
	// mapearlas en silencio a un estado nuevo sería inventar datos (turno 67).
	consulta := `SELECT r.id, r.repo_id, r.branch, r.verdict, COALESCE(r.outcome, 'legacy'),
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

	// Se escribe a un temporal EN EL MISMO DIRECTORIO y se renombra al
	// final: os.Create(destino) trunca el CSV anterior antes de escribir
	// nada, y un crash a media exportación dejaba un archivo a medias
	// pisando al bueno. Con temp+rename el destino es siempre el CSV viejo
	// completo o el nuevo completo; nunca uno truncado. El temporal tiene
	// que estar en el mismo directorio porque os.Rename sólo es atómico
	// dentro del mismo filesystem.
	tmp, err := os.CreateTemp(filepath.Dir(destino), ".codeguard-runs-*.tmp")
	if err != nil {
		return 0, err
	}
	// Ante cualquier fallo a mitad, el temporal se cierra y se borra SIN
	// tocar el destino: una exportación fallida no deja basura .tmp ni un
	// CSV a medias reemplazando al anterior.
	descartar := func() {
		tmp.Close()
		os.Remove(tmp.Name())
	}

	w := csv.NewWriter(tmp)
	if err := w.Write([]string{"id", "repo", "rama", "veredicto", "outcome", "bloqueantes", "avisos", "fecha"}); err != nil {
		descartar()
		return 0, err
	}

	n := 0
	for filas.Next() {
		var id, repo, rama, veredicto, outcome, fecha string
		var bloq, avisos int
		// Una fila ilegible es un dato corrupto, no un CSV a medias sin avisar.
		if err := filas.Scan(&id, &repo, &rama, &veredicto, &outcome, &bloq, &avisos, &fecha); err != nil {
			descartar()
			return n, fmt.Errorf("fila %d ilegible: %w", n+1, err)
		}
		if err := w.Write([]string{celdaSegura(id), celdaSegura(repo), celdaSegura(rama),
			celdaSegura(veredicto), celdaSegura(outcome), strconv.Itoa(bloq), strconv.Itoa(avisos),
			celdaSegura(fecha)}); err != nil {
			descartar()
			return n, err
		}
		n++
	}
	if err := filas.Err(); err != nil {
		descartar()
		return n, err
	}
	w.Flush()
	if err := w.Error(); err != nil {
		descartar()
		return n, err
	}
	// Cerrar es donde afloran los errores de escritura diferidos: un CSV
	// truncado que se anuncia como completo es peor que no tenerlo.
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return n, fmt.Errorf("el CSV quedó incompleto: %w", err)
	}
	// Sólo con TODO escrito y cerrado se reemplaza el destino. En Windows
	// os.Rename usa MoveFileEx con REPLACE_EXISTING, así que pisa un CSV
	// anterior igual que en POSIX.
	if err := os.Rename(tmp.Name(), destino); err != nil {
		os.Remove(tmp.Name())
		return n, fmt.Errorf("no se pudo reemplazar %s: %w", destino, err)
	}
	return n, nil
}

// celdaSegura neutraliza la inyección de fórmulas en el CSV: Excel y
// LibreOffice interpretan como fórmula toda celda que empieza por =, +, -, @ o
// tabulación, y el nombre de una rama o de un repo puede empezar así — sale de
// un remote o de un `git branch`, no lo teclea quien abre el archivo. El
// apóstrofo delante fuerza texto literal sin perder el dato.
func celdaSegura(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t':
		return "'" + s
	}
	return s
}

// ResumenSemanal describe la salud del repo en la última semana.
func (s *Store) ResumenSemanal(repoID string) (string, error) {
	desde := time.Now().AddDate(0, 0, -7).Format(time.RFC3339)
	// Se traen los DOS conteos, igual que en ExportarRuns: bloqueantes y avisos
	// son cosas distintas. Decidir «con avisos» mirando los BLOQUEANTES hacía
	// que un pass con avisos de verdad se contara como limpio.
	filas, err := s.db.Query(`SELECT COALESCE(r.outcome, ''), COALESCE(r.verdict, ''),
	       (SELECT COUNT(*) FROM findings f WHERE f.run_id = r.id AND f.blocking = 1),
	       (SELECT COUNT(*) FROM findings f WHERE f.run_id = r.id AND f.blocking = 0)
	  FROM runs r WHERE r.repo_id = ? AND r.started_at >= ?`, repoID, desde)
	if err != nil {
		return "", err
	}
	defer filas.Close()

	var total, bloqueados, limpios, conAvisos, muyMalos, sinGarantia, sinRevisar int
	for filas.Next() {
		var o, v string
		var b, avisos int
		// Misma regla que el CSV: una fila ilegible es dato corrupto, no un
		// resumen que cuenta de menos sin avisar.
		if err := filas.Scan(&o, &v, &b, &avisos); err != nil {
			return "", fmt.Errorf("run ilegible en el resumen semanal: %w", err)
		}
		total++
		// El outcome tipado manda cuando existe. Las filas de antes de la
		// columna conservan su lectura de SIEMPRE (el switch legacy de abajo):
		// se midieron con el vocabulario viejo y reinterpretarlas con el nuevo
		// sería inventar datos (turno 67). El "degraded" sintetizado viejo
		// —que este resumen mandaba a «omitidos» y el panel pintaba «pasó»—
		// se queda en su cubo legacy; el degradado de verdad viene en outcome.
		switch o {
		case "blocked":
			bloqueados++
			if b > 5 {
				muyMalos++
			}
			continue
		case "clean":
			limpios++
			continue
		case "findings":
			conAvisos++
			continue
		case "degraded":
			sinGarantia++
			continue
		case "failed", "skipped":
			sinRevisar++
			continue
		}
		switch v {
		case "block":
			bloqueados++
			if b > 5 {
				muyMalos++
			}
		case "pass":
			switch {
			case avisos > 0:
				conAvisos++
			case b == 0:
				limpios++
			default:
				// pass CON bloqueantes y sin avisos: dato incoherente (si hay
				// bloqueantes el veredicto tendría que ser block). No se cuenta
				// como limpio, que maquillaría el resumen, ni como «con
				// avisos», que no tiene: va con los no revisados.
				sinRevisar++
			}
		default: // skipped, degraded sintetizado, vacío: vocabulario viejo
			sinRevisar++
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
	frase := fmt.Sprintf("%d commits: %d limpios, %d con avisos, %d bloqueados, %d sin revisar",
		total, limpios, conAvisos, bloqueados, sinRevisar)
	// La garantía rota se dice aparte y solo cuando existe: es la categoría que
	// el resumen viejo escondía en «omitidos» — un commit que SÍ corrió pero
	// cuyo análisis no cubre lo que promete.
	if sinGarantia > 0 {
		frase += fmt.Sprintf(", %d sin garantía completa", sinGarantia)
	}
	return frase, nil
}
