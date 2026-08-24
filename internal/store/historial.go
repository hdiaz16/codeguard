package store

import "fmt"

// El historial existe porque la base ya guardaba todo esto y nadie lo enseñaba.
// Cada commit deja su run y sus hallazgos, así que el dato de "qué me ha pasado
// en este repo" llevaba meses acumulándose sin superficie que lo mostrara.

// Corrida es un análisis pasado, tal como se cuenta en el panel.
type Corrida struct {
	Cuando  string `json:"cuando"`
	Rama    string `json:"rama"`
	Verdict string `json:"verdict"`
	// Outcome es el veredicto tipado (003_outcome.sql). Vacío en corridas
	// anteriores a la columna: el panel las pinta desde el verdict legacy y
	// lo dice, en vez de mapearlas en silencio a un estado que no se midió.
	Outcome     string `json:"outcome"`
	Bloqueantes int    `json:"bloqueantes"`
	Avisos      int    `json:"avisos"`
	Bypass      bool   `json:"bypass"`
	ElapsedMs   int64  `json:"elapsed_ms"`
}

// Cerrado es un hallazgo bloqueante que dejó de aparecer.
//
// Se llama "cerrado" y NO "resuelto", y la diferencia importa: CodeGuard
// analiza el CAMBIO, no el repo entero, así que un hallazgo también desaparece
// cuando su archivo no se ha vuelto a tocar. Decirle "resuelto" a eso sería
// exactamente la mentira por omisión que este producto persigue — el ✓ sobre
// algo que nadie volvió a mirar. El panel lo dice con estas palabras.
type Cerrado struct {
	Regla     string `json:"regla"`
	Archivo   string `json:"archivo"`
	Linea     int    `json:"linea"`
	Pilar     string `json:"pilar"`
	UltimaVez string `json:"ultima_vez"`
}

// Historial es lo que el panel pinta en su pestaña.
type Historial struct {
	Corridas []Corrida `json:"corridas"`
	Cerrados []Cerrado `json:"cerrados"`
}

// Historial devuelve las últimas corridas de un repo y los bloqueantes que ya
// no aparecen.
func (s *Store) Historial(repoID string, limite int) (Historial, error) {
	var h Historial
	if limite <= 0 {
		limite = 20
	}

	// Los conteos salen de la propia tabla de hallazgos y no de un campo del
	// run: así el número que se enseña es el que de verdad se guardó, y no una
	// cifra que pudo quedarse desincronizada.
	filas, err := s.db.Query(`
		-- El COALESCE se aplica también a bypassed y elapsed_ms, no sólo a
		-- verdict: tienen el mismo riesgo (corridas anteriores a la columna, o
		-- interrumpidas), y un solo NULL en una fila vieja hacía fallar el Scan
		-- y dejaba de pintarse el historial ENTERO.
		SELECT r.started_at, r.branch, COALESCE(r.verdict,''), COALESCE(r.outcome,''),
		       COALESCE(r.bypassed, 0), COALESCE(r.elapsed_ms, 0),
		       COALESCE(SUM(CASE WHEN f.blocking = 1 THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN f.blocking = 0 THEN 1 ELSE 0 END), 0)
		FROM runs r LEFT JOIN findings f ON f.run_id = r.id
		WHERE r.repo_id = ?
		GROUP BY r.id
		-- Mismo desempate por id que la subconsulta de «la corrida más reciente»
		-- de abajo: sin él, dos corridas del mismo segundo —caso habitual, como
		-- reconoce el comentario de esa subconsulta— se ordenan al azar y el
		-- panel puede contradecir a la lógica de cerrados.
		ORDER BY r.started_at DESC, r.id DESC
		LIMIT ?`, repoID, limite)
	if err != nil {
		return h, fmt.Errorf("no pude leer las corridas: %w", err)
	}
	defer filas.Close()
	for filas.Next() {
		var c Corrida
		var bypass int
		if err := filas.Scan(&c.Cuando, &c.Rama, &c.Verdict, &c.Outcome, &bypass, &c.ElapsedMs,
			&c.Bloqueantes, &c.Avisos); err != nil {
			return h, err
		}
		c.Bypass = bypass == 1
		h.Corridas = append(h.Corridas, c)
	}
	if err := filas.Err(); err != nil {
		return h, err
	}

	// Bloqueantes cuya última aparición NO es la corrida más reciente.
	//
	// Se agrupa por huella y no por regla+archivo porque la huella es lo único
	// que identifica un hallazgo entre corridas; es la misma clave con la que
	// se suprime y se calibra.
	// Se compara contra la corrida más reciente POR IDENTIDAD, no por fecha.
	// Con fechas, dos commits del mismo segundo —lo normal al reintentar tras
	// arreglar algo— quedaban empatados y nada salía nunca como cerrado.
	//
	// COALESCE(fingerprint_legacy, fingerprint) EN AMBOS LADOS: durante la
	// ventana dual de huellas (004_huella_legacy.sql) conviven filas v1
	// (huella vieja, sin alias) y filas v2 (huella nueva + alias v1). Comparar
	// fingerprint contra fingerprint habría anunciado una ola FALSA de
	// «cerrados» el día del despliegue — todo bloqueante histórico quedaba
	// fuera del NOT IN por hablar otro formato. El alias pone a todos en el
	// mismo espacio de claves; al expirar la ventana esta comparación vuelve
	// a fingerprint puro.
	cerr, err := s.db.Query(`
		SELECT f.rule_key, f.file_path, COALESCE(f.line_start,0), f.pillar, MAX(r.started_at) AS ultima
		FROM findings f JOIN runs r ON r.id = f.run_id
		WHERE r.repo_id = ? AND f.blocking = 1
		  AND COALESCE(f.fingerprint_legacy, f.fingerprint) NOT IN (
		      SELECT COALESCE(f2.fingerprint_legacy, f2.fingerprint) FROM findings f2
		      WHERE f2.run_id = (
		          SELECT id FROM runs WHERE repo_id = ?
		          ORDER BY started_at DESC, id DESC LIMIT 1))
		GROUP BY COALESCE(f.fingerprint_legacy, f.fingerprint)
		ORDER BY ultima DESC
		LIMIT ?`, repoID, repoID, limite)
	if err != nil {
		return h, fmt.Errorf("no pude leer los cerrados: %w", err)
	}
	defer cerr.Close()
	for cerr.Next() {
		var c Cerrado
		if err := cerr.Scan(&c.Regla, &c.Archivo, &c.Linea, &c.Pilar, &c.UltimaVez); err != nil {
			return h, err
		}
		h.Cerrados = append(h.Cerrados, c)
	}
	return h, cerr.Err()
}
