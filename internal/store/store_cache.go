package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

func (s *Store) DiffCacheGet(repoID, diffSHA, rulepack, configHash, model string) (string, bool) {
	var result string
	err := s.db.QueryRow(`SELECT result_json FROM diff_cache
		WHERE repo_id=? AND diff_sha256=? AND rulepack_ver=? AND config_hash=? AND model=?`,
		repoID, diffSHA, rulepack, configHash, model).Scan(&result)
	return result, err == nil
}

func (s *Store) DiffCachePut(repoID, diffSHA, rulepack, configHash, model, resultJSON string) error {
	_, err := s.db.Exec(`INSERT INTO diff_cache
		(id, repo_id, diff_sha256, rulepack_ver, config_hash, model, result_json, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (repo_id, diff_sha256, rulepack_ver, config_hash, model)
		DO UPDATE SET result_json = excluded.result_json, created_at = excluded.created_at`,
		NewULID(), repoID, diffSHA, rulepack, configHash, model, resultJSON, nowISO())
	return err
}

func (s *Store) FileCacheGet(repoID, rulepack, configHash string, shas []string) (map[string]string, error) {
	if len(shas) == 0 {
		return map[string]string{}, nil
	}
	lista, err := json.Marshal(shas)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Query(`SELECT file_sha256, result_json FROM file_cache
		WHERE repo_id=? AND rulepack_ver=? AND config_hash=?
		  AND file_sha256 IN (SELECT value FROM json_each(?))`,
		repoID, rulepack, configHash, string(lista))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var sha, js string
		if err := rows.Scan(&sha, &js); err != nil {
			return nil, err
		}
		out[sha] = js
	}
	return out, rows.Err()
}

func (s *Store) FileCachePut(repoID, rulepack, configHash string, porSHA map[string]string) error {
	if len(porSHA) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for sha, js := range porSHA {
		if _, err := tx.Exec(`INSERT INTO file_cache
			(id, repo_id, file_sha256, rulepack_ver, config_hash, result_json, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (repo_id, file_sha256, rulepack_ver, config_hash)
			DO UPDATE SET result_json = excluded.result_json, created_at = excluded.created_at`,
			NewULID(), repoID, sha, rulepack, configHash, js, nowISO()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) FileCachePrune(repoID, rulepackVigente string, edadMax time.Duration) error {
	corte := time.Now().UTC().Add(-edadMax).Format(time.RFC3339)
	_, err := s.db.Exec(`DELETE FROM file_cache
		WHERE repo_id = ? AND (rulepack_ver != ? OR created_at < ?)`,
		repoID, rulepackVigente, corte)
	return err
}

type RuleStat struct {
	Engine, RuleKey  string
	Useful, FalsePos int
}

func (s *Store) RuleStats(repoID string) ([]RuleStat, error) {
	q := `SELECT f.engine, f.rule_key,
	       SUM(CASE WHEN fb.verdict = 'useful' THEN 1 ELSE 0 END),
	       SUM(CASE WHEN fb.verdict = 'false_positive' THEN 1 ELSE 0 END)
	  FROM feedback fb
	  JOIN findings f ON f.id = fb.finding_id
	  JOIN runs r ON r.id = f.run_id
	 WHERE (? = '' OR r.repo_id = ?)
	 GROUP BY f.engine, f.rule_key
	 ORDER BY 4 DESC, 3 DESC`
	rows, err := s.db.Query(q, repoID, repoID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RuleStat
	for rows.Next() {
		var st RuleStat
		if err := rows.Scan(&st.Engine, &st.RuleKey, &st.Useful, &st.FalsePos); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

type Emision struct {
	Engine, RuleKey string
	Total           int
}

func (s *Store) Emisiones(repoID string) ([]Emision, error) {
	rows, err := s.db.Query(`SELECT f.engine, f.rule_key, COUNT(*)
	  FROM findings f JOIN runs r ON r.id = f.run_id
	 WHERE (? = '' OR r.repo_id = ?)
	 GROUP BY f.engine, f.rule_key`, repoID, repoID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Emision
	for rows.Next() {
		var e Emision
		if err := rows.Scan(&e.Engine, &e.RuleKey, &e.Total); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

type Calibracion struct {
	Hallazgos, Votos int
	Desde, Hasta     string
}

func (s *Store) ProgresoCalibracion(repoID string) (Calibracion, error) {
	var c Calibracion
	var desde, hasta sql.NullString
	err := s.db.QueryRow(`SELECT COUNT(*), MIN(f.created_at), MAX(f.created_at)
	  FROM findings f JOIN runs r ON r.id = f.run_id
	 WHERE (? = '' OR r.repo_id = ?)`, repoID, repoID).Scan(&c.Hallazgos, &desde, &hasta)
	if err != nil {
		return c, err
	}
	c.Desde, c.Hasta = desde.String, hasta.String
	err = s.db.QueryRow(`SELECT COUNT(*) FROM feedback fb
	  JOIN findings f ON f.id = fb.finding_id
	  JOIN runs r ON r.id = f.run_id
	 WHERE (? = '' OR r.repo_id = ?)`, repoID, repoID).Scan(&c.Votos)
	return c, err
}

func (s *Store) DemotedRules(repoID string, minVotes int, maxFPRate float64) (map[string]bool, error) {
	stats, err := s.RuleStats(repoID)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, st := range stats {
		total := st.Useful + st.FalsePos
		if total >= minVotes && float64(st.FalsePos)/float64(total) > maxFPRate {
			out[st.Engine+"/"+st.RuleKey] = true
		}
	}
	return out, nil
}

func (s *Store) SaveFeedback(findingID, verdict, comment string) error {
	if verdict != "useful" && verdict != "false_positive" && verdict != "unclear" {
		return fmt.Errorf("veredicto inválido: %q", verdict)
	}
	_, err := s.db.Exec(`INSERT INTO feedback (id, finding_id, verdict, comment, created_at)
		VALUES (?, ?, ?, ?, ?)`, NewULID(), findingID, verdict, comment, nowISO())
	return err
}
