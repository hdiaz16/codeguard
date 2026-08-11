package daemon

import (
	"encoding/json"
	"log"
	"time"

	"codeguard/internal/config"
	sgengine "codeguard/internal/engines/semgrep"
	"codeguard/internal/finding"
	"codeguard/internal/store"
)

// CachePorArchivo arma el caché de resultados por archivo (§9, file_cache)
// que consume el motor semgrep: la huella del contenido → sus hallazgos con
// este rulepack y esta config. Devuelve nil —sin caché, todo se analiza— si
// falta el store o la config: el caché es una aceleración, jamás un requisito.
//
// remote puede venir vacío (el hook no lo manda por el pipe): UpsertRepo solo
// lo usa al INSERTAR la fila, y quien la crea normalmente (SaveRun del camino
// del commit) sí lo trae.
func CachePorArchivo(st *store.Store, repoID, remote, nombre string, cfg *config.Config) sgengine.Cache {
	if st == nil || cfg == nil || repoID == "" {
		return nil
	}
	// La fila del repo debe existir antes que sus entradas (FK), y la poda
	// mantiene el caché honesto: entradas de otros rulepacks no aciertan nunca
	// (el repo pinnea uno) y las de más de 30 días ya no representan a nadie.
	if err := st.UpsertRepo(repoID, remote, nombre); err != nil {
		log.Printf("file_cache: sin repo no hay caché: %v", err)
		return nil
	}
	if err := st.FileCachePrune(repoID, cfg.Rulepack, 30*24*time.Hour); err != nil {
		log.Printf("file_cache: la poda falló (se sigue sin podar): %v", err)
	}
	return &cacheArchivos{st: st, repoID: repoID, rulepack: cfg.Rulepack, configHash: cfg.Hash}
}

type cacheArchivos struct {
	st                           *store.Store
	repoID, rulepack, configHash string
}

func (c *cacheArchivos) Leer(shas []string) map[string][]finding.Finding {
	crudos, err := c.st.FileCacheGet(c.repoID, c.rulepack, c.configHash, shas)
	if err != nil {
		log.Printf("file_cache: lectura fallida, se analiza todo: %v", err)
		return nil
	}
	out := make(map[string][]finding.Finding, len(crudos))
	for sha, js := range crudos {
		var fs []finding.Finding
		if err := json.Unmarshal([]byte(js), &fs); err != nil {
			continue // entrada ilegible = miss; la sobrescribirá el Guardar
		}
		out[sha] = fs
	}
	return out
}

func (c *cacheArchivos) Guardar(porSHA map[string][]finding.Finding) {
	m := make(map[string]string, len(porSHA))
	for sha, fs := range porSHA {
		if fs == nil {
			fs = []finding.Finding{}
		}
		js, err := json.Marshal(fs)
		if err != nil {
			continue
		}
		m[sha] = string(js)
	}
	if err := c.st.FileCachePut(c.repoID, c.rulepack, c.configHash, m); err != nil {
		log.Printf("file_cache: escritura fallida (el análisis ya terminó, solo se pierde el acierto futuro): %v", err)
	}
}
