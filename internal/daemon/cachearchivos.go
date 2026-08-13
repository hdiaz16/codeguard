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
	// La VERSIÓN del agente entra en la clave, y no es un detalle.
	//
	// Un acierto de caché dice "este contenido, con estas reglas y esta config,
	// ya se analizó". Faltaba la cuarta cosa de la que depende el resultado:
	// el código que lo analizó. Al actualizar CodeGuard, los motores cambian
	// —se arregla un conteo, se cura una regla, se corrige un parseo— y el
	// caché seguía sirviendo lo que produjo el binario viejo, sin forma de
	// notarlo.
	//
	// Se descubrió arreglando el conteo de vulnerabilidades de govulncheck: el
	// arreglo estaba compilado y funcionando, y el informe seguía mostrando el
	// número anterior porque venía del caché. Una corrección que no llega al
	// usuario es una corrección que no existe.
	return &cacheArchivos{
		st: st, repoID: repoID, rulepack: cfg.Rulepack,
		configHash: cfg.Hash + "|" + Version,
	}
}

// Version la fijan los dos binarios al arrancar (la inyecta build-dist desde
// setup.iss). Vive aquí porque el caché la necesita en su clave y este paquete
// no puede ver el main de nadie. "dev" delata un binario compilado a mano, y
// como también entra en la clave, un binario de desarrollo no envenena el
// caché del instalado.
var Version = "dev"

type cacheArchivos struct {
	st                           *store.Store
	repoID, rulepack, configHash string
}

// enCache es cómo viaja un hallazgo dentro del caché.
//
// Existe porque finding.Finding marca Fingerprint y LineContent como `json:"-"`
// —no viajan por el protocolo del daemon a propósito— y el caché los serializa
// con el mismo json.Marshal. Resultado: al acertar el caché, los hallazgos
// volvían SIN huella.
//
// Y una huella vacía no casa con ninguna baseline. O sea que la promesa central
// de adopción, «sólo lo nuevo bloquea», se rompía en cuanto el caché empezaba a
// acertar: aceptabas un hallazgo, la primera corrida lo suprimía, y la
// siguiente —ya con caché— volvía a bloquearlo. Un hallazgo que reaparece
// después de haberlo aceptado se lee como "esta herramienta no sirve", y con
// razón.
//
// Lo destapó la prueba de la Fase 1 que comprueba que la baseline suprime lo
// preexistente. Antes no había ninguna que lo mirase.
//
// LineContent viaja también, y no es opcional: sin él, el recálculo de la
// huella que hace semgrep cuando una entrada compartida sirve a dos rutas
// produciría una huella distinta de la real (sha256 sobre contenido vacío).
type enCache struct {
	finding.Finding
	Fingerprint string `json:"fp"`
	LineContent string `json:"linea,omitempty"`
}

func (c *cacheArchivos) Leer(shas []string) map[string][]finding.Finding {
	crudos, err := c.st.FileCacheGet(c.repoID, c.rulepack, c.configHash, shas)
	if err != nil {
		log.Printf("file_cache: lectura fallida, se analiza todo: %v", err)
		return nil
	}
	out := make(map[string][]finding.Finding, len(crudos))
	for sha, js := range crudos {
		var guardados []enCache
		if err := json.Unmarshal([]byte(js), &guardados); err != nil {
			continue // entrada ilegible = miss; la sobrescribirá el Guardar
		}
		fs := make([]finding.Finding, 0, len(guardados))
		for _, g := range guardados {
			f := g.Finding
			f.Fingerprint = g.Fingerprint
			f.LineContent = g.LineContent
			// Una entrada vieja (escrita antes de que el caché guardara la
			// huella) llega sin ella. Se descarta la ENTRADA entera en vez de
			// devolver hallazgos sin huella: un hallazgo sin huella es
			// insuprimible, y prefiero volver a analizar el archivo que
			// resucitar deuda que alguien ya aceptó.
			if f.Fingerprint == "" {
				fs = nil
				break
			}
			fs = append(fs, f)
		}
		if fs == nil {
			continue
		}
		out[sha] = fs
	}
	return out
}

func (c *cacheArchivos) Guardar(porSHA map[string][]finding.Finding) {
	m := make(map[string]string, len(porSHA))
	for sha, fs := range porSHA {
		guardados := make([]enCache, 0, len(fs))
		for _, f := range fs {
			guardados = append(guardados, enCache{
				Finding:     f,
				Fingerprint: f.Fingerprint,
				LineContent: f.LineContent,
			})
		}
		js, err := json.Marshal(guardados)
		if err != nil {
			continue
		}
		m[sha] = string(js)
	}
	if err := c.st.FileCachePut(c.repoID, c.rulepack, c.configHash, m); err != nil {
		log.Printf("file_cache: escritura fallida (el análisis ya terminó, solo se pierde el acierto futuro): %v", err)
	}
}
