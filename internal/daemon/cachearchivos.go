package daemon

import (
	"encoding/json"
	"log"
	"time"

	"codeguard/internal/config"
	"codeguard/internal/engines"
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
func CachePorArchivo(st *store.Store, repoID, remote, nombre string, cfg *config.Config, analysisRoot string) sgengine.Cache {
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
		configHash: cfg.Hash + "|" + Version, analysisRoot: analysisRoot,
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
	analysisRoot                 string
}

// enCache es cómo viaja un hallazgo dentro del caché.
//
// Existe porque finding.Finding marca LineContent como `json:"-"` —no viaja
// por el protocolo del daemon a propósito— y el caché serializa con el mismo
// json.Marshal. Y LineContent no es opcional: es el INSUMO de la huella, que
// desde huellas v2 se asigna colectivamente en el pipeline
// (finding.AsignarHuellas) DESPUÉS de que el caché sirva — sin él, la huella
// del acierto saldría sobre contenido vacío y no casaría con ninguna baseline.
//
// La huella misma YA NO viaja: se re-deriva en cada corrida con el contrato
// vigente. Cachearla era arrastrar el contrato de la corrida que la escribió
// (una entrada v1 servida tras el despliegue de v2 habría revivido el formato
// viejo). El campo "fp" de las entradas anteriores se ignora al leer; además
// la clave del caché lleva la Version del agente, así que el despliegue las
// deja huérfanas de todos modos.
type enCache struct {
	finding.Finding
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
		if err := json.Unmarshal([]byte(js), &guardados); err != nil || guardados == nil {
			// `null` es JSON válido y deja el slice en nil. Aceptarlo como una
			// lista vacía convertiría corrupción de la BD en un hit "limpio".
			// Sólo `[]` representa legítimamente «analizado, sin hallazgos».
			continue // entrada ilegible = miss; la sobrescribirá el Guardar
		}
		fs := make([]finding.Finding, 0, len(guardados))
		for _, g := range guardados {
			f := g.Finding
			f.LineContent = g.LineContent
			// Una entrada sin el insumo de la huella no sirve: la huella se
			// asigna en el pipeline sobre LineContent, y sin él saldría sobre
			// contenido vacío — insuprimible por ninguna baseline. Se descarta
			// la ENTRADA entera: mejor re-analizar el archivo que resucitar
			// deuda que alguien ya aceptó.
			if !hallazgoCacheValido(f) {
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

// hallazgoCacheValido comprueba el contrato persistido, no sólo que el JSON
// tenga sintaxis válida. Un objeto `{}` o un hallazgo sin identidad también es
// corrupción: servirlo puede fabricar huellas vacías, romper la baseline o
// atribuir un resultado al motor equivocado. Ante cualquier duda se reanaliza.
func hallazgoCacheValido(f finding.Finding) bool {
	if f.Engine == "" || f.RuleKey == "" || f.File == "" ||
		f.Message == "" || f.LineContent == "" {
		return false
	}
	switch f.Pillar {
	case finding.Quality, finding.Security, finding.Data:
	default:
		return false
	}
	switch f.Severity {
	case finding.Info, finding.Warning, finding.Error:
	default:
		return false
	}
	// Este caché sólo admite resultados deterministas. Aceptar Source vacío o
	// LLM mezclaría hechos con una salida no reproducible bajo la misma clave.
	return f.Source == finding.Deterministic
}

func (c *cacheArchivos) Guardar(entradas []engines.Cacheable) {
	m := make(map[string]string, len(entradas))
	descartadas := 0
	invalidas := 0
	for _, e := range entradas {
		// Los motores entregan hallazgos ANTES de la asignación colectiva de
		// huellas del pipeline. Los de identidad por línea todavía no traen
		// LineContent; persistirlos así crea entradas que nunca pueden
		// rehidratarse con la misma identidad. Se completa una COPIA desde el
		// árbol exacto analizado (snapshot staged en el hook/daemon).
		preparados := append([]finding.Finding(nil), e.Findings...)
		finding.AsignarHuellas(preparados, finding.FuenteDeArchivos(c.analysisRoot))
		valida := true
		for _, f := range preparados {
			if !hallazgoCacheValido(f) {
				valida = false
				break
			}
		}
		// LA guarda del bug #8 (engines.Cacheable): la clave nació en el
		// instante del diff y el motor leyó el disco después. Si la fuente ya
		// no describe el disco, escribir sería etiquetar hallazgos de un
		// contenido con la clave de otro — el veneno persistente que el test
		// TOCTOU reproduce. Descartar solo cuesta el acierto futuro.
		// Vigente se consulta DESPUÉS de leer las líneas: si el archivo mutó
		// durante la hidratación, la clave ya no coincide y no se escribe.
		if !valida {
			invalidas++
			continue
		}
		if e.Vigente == nil || !e.Vigente() {
			descartadas++
			continue
		}
		guardados := make([]enCache, 0, len(preparados))
		for _, f := range preparados {
			guardados = append(guardados, enCache{
				Finding:     f,
				LineContent: f.LineContent,
			})
		}
		js, err := json.Marshal(guardados)
		if err != nil {
			continue
		}
		m[e.Clave] = string(js)
	}
	if descartadas > 0 {
		log.Printf("file_cache: %d entrada(s) descartada(s) — el contenido cambió durante el análisis y la clave ya no lo describe", descartadas)
	}
	if invalidas > 0 {
		log.Printf("file_cache: %d entrada(s) descartada(s) — sus hallazgos no tenían identidad persistible", invalidas)
	}
	if len(m) == 0 {
		return
	}
	if err := c.st.FileCachePut(c.repoID, c.rulepack, c.configHash, m); err != nil {
		log.Printf("file_cache: escritura fallida (el análisis ya terminó, solo se pierde el acierto futuro): %v", err)
	}
}
