// Package store persiste runs y findings en SQLite local (modernc, sin cgo).
// DDL portable SQLite → PostgreSQL según las reglas de la sección 9.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
	_ "modernc.org/sqlite"

	"codeguard/internal/finding"
	"codeguard/internal/pipeline"
	"codeguard/migrations"
)

type Store struct {
	db *sql.DB
}

func NewULID() string {
	return ulid.MustNew(ulid.Timestamp(time.Now().UTC()), rand.Reader).String()
}

func nowISO() string { return time.Now().UTC().Format(time.RFC3339) }

// CanonicalRepoID normaliza la URL del remote (sección 8): host en minúsculas,
// sin protocolo, sin credenciales, sin sufijo .git — ssh y https del mismo
// repo producen el mismo id.
func CanonicalRepoID(remoteURL string) string {
	s := strings.TrimSpace(remoteURL)
	// forma ssh scp-like: git@host:org/repo.git
	if strings.Contains(s, "@") && !strings.Contains(s, "://") {
		if i := strings.Index(s, "@"); i >= 0 {
			s = s[i+1:]
		}
		s = strings.Replace(s, ":", "/", 1)
	} else if u, err := url.Parse(s); err == nil && u.Host != "" {
		s = u.Host + u.Path
	}
	s = strings.TrimSuffix(strings.ToLower(s), ".git")
	s = strings.TrimSuffix(s, "/")
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// RepoIDDe es el ÚNICO sitio donde se decide bajo qué identificador vive un
// repositorio en la base.
//
// Con remote manda el remote, y eso es lo que hace que dos clones del mismo
// repositorio —en dos máquinas o en dos carpetas— compartan historial. Sin
// remote se cae a la carpeta, porque un repositorio local sigue siendo un
// repositorio y sus hallazgos tienen que ir a algún cajón estable.
//
// Existe porque este cálculo estaba repetido en CINCO sitios y sólo DOS tenían
// el respaldo. Los otros tres —`codeguard stats`, el caché por archivo y el
// RepoID que el gancho manda al daemon— llamaban a CanonicalRepoID("") y se
// quedaban con la cadena vacía: guardaban bajo un identificador y leían bajo
// otro. Medido en un repo recién creado sin `origin`: 21 hallazgos en la base y
// `codeguard stats` respondiendo "sin hallazgos registrados todavía".
//
// Un repositorio sin remote es justo el de quien acaba de crear algo para
// probar el producto, así que el fallo caía entero sobre la primera impresión.
//
// La ruta se normaliza a barras normales antes de tomar la última parte: el
// daemon las entrega ya normalizadas y la CLI no, y sin esto el panel y la
// terminal hablarían de repositorios distintos.
func RepoIDDe(repoRoot, remote string) string {
	if strings.TrimSpace(remote) != "" {
		return CanonicalRepoID(remote)
	}
	// La ruta entra ENTERA, no sólo la carpeta final. Con el nombre solo,
	// C:\trabajo\proyecto y D:\personal\proyecto abrían el MISMO cajón y
	// mezclaban runs, hallazgos, cachés y estadísticas. No era teórico: en la
	// base de esta máquina los cuatro repos son locales y dos de ellos se
	// llaman "001" y "002" —los temporales de los e2e, que nacen en un
	// directorio distinto cada corrida—, así que sus 125 runs estaban apilados
	// en dos cajones compartidos.
	//
	// La ruta no se filtra a la telemetría: CanonicalRepoID devuelve el SHA-256,
	// no el texto. Y las mayúsculas las pliega su ToLower, que es lo correcto
	// donde el sistema de archivos tampoco las distingue.
	//
	// El historial anterior de un repo sin remote queda bajo el id viejo:
	// huérfano pero intacto, y sigue viéndose con `stats --all`. No hay
	// migración posible y no es pereza: el id viejo sólo codificaba el basename
	// y la ruta completa no se persiste en ninguna columna —UpsertRepo recibe
	// remote vacío y filepath.Base—, así que nada permite reconstruir de qué
	// ruta venía cada run; y lo que dos repos ya mezclaron no se puede
	// desmezclar. Seguir escribiendo bajo el id viejo sí perpetuaba la mezcla.
	realPath := repoRoot
	if eval, err := filepath.EvalSymlinks(repoRoot); err == nil && eval != "" {
		realPath = eval
	} else if abs, err := filepath.Abs(repoRoot); err == nil && abs != "" {
		realPath = abs
	}
	limpia := strings.TrimRight(filepath.ToSlash(filepath.Clean(realPath)), "/")
	return CanonicalRepoID("local/" + limpia)
}

// busyTimeoutMS es cuánto espera una conexión a que OTRO PROCESO suelte la
// base antes de rendirse: hook, ci y daemon comparten el mismo archivo (ver
// DefaultPath) y el arbitraje entre procesos sólo puede ser esperar y
// reintentar.
const busyTimeoutMS = 5000

func Open(path string) (*Store, error) { return abrir(path, busyTimeoutMS) }

// abrir concentra la política de conexión en un solo sitio. El busy_timeout va
// como parámetro porque es una política —cuánto se aguanta a otro proceso—, no
// una constante del esquema: bajarlo deja al descubierto la contención DENTRO
// del proceso, que es exactamente lo que el pool de abajo tiene que eliminar.
func abrir(path string, busyMS int) (*Store, error) {
	db, err := sql.Open("sqlite", fmt.Sprintf(
		"%s?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(%d)", path, busyMS))
	if err != nil {
		return nil, err
	}
	// UNA conexión, a propósito, y no es una cifra conservadora que se pueda
	// subir: SQLite es un motor embebido que admite UN escritor a la vez. El
	// default de database/sql (conexiones ilimitadas) está pensado para motores
	// cliente-servidor con varios escritores; sobre este archivo lo único que
	// produce es que el proceso se pelee consigo mismo y devuelva SQLITE_BUSY
	// justo cuando más trabajo hay. Con una sola conexión, la cola la hace
	// database/sql —que sabe esperar sin reintentar a ciegas— y el
	// SQLITE_BUSY de dentro del proceso desaparece; el busy_timeout queda para
	// lo único que puede arbitrar: hook vs daemon vs ci, que son procesos
	// distintos.
	//
	// Y no se paga nada por ello, contra lo que dice la intuición: BenchmarkLecturas,
	// tres repeticiones de cada configuración en la misma máquina, da 2.15-2.29 ms/op
	// con una conexión frente a 3.19-22.08 sin límite. Una sola conexión es entre un
	// 35% y un 50% MÁS RÁPIDA en lectura, y muchísimo más estable — la cola de
	// database/sql sale más barata que la contención por el archivo. Si algún día
	// molestara de verdad, la salida NO es subir este número: es un segundo pool de
	// sólo lectura.
	//
	// ConnMaxLifetime(0) = la conexión no caduca. Reciclarla no compra nada
	// aquí (no hay servidor al otro lado que cierre sesiones) y cada
	// reconexión volvería a aplicar los PRAGMA.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	// BEGIN IMMEDIATE toma el lock de escritura ANTES de leer schema_migrations.
	// Sin él, el «mira si está aplicada y si no aplícala» no es atómico ENTRE
	// PROCESOS: si el hook y el daemon abren la base virgen a la vez, los dos
	// leen exists=0, los dos aplican el DDL y el perdedor revienta en el INSERT
	// por PRIMARY KEY — Open fallaba en un primer arranque que no tenía nada de
	// malo. Los DDL no son idempotentes (ningún CREATE lleva IF NOT EXISTS), así
	// que serializar es la salida: el segundo proceso espera su busy_timeout y
	// se encuentra el trabajo hecho.
	//
	// Va sobre una conexión TOMADA del pool y no sobre s.db: database/sql
	// devuelve la conexión al pool en cada Exec y puede resetear la sesión, lo
	// que se llevaría por delante la transacción recién abierta.
	ctx := context.Background()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return fmt.Errorf("tomando el lock de migraciones: %w", err)
	}
	confirmado := false
	defer func() {
		if !confirmado {
			// Si algo falla antes del COMMIT la base queda como estaba: ninguna
			// migración a medias queda registrada como aplicada.
			_, _ = conn.ExecContext(ctx, `ROLLBACK`)
		}
	}()
	if _, err := conn.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return err
	}
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		var exists int
		if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, name).Scan(&exists); err != nil {
			return err
		}
		if exists > 0 {
			continue
		}
		ddl, err := fs.ReadFile(migrations.FS, name)
		if err != nil {
			return err
		}
		if _, err := conn.ExecContext(ctx, string(ddl)); err != nil {
			return fmt.Errorf("migración %s: %w", name, err)
		}
		if _, err := conn.ExecContext(ctx, `INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`, name, nowISO()); err != nil {
			return err
		}
	}
	if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
		return err
	}
	confirmado = true
	return nil
}

func (s *Store) UpsertRepo(id, remoteURL, name string) error {
	_, err := s.db.Exec(`INSERT INTO repos (id, remote_url, name, first_seen_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET last_seen_at = excluded.last_seen_at`,
		id, remoteURL, name, nowISO(), nowISO())
	return err
}

type RunMeta struct {
	RunID       string
	RepoID      string
	Branch      string
	RulepackVer string
	ConfigHash  string
	Environment string // local | ci
	Bypassed    bool
}

// SaveRun persiste el run y sus hallazgos (modo sombra: se registra todo,
// shown queda en 0 — nada se muestra aún).
func (s *Store) SaveRun(meta RunMeta, res *pipeline.Result, filesChanged int) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	verdict := string(res.Verdict)
	if len(res.Degraded) > 0 && res.Verdict == pipeline.Pass {
		verdict = "degraded"
	}
	_, err = tx.Exec(`INSERT INTO runs
		(id, repo_id, branch, started_at, finished_at, verdict, files_changed,
		 lines_changed, bypassed, degraded_layers, rulepack_ver, config_hash, elapsed_ms, environment)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		meta.RunID, meta.RepoID, meta.Branch, nowISO(), nowISO(), verdict,
		filesChanged, 0, b2i(meta.Bypassed), strings.Join(res.Degraded, ","),
		meta.RulepackVer, meta.ConfigHash, res.ElapsedMs, meta.Environment)
	if err != nil {
		return err
	}
	for i := range res.Findings {
		f := &res.Findings[i]
		if f.ID == "" {
			f.ID = NewULID()
		}
		_, err = tx.Exec(`INSERT INTO findings
			(id, run_id, engine, rule_key, pillar, severity, source, blocking,
			 verified, shown, file_path, line_start, line_end, fingerprint,
			 message, why, fix_hint, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?)`,
			f.ID, meta.RunID, f.Engine, f.RuleKey, string(f.Pillar), string(f.Severity),
			string(f.Source), b2i(f.Blocking), b2i(f.Verified),
			f.File, f.Line, f.EndLine, f.Fingerprint, f.Message, f.Why, f.FixHint, nowISO())
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

type LLMCall struct {
	RunID            string
	Pillar           string
	Model            string
	PromptTokens     int
	CompletionTokens int
	LatencyMs        int64
	Status           string // ok | timeout | error | skipped
	FindingsReturned int
	FindingsRejected int
	CostMicros       int64 // millonésimas de dólar; 0 si no hay tarifas configuradas
}

// GastoDelMesUSD suma lo gastado en llamadas al modelo desde el día 1 del mes
// en curso. Es la base del tope de presupuesto: sin esto, monthly_budget_usd
// era un campo de configuración que nadie leía.
func (s *Store) GastoDelMesUSD() (float64, error) {
	inicio := time.Now().UTC().Format("2006-01") + "-01T00:00:00Z"
	var micros sql.NullInt64
	err := s.db.QueryRow(
		`SELECT SUM(cost_micros) FROM llm_calls WHERE created_at >= ?`, inicio,
	).Scan(&micros)
	if err != nil {
		return 0, err
	}
	return float64(micros.Int64) / 1e6, nil
}

// SaveLLMCall registra la telemetría de una llamada al modelo (fase 3 sombra).
func (s *Store) SaveLLMCall(c LLMCall) error {
	_, err := s.db.Exec(`INSERT INTO llm_calls
		(id, run_id, pillar, model, prompt_tokens, completion_tokens, cost_micros,
		 latency_ms, status, findings_returned, findings_rejected, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		NewULID(), c.RunID, c.Pillar, c.Model, c.PromptTokens, c.CompletionTokens,
		c.CostMicros, c.LatencyMs, c.Status, c.FindingsReturned, c.FindingsRejected, nowISO())
	return err
}

// SaveLLMFindings persiste hallazgos del modelo en sombra: shown=0 siempre.
func (s *Store) SaveLLMFindings(runID string, fs []finding.Finding) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, f := range fs {
		id := f.ID
		if id == "" {
			id = NewULID()
		}
		_, err := tx.Exec(`INSERT INTO findings
			(id, run_id, engine, rule_key, pillar, severity, source, blocking,
			 verified, shown, file_path, line_start, line_end, fingerprint,
			 message, why, fix_hint, created_at)
			VALUES (?, ?, ?, ?, ?, ?, 'llm', 0, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, runID, f.Engine, f.RuleKey, string(f.Pillar), string(f.Severity),
			b2i(f.Verified), f.File, f.Line, f.EndLine, f.Fingerprint,
			f.Message, f.Why, f.FixHint, nowISO())
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ErrRunNoExiste dice que el UPDATE no encontró la fila del run.
//
// Existe porque database/sql NO considera error un UPDATE que no toca ninguna
// fila: err llega nil y las cero filas se pierden sin dejar rastro. Aquí ese
// silencio costaba datos. La sombra corre en el proceso del DAEMON, pero quien
// escribe la fila del run es el proceso del HOOK (persistRun, en cmd/codeguard)
// justo después de recibir la respuesta. Cuando el hook tardaba —antivirus,
// disco, contención sobre el mismo SQLite—, la sombra actualizaba un run que
// todavía no existía: cero filas, err nil, y el risk_score y el llm_used se
// perdían para siempre y en silencio.
//
// Que sea un error con nombre es lo que permite al llamador distinguir las tres
// cosas que antes eran indistinguibles: se escribió, todavía no está, o la base
// falló.
var ErrRunNoExiste = errors.New("el run todavía no está en la base")

// UpdateRunLLM anota el puntaje de riesgo y si se usó el modelo. Devuelve
// ErrRunNoExiste envuelto si el UPDATE no tocó ninguna fila.
//
// De paso reencola el run para el central: risk_score y llm_used son los ÚNICOS
// campos del run que se escriben después de crearlo, así que este método es el
// único sitio donde puede saberse que una fila ya empujada cambió.
func (s *Store) UpdateRunLLM(runID string, riskScore int, llmUsed bool) error {
	res, err := s.db.Exec(`UPDATE runs SET risk_score = ?, llm_used = ? WHERE id = ?`,
		riskScore, b2i(llmUsed), runID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		// Un driver que no sabe cuántas filas tocó no puede afirmar que tocó
		// alguna: se dice, no se supone.
		return fmt.Errorf("no se pudo saber si el run %s se actualizó: %w", runID, err)
	}
	if n == 0 {
		return fmt.Errorf("anotando riesgo del run %s: %w", runID, ErrRunNoExiste)
	}
	if err := s.reencolarRunParaCentral(runID); err != nil {
		// El riesgo YA quedó anotado en local; lo que falló es el aviso al
		// sync. El mensaje lo dice para que nadie lo lea como una pérdida.
		return fmt.Errorf("riesgo anotado, pero el run %s no se pudo reencolar para el central: %w", runID, err)
	}
	return nil
}

// reencolarRunParaCentral retrocede la marca de agua del sync para que un run
// que YA viajó vuelva a viajar.
//
// La marca de sync_marcas es un `id > ultima`: una fila que ya se empujó no se
// vuelve a mirar nunca. Eso es correcto para todo lo que es inmutable —
// findings, feedback y llm_calls se escriben una vez y no cambian—, pero el run
// NO lo es: SaveRun lo inserta con risk_score y llm_used en su DEFAULT 0 y la
// sombra los rellena después, hasta un minuto más tarde (plazoSombra). Como el
// empuje oportunista del daemon dispara sin coordinarse con la sombra, si se
// cuela en esa ventana el central se queda con risk_score=0.
//
// El ON CONFLICT (id) DO UPDATE del INSERT de runs (ver sync.go) sabe corregir
// esa fila, pero sólo puede hacerlo si la fila vuelve a pasar por ahí — y por
// la marca no volvía. Sin esto, aquel 0 era definitivo: risk_score no se lee en
// ningún otro sitio del producto, el central es su único consumidor.
//
// Retroceder al id inmediatamente anterior re-empuja este run y los posteriores;
// el ON CONFLICT los absorbe sin duplicar y son los de los últimos minutos, así
// que el coste es de unas pocas filas. La condición `ultima >= ?` evita tocar la
// marca cuando el run todavía no había viajado, que es el caso normal.
//
// Best-effort, como toda la telemetría: si un empuje está corriendo AHORA MISMO
// y termina después de este retroceso, guardará su marca adelantada y se lo
// llevará por delante. Eso deja las cosas exactamente como estaban antes de
// existir esta función, nunca peor.
func (s *Store) reencolarRunParaCentral(runID string) error {
	var anterior sql.NullString // NULL si es el primer run: marca vacía = desde el principio
	if err := s.db.QueryRow(`SELECT MAX(id) FROM runs WHERE id < ?`, runID).Scan(&anterior); err != nil {
		return err
	}
	_, err := s.db.Exec(`UPDATE sync_marcas SET ultima = ?, actualizada_at = ?
		WHERE tabla = 'runs' AND ultima >= ?`, anterior.String, nowISO(), runID)
	return err
}

// RunExiste dice si la fila del run ya está escrita. Es la señal con la que el
// daemon espera al proceso del hook en vez de dormir una cantidad fija de
// segundos (ver esperarRunPersistido). El error se devuelve en vez de doblarse
// en un false: "no está" y "no se pudo preguntar" no son lo mismo.
func (s *Store) RunExiste(runID string) (bool, error) {
	var uno int
	err := s.db.QueryRow(`SELECT 1 FROM runs WHERE id = ?`, runID).Scan(&uno)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// DiffCacheGet / DiffCachePut: caché de resultados LLM por diff (§9).
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

// FileCacheGet / FileCachePut / FileCachePrune: caché de resultados
// deterministas por archivo (§9, tabla file_cache). La clave es el sha256 del
// contenido normalizado a LF más el rulepack y el hash de la config: mismo
// contenido + mismas reglas = mismos hallazgos, sin volver a correr nada.

// FileCacheGet devuelve, de los shas pedidos, los que tienen resultado
// cacheado (sha → result_json). Los que no aparecen son misses.
//
// Los shas viajan como UN parámetro JSON y json_each los expande dentro de
// SQLite: la consulta queda estática (la primera versión concatenaba "?" por
// sha y el propio go-sql-concat-en-variable del rulepack la bloqueó — con
// razón: una consulta que se arma con + es una consulta que otro editará mal)
// y de paso desaparece el troceo por el tope de parámetros.
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

// FileCachePut guarda los resultados por sha. La lista vacía también se
// guarda: "analizado y limpio" es el resultado que más veces se reutiliza.
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

// FileCachePrune borra, de UN repo, lo que ya no puede acertar: entradas de
// otros rulepacks (el repo pinnea uno) y entradas más viejas que edadMax. Es
// por repo a propósito: otros repos de la máquina pinnean otras versiones.
func (s *Store) FileCachePrune(repoID, rulepackVigente string, edadMax time.Duration) error {
	corte := time.Now().UTC().Add(-edadMax).Format(time.RFC3339)
	_, err := s.db.Exec(`DELETE FROM file_cache
		WHERE repo_id = ? AND (rulepack_ver != ? OR created_at < ?)`,
		repoID, rulepackVigente, corte)
	return err
}

// RuleStat es la precisión medida de una regla según el feedback del equipo.
type RuleStat struct {
	Engine, RuleKey  string
	Useful, FalsePos int
}

// RuleStats agrega el feedback por regla, opcionalmente filtrado por repo.
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

// Emision es cuánto produjo una regla, votado o no. La precisión sobre votos
// solos tiene sesgo de selección: una regla que emite 200 hallazgos y recibe
// 3 votos no está calibrada por muy 100% que salgan los tres.
type Emision struct {
	Engine, RuleKey string
	Total           int
}

// Emisiones cuenta los hallazgos registrados por regla (la sombra registra
// todo, así que esto es el denominador real de la calibración).
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

// Calibracion resume el avance hacia el umbral del protocolo §17: dos semanas
// de sombra y 500+ hallazgos etiquetados.
type Calibracion struct {
	Hallazgos, Votos int
	Desde, Hasta     string // ISO; vacíos si no hay datos
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

// DemotedRules devuelve las reglas auto-degradadas para un repo: con al
// menos minVotes votos y tasa de falsos positivos sobre el umbral, dejan de
// bloquear (§17: precisión < 80% se corrige o se desactiva — aquí, se degrada
// sola con el feedback del equipo, sin esperar a la calibración formal).
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

// DefaultPath es la BD local por usuario, compartida por hook, ci y daemon.
func DefaultPath() string {
	// Lo que se impone es que la ruta sea ABSOLUTA, no que la variable no esté
	// vacía. No es lo mismo: con LOCALAPPDATA en blanco o con un valor relativo
	// puesto a mano, filepath.Join devolvía algo como `.\   \codeguard\codeguard.db`,
	// relativo al directorio de trabajo — que durante un commit es el repo que se
	// está analizando. La base de datos acababa DENTRO del repo del usuario, donde
	// además puede terminar commiteada.
	//
	// Y había una segunda consecuencia, más difícil de diagnosticar: cmd/codeguard
	// resuelve la MISMA base por su cuenta (dirDatos) y ésa sí exigía ruta
	// absoluta, así que en ese estado las dos puertas apuntaban a archivos
	// DISTINTOS y el usuario veía un historial u otro según por qué comando
	// entrara.
	//
	// Es la misma clase que H007, N001 y N003, con la misma lección: la guarda va
	// donde se resuelve la ruta. Aquí faltaba generalizarla a esta segunda puerta.
	dir := filepath.Join(os.Getenv("LOCALAPPDATA"), "codeguard")
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(os.TempDir(), "codeguard")
	}
	if !filepath.IsAbs(dir) {
		// Sin ningún sitio absoluto donde escribir, se devuelve vacío y Open
		// falla en voz alta. Es preferible a inventar una ruta: una base de
		// datos en el sitio equivocado no se nota hasta que faltan los datos.
		return ""
	}
	_ = os.MkdirAll(dir, 0o755) // best-effort: Open dará el error real si no se puede escribir
	return filepath.Join(dir, "codeguard.db")
}

// SaveFeedback registra el veredicto del dev sobre un hallazgo (§5 etapa 9:
// la única palanca de calibración del sistema).
func (s *Store) SaveFeedback(findingID, verdict, comment string) error {
	if verdict != "useful" && verdict != "false_positive" && verdict != "unclear" {
		return fmt.Errorf("veredicto inválido: %q", verdict)
	}
	_, err := s.db.Exec(`INSERT INTO feedback (id, finding_id, verdict, comment, created_at)
		VALUES (?, ?, ?, ?, ?)`, NewULID(), findingID, verdict, comment, nowISO())
	return err
}

var _ = finding.Finding{} // referencia explícita al modelo del contrato
