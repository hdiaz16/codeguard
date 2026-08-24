-- 007: outbox transaccional del sync (W5, consejo t.119-123). Cierra la
-- pérdida de eventos del mismo milisegundo (la marca id>ULID, autoconfesada
-- en sync.go:154-159: dos ULID del mismo ms se ordenan por su sufijo
-- aleatorio, así que una fila escrita en el ms de la marca cae detrás y no
-- viaja jamás) y el poison pill (un error permanente de una fila bloqueaba
-- el lote entero de esa tabla para siempre).
--
-- SOLO DDL: esta migración corre TAMBIÉN en el Postgres central (un único DDL,
-- cero divergencia), así que no siembra nada — sembrar aquí llenaría el
-- central de eventos locales inútiles. La siembra de lo ya existente la hace
-- un bootstrap LOCAL en Store.Open. Expand-only.

-- La secuencia monotónica propia, PORTABLE (AUTOINCREMENT de SQLite no existe
-- en Postgres y las migraciones son compartidas): una fila singleton cuyo
-- next_seq se incrementa DENTRO de la misma transacción que cada alta. Bajo
-- el escritor serializado del local (MaxOpenConns 1 + WAL) el seq refleja el
-- orden REAL de commit, sin las colisiones de milisegundo del ULID.
CREATE TABLE outbox_sequence (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  next_seq  BIGINT NOT NULL
);
INSERT INTO outbox_sequence (singleton, next_seq) VALUES (1, 1);

-- Un evento por alta o cambio. La elegibilidad para empujar es el ESTADO
-- (pending|retry), no una marca de agua: si un evento queda en retry, los
-- posteriores siguen y él no se pierde (el agujero de "seq > marca"). El
-- estado terminal es sent|superseded|quarantined; la cuarentena JAMÁS borra
-- el evento (se revisa con `sync retry`/`sync discard`).
--
-- revision permite que una entidad MUTABLE (runs, con su risk_score tardío)
-- genere un evento nuevo por cambio; el central acepta solo revisión >= la
-- suya, así un retry viejo no pisa una actualización nueva. UNIQUE(entity,
-- row_id, revision) hace idempotente la creación del evento.
CREATE TABLE outbox (
  seq             BIGINT PRIMARY KEY,
  entity          TEXT NOT NULL,
  row_id          TEXT NOT NULL,
  revision        BIGINT NOT NULL DEFAULT 1,
  operation       TEXT NOT NULL,              -- insert | update
  state           TEXT NOT NULL,              -- pending | retry | sent | superseded | quarantined
  attempts        INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TEXT,
  error_class     TEXT,                       -- transient | dependency | permanent | unknown
  error_detail    TEXT,
  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL,
  UNIQUE (entity, row_id, revision)
);

-- El empujador filtra por estado y ventana de reintento, ordenado por seq.
CREATE INDEX idx_outbox_pendientes ON outbox (state, next_attempt_at, seq);

-- runs es la ÚNICA entidad mutable (risk_score/llm_used llegan tarde): su
-- revisión monotónica local viaja al central, que rechaza revisiones viejas.
-- NULL = fila anterior a esta migración; el bootstrap la trata como revisión 1.
ALTER TABLE runs ADD COLUMN sync_revision BIGINT;
