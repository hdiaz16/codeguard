-- 008: cobertura por capa, persistida (W6 Q3, consejo t.128). Hasta aquí el
-- resultado guardaba degraded_layers como un string de etiquetas: servía para
-- el veredicto de UN run, pero no dejaba ver que una MISMA capa lleva días
-- degradándose. Sin ese historial, «semgrep falló hoy» y «semgrep lleva una
-- semana sin mirar Python» se leen igual, y el segundo es el que importa.
--
-- SOLO DDL, expand-only: corre TAMBIÉN en el Postgres central (un único DDL,
-- cero divergencia). No siembra nada. La ESCRITURA de estas tablas es LOCAL —
-- el doctor las lee en la máquina— así que el central tiene el esquema pero, por
-- ahora, sin filas; la agregación de flota es trabajo posterior y este esquema
-- no la estorba.

-- run_layers: una fila por (run, motor). Es el recibo de cobertura de la síntesis
-- Q2 aterrizado: cuántas unidades prometió el motor y cuántas completaron o
-- quedaron a medias. state y reason_code son ESTABLES (los pone capaDe, el único
-- clasificador); los counts vienen del cruce plan-vs-recibos. unit_kind dice si
-- el motor declara cobertura fina (file) o corrió como capa entera (layer).
CREATE TABLE run_layers (
  run_id         TEXT NOT NULL REFERENCES runs(id),
  engine         TEXT NOT NULL,
  unit_kind      TEXT,                       -- file | layer  (NULL = no declarada)
  state          TEXT NOT NULL,              -- corrio | degradada | ausente | no-aplica
  reason_code    TEXT,                       -- estable; NULL cuando state = corrio/no-aplica
  planned_count  INTEGER NOT NULL DEFAULT 0,
  complete_count INTEGER NOT NULL DEFAULT 0,
  partial_count  INTEGER NOT NULL DEFAULT 0,
  findings       INTEGER NOT NULL DEFAULT 0,
  ms             BIGINT  NOT NULL DEFAULT 0,
  created_at     TEXT NOT NULL,
  PRIMARY KEY (run_id, engine)
);
-- Sin índice secundario por ahora: nadie consulta run_layers por motor todavía
-- (el doctor lee layer_health, no esto). Cuando una vista de historial lo pida,
-- se añade su índice entonces —con su justificación— en vez de cargar aquí un
-- índice sin lector. La PK (run_id, engine) cubre la lectura por run.

-- layer_health: el estado ACUMULADO de cada (repo, motor). La racha cuenta
-- fallos CONSECUTIVOS y se reinicia SOLO cuando la capa aplica Y completa (un
-- no-aplica ni cura ni rompe: la capa no tenía nada que mirar). reason_code
-- guarda el motivo del fallo vigente; «misma reason_code con detalles distintos
-- cuenta como la misma», por eso el detalle libre no vive aquí. Con la racha y
-- las fechas, el doctor decide recurrente (2 consecutivos) o persistente (5
-- consecutivos o ≥2 durante >24 h) sin recalcular nada.
CREATE TABLE layer_health (
  repo_id              TEXT NOT NULL REFERENCES repos(id),
  engine               TEXT NOT NULL,
  reason_code          TEXT,                 -- motivo del fallo vigente; NULL si la última fue éxito
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  first_failure_at     TEXT,                 -- inicio de la racha actual
  last_failure_at      TEXT,
  last_success_at      TEXT,
  updated_at           TEXT NOT NULL,
  PRIMARY KEY (repo_id, engine)
);
