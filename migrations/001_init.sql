-- 001: esquema inicial (sección 9 de la spec, con diff_cache y config_hash en cachés)
CREATE TABLE repos (
  id            TEXT PRIMARY KEY,
  remote_url    TEXT NOT NULL,
  name          TEXT NOT NULL,
  first_seen_at TEXT NOT NULL,
  last_seen_at  TEXT NOT NULL
);

CREATE TABLE rules (
  id            TEXT PRIMARY KEY,
  engine        TEXT NOT NULL,
  rule_key      TEXT NOT NULL,
  pillar        TEXT NOT NULL CHECK (pillar IN ('quality','security','data')),
  severity      TEXT NOT NULL CHECK (severity IN ('info','warning','error')),
  blocking      INTEGER NOT NULL DEFAULT 0 CHECK (blocking IN (0,1)),
  title         TEXT NOT NULL,
  rationale     TEXT,
  rulepack_ver  TEXT NOT NULL,
  UNIQUE (engine, rule_key, rulepack_ver)
);

CREATE TABLE runs (
  id              TEXT PRIMARY KEY,
  repo_id         TEXT NOT NULL REFERENCES repos(id),
  branch          TEXT NOT NULL,
  started_at      TEXT NOT NULL,
  finished_at     TEXT,
  verdict         TEXT CHECK (verdict IN ('pass','block','degraded','skipped')),
  risk_score      INTEGER NOT NULL DEFAULT 0,
  files_changed   INTEGER NOT NULL DEFAULT 0,
  lines_changed   INTEGER NOT NULL DEFAULT 0,
  ai_generated    INTEGER NOT NULL DEFAULT 0 CHECK (ai_generated IN (0,1)),
  llm_used        INTEGER NOT NULL DEFAULT 0 CHECK (llm_used IN (0,1)),
  bypassed        INTEGER NOT NULL DEFAULT 0 CHECK (bypassed IN (0,1)),
  ci_parity       INTEGER NOT NULL DEFAULT 1 CHECK (ci_parity IN (0,1)),
  degraded_layers TEXT,
  rulepack_ver    TEXT NOT NULL,
  config_hash     TEXT NOT NULL,
  elapsed_ms      INTEGER NOT NULL DEFAULT 0,
  environment     TEXT NOT NULL CHECK (environment IN ('local','ci'))
);
CREATE INDEX idx_runs_repo_started ON runs (repo_id, started_at);

CREATE TABLE findings (
  id            TEXT PRIMARY KEY,
  run_id        TEXT NOT NULL REFERENCES runs(id),
  rule_id       TEXT REFERENCES rules(id),
  engine        TEXT NOT NULL,
  rule_key      TEXT NOT NULL,
  pillar        TEXT NOT NULL CHECK (pillar IN ('quality','security','data')),
  severity      TEXT NOT NULL CHECK (severity IN ('info','warning','error')),
  source        TEXT NOT NULL CHECK (source IN ('deterministic','llm')),
  blocking      INTEGER NOT NULL DEFAULT 0 CHECK (blocking IN (0,1)),
  verified      INTEGER NOT NULL DEFAULT 1 CHECK (verified IN (0,1)),
  shown         INTEGER NOT NULL DEFAULT 0 CHECK (shown IN (0,1)),
  file_path     TEXT NOT NULL,
  line_start    INTEGER,
  line_end      INTEGER,
  fingerprint   TEXT NOT NULL,
  message       TEXT NOT NULL,
  why           TEXT,
  fix_hint      TEXT,
  created_at    TEXT NOT NULL
);
CREATE INDEX idx_findings_run ON findings (run_id);
CREATE INDEX idx_findings_fingerprint ON findings (fingerprint);

CREATE TABLE feedback (
  id          TEXT PRIMARY KEY,
  finding_id  TEXT NOT NULL REFERENCES findings(id),
  verdict     TEXT NOT NULL CHECK (verdict IN ('useful','false_positive','unclear')),
  comment     TEXT,
  created_at  TEXT NOT NULL
);
CREATE INDEX idx_feedback_finding ON feedback (finding_id);

CREATE TABLE suppressions (
  id           TEXT PRIMARY KEY,
  repo_id      TEXT NOT NULL REFERENCES repos(id),
  fingerprint  TEXT NOT NULL,
  scope        TEXT NOT NULL CHECK (scope IN ('baseline','manual')),
  reason       TEXT,
  created_at   TEXT NOT NULL,
  expires_at   TEXT,
  UNIQUE (repo_id, fingerprint)
);

-- Resultados deterministas: por archivo
CREATE TABLE file_cache (
  id           TEXT PRIMARY KEY,
  repo_id      TEXT NOT NULL REFERENCES repos(id),
  file_sha256  TEXT NOT NULL,
  rulepack_ver TEXT NOT NULL,
  config_hash  TEXT NOT NULL,
  result_json  TEXT NOT NULL,
  created_at   TEXT NOT NULL,
  UNIQUE (repo_id, file_sha256, rulepack_ver, config_hash)
);

-- Resultados LLM: por diff (el análisis usa contexto entre archivos)
CREATE TABLE diff_cache (
  id           TEXT PRIMARY KEY,
  repo_id      TEXT NOT NULL REFERENCES repos(id),
  diff_sha256  TEXT NOT NULL,
  rulepack_ver TEXT NOT NULL,
  config_hash  TEXT NOT NULL,
  model        TEXT NOT NULL,
  result_json  TEXT NOT NULL,
  created_at   TEXT NOT NULL,
  UNIQUE (repo_id, diff_sha256, rulepack_ver, config_hash, model)
);

CREATE TABLE llm_calls (
  id                 TEXT PRIMARY KEY,
  run_id             TEXT NOT NULL REFERENCES runs(id),
  pillar             TEXT NOT NULL CHECK (pillar IN ('quality','security','data')),
  model              TEXT NOT NULL,
  prompt_tokens      INTEGER NOT NULL DEFAULT 0,
  completion_tokens  INTEGER NOT NULL DEFAULT 0,
  cost_micros        INTEGER NOT NULL DEFAULT 0,
  latency_ms         INTEGER NOT NULL DEFAULT 0,
  status             TEXT NOT NULL CHECK (status IN ('ok','timeout','error','skipped')),
  findings_returned  INTEGER NOT NULL DEFAULT 0,
  findings_rejected  INTEGER NOT NULL DEFAULT 0,
  created_at         TEXT NOT NULL
);
CREATE INDEX idx_llm_calls_run ON llm_calls (run_id);
