-- 009: la fórmula de riesgo, versionada explícitamente (W6, defecto #1 de GPT).
-- El risk_score guardado no decía CÓMO se calculó: un hash de los pesos no basta
-- —el ALGORITMO puede cambiar con los mismos pesos (un factor nuevo, otra
-- combinación)— así que un score viejo y uno nuevo se comparaban como si
-- salieran de la misma regla. Ahora cada run lleva las dos mitades de esa
-- identidad: risk_formula_version (el algoritmo, a mano) y risk_config_hash
-- (los pesos, derivado). Con las dos, dos scores son comparables solo si
-- coinciden ambas.
--
-- SOLO DDL, expand-only: corre TAMBIÉN en el Postgres central. NULL = run
-- anterior a esta migración (legacy explícito; nadie lo re-infiere).
ALTER TABLE runs ADD COLUMN risk_formula_version INTEGER;
ALTER TABLE runs ADD COLUMN risk_config_hash TEXT;
