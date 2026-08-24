-- 005: identidad del rulepack en cada corrida (W3, consejo t.95-105).
--
-- rulepack_ver (001) guarda el NOMBRE pinneado; estas columnas guardan lo que
-- de verdad corrió: el digest sha256 del árbol de reglas
-- (codeguard-rulepack-tree-v1), de dónde salió (installed|vendored) y si su
-- manifiesto firmado verificó. El caso medido que las motiva: tres copias de
-- "2026.08.2" en la misma máquina con DOS contenidos distintos (161 reglas en
-- el repo, 130 instaladas, y la instalada ganando la resolución local mientras
-- el CI usaba la del repo) y ningún lector capaz de notarlo — el nombre puede
-- mentir, el digest no.
--
-- NULL = fila anterior a esta migración o corrida sin identidad resoluble
-- (legacy explícito, jamás se re-infiere). Expand-only; el central corre
-- estas mismas migraciones.
ALTER TABLE runs ADD COLUMN rulepack_digest TEXT;
ALTER TABLE runs ADD COLUMN rulepack_source TEXT;
ALTER TABLE runs ADD COLUMN rulepack_verified INTEGER;
