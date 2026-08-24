-- 004: la ventana dual de huellas (v2, consejo turnos 71-84).
--
-- findings.fingerprint pasa a llevar el formato vigente ("v2:<hex>") en las
-- filas nuevas; las viejas conservan su 64-hex desnudo (v1) y NO se
-- reescriben — se midieron con el contrato anterior.
--
-- fingerprint_legacy es el alias v1 EXACTO del hallazgo (finding.LegacyV1):
-- existe para que el historial de «cerrados» —que compara huella↔huella entre
-- corridas— no anuncie una ola falsa de resueltos el día del despliegue: la
-- comparación va por COALESCE(fingerprint_legacy, fingerprint), que en filas
-- viejas es la v1 y en filas nuevas su alias v1 — mismo espacio de claves
-- durante toda la ventana. Al expirar la ventana, la comparación pasa a v2 y
-- esta columna queda como registro histórico.
--
-- Expand-only; el central corre estas mismas migraciones.
ALTER TABLE findings ADD COLUMN fingerprint_legacy TEXT;
CREATE INDEX idx_findings_fingerprint_legacy ON findings (fingerprint_legacy);
