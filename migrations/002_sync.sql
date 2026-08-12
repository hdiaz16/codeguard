-- 002: la marca de agua del empuje al central (fase 5, telemetría a nivel
-- organización). Cada tabla sincronizada guarda aquí el último id ULID
-- confirmado en el central: los ULID ordenan por tiempo lexicográficamente,
-- así que "id > ultima" es exactamente "lo que falta por viajar". El central
-- se crea con estas mismas migraciones a propósito (un solo DDL, cero
-- divergencia), así que la tabla también existe allá — vacía e inofensiva.
CREATE TABLE sync_marcas (
  tabla          TEXT PRIMARY KEY,
  ultima         TEXT NOT NULL,
  actualizada_at TEXT NOT NULL
);
