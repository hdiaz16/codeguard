# Fixture de semgrep --test -- no es codigo del producto, y la extension .rb
# es MENTIRA DELIBERADA: el contenido es SQL. El modo test de semgrep intenta
# parsear las extensiones desconocidas (.sql, .pgsql) con TODOS los lenguajes
# del pack y los errores parciales son fatales; una extension conocida sin
# reglas de su lenguaje en el pack (.rb) la esquiva, y las reglas generic
# leen el texto igual. Medido con bisection el 2026-08-22.
# Migraciones deliberadamente peligrosas para las reglas pg-* de datos-ext.
# Anotaciones con almohadilla y no con guiones: son las sintaxis que el modo
# test de semgrep reconoce. Ojo: el parser generic exige brackets balanceados
# incluso dentro de comentarios.

# ruleid: pg-create-index-sin-concurrently
CREATE INDEX idx_usuarios_correo ON usuarios (correo);

# ruleid: pg-add-column-not-null-sin-default
ALTER TABLE usuarios ADD COLUMN estado text NOT NULL;

# ruleid: pg-add-constraint-sin-not-valid
ALTER TABLE pedidos ADD CONSTRAINT fk_pedidos_usuario FOREIGN KEY (usuario_id) REFERENCES usuarios (id);

# ruleid: pg-drop-table-column
ALTER TABLE usuarios DROP COLUMN apodo;

# ruleid: pg-alter-column-type
ALTER TABLE usuarios ALTER COLUMN saldo TYPE numeric(12,2);

# ruleid: pg-add-bigserial
ALTER TABLE eventos ADD COLUMN consecutivo BIGSERIAL;

# ruleid: pg-rename-column
ALTER TABLE usuarios RENAME COLUMN alias TO apodo_publico;

# ruleid: pg-add-constraint-unique
ALTER TABLE usuarios ADD CONSTRAINT uq_usuarios_correo UNIQUE (correo);

# ruleid: pg-grant-all-privileges
GRANT ALL PRIVILEGES ON esquema_publico TO aplicacion;

# ruleid: pg-money-type-disallowed
ALTER TABLE pagos ADD COLUMN importe money;

# ruleid: pg-index-concurrently-in-tx
BEGIN;
CREATE INDEX CONCURRENTLY idx_pedidos_fecha ON pedidos (fecha);
COMMIT;

# ruleid: sql-seed-password
INSERT INTO usuarios (correo, password) VALUES ('admin@ejemplo.invalido', 'password-de-semilla');
