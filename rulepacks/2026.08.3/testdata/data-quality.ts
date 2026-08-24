// Fixture de semgrep --test — no es código del producto.

export async function cargarDetalles(db: Basedatos, ids: string[]) {
  const filas = [];
  for (let i = 0; i < ids.length; i++) {
    // ruleid: ts-query-en-bucle
    const fila = await db.query("SELECT id, total FROM pedidos WHERE id = $1", [ids[i]]);
    filas.push(fila);
  }
  return filas;
}

export async function cargarDetallesEnLote(db: Basedatos, ids: string[]) {
  // ok: ts-query-en-bucle
  return await db.query("SELECT id, total FROM pedidos WHERE id = ANY($1)", [ids]);
}

export function guardarPreferencias(datos: unknown) {
  // ruleid: catch-vacio-ts
  try {
    persistir(datos);
  } catch (e) {}
}

export function guardarPreferenciasBien(datos: unknown) {
  // ok: catch-vacio-ts
  try {
    persistir(datos);
  } catch (e) {
    console.error("fallo al persistir las preferencias", e);
  }
}
