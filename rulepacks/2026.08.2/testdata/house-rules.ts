// Fixture de semgrep --test — no es código del producto.

// ruleid: ts-explicit-any
function procesarDato(dato: any) {
  return dato;
}

// ok: ts-explicit-any
function procesarDatoSeguro(dato: unknown) {
  return dato;
}

export async function sincronizarPedidos(db: Basedatos, ids: string[]) {
  for (let i = 0; i < ids.length; i++) {
    // ruleid: sql-in-loop-ts
    await db.query("UPDATE pedidos SET sincronizado = 1 WHERE id = $1", [ids[i]]);
  }
}

export async function sincronizarPedidosEnLote(db: Basedatos, ids: string[]) {
  // ok: sql-in-loop-ts
  await db.query("UPDATE pedidos SET sincronizado = 1 WHERE id = ANY($1)", [ids]);
}
