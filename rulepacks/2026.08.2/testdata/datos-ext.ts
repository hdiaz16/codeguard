// Fixture de semgrep --test — no es código del producto.
// Casos de prueba del pilar datos (stem datos-ext), lenguaje TypeScript.

// --- pii-en-telemetria ---------------------------------------------------------------
export function rastrearAlta(correo: string, plan: string) {
  // ruleid: pii-en-telemetria
  analytics.track("alta de cuenta", { email: correo });
  // ok: pii-en-telemetria
  analytics.track("alta de cuenta", { plan: plan });
}

// --- ts-datetime-naive ---------------------------------------------------------------
export function crearFechas() {
  // ruleid: ts-datetime-naive
  const inicio = new Date("2026-01-15");
  // ok: ts-datetime-naive
  const fin = new Date("2026-01-15T00:00:00-06:00");
  return [inicio, fin];
}

// --- escrituras-sin-transaccion-ts ------------------------------------------------------
export async function guardarPedido(db: any, pedido: any, reserva: any) {
  // ruleid: escrituras-sin-transaccion-ts
  db.update(pedido);
  db.delete(reserva);
}

export async function guardarPedidoAtomico(sequelize: any, pedido: any, reserva: any) {
  await sequelize.transaction(async (tx: any) => {
    // ok: escrituras-sin-transaccion-ts
    tx.update(pedido);
    tx.delete(reserva);
  });
}

// --- ts-dinero-float -----------------------------------------------------------------
// ruleid: ts-dinero-float
const precioBase: number = 99.9;
// ruleid: ts-dinero-float
let saldoPendiente: number = 0;

// ruleid: ts-dinero-float
export function cobrar(importeFinal: number) {
  return importeFinal;
}

// El nombre no es monetario: la regla filtra por nombre.
// ok: ts-dinero-float
const cantidadItems: number = 3;
// Dinero como entero en centavos, el remedio recomendado.
// ok: ts-dinero-float
const precioCentavos: bigint = 9990n;
