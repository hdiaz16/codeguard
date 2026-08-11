// Fixture de semgrep --test — no es código del producto.
// Casos de prueba del pilar calidad (stem calidad-ext), lenguaje TypeScript.

// --- ts-promesa-sin-await ------------------------------------------------------
// ruleid: ts-promesa-sin-await
cliente.obtener("/pedidos").then(procesar);

// ok: ts-promesa-sin-await
const respuesta = await cliente.obtener("/pedidos");

// El rechazo sí se maneja: este idioma era falso positivo antes de la
// curación de 2026-08-11 (pattern-not no suprime sub-rangos; -inside sí).
// ok: ts-promesa-sin-await
cliente.obtener("/pedidos").then(procesar).catch(reportar);

// --- test-saltado ---------------------------------------------------------------
// ruleid: test-saltado
it.only("suma dos cantidades", () => {});

// ruleid: test-saltado
xdescribe("módulo de envíos", () => {});

// ok: test-saltado
it("resta dos cantidades", () => {});

// --- assert-siempre-verdadero-ts -------------------------------------------------
// ruleid: assert-siempre-verdadero-ts
expect(true).toBe(true);

// ruleid: assert-siempre-verdadero-ts
expect(resultado).toBeDefined();

// ok: assert-siempre-verdadero-ts
expect(resultado.codigo).toBe(200);

// --- parametros-excesivos-ts -------------------------------------------------------
// ruleid: parametros-excesivos-ts
function crearEnvio(a, b, c, d, e, g) {
  return [a, b, c, d, e, g];
}

// ok: parametros-excesivos-ts
function crearNota(a, b, c) {
  return [a, b, c];
}

// --- anidamiento-profundo-ts ----------------------------------------------------
function revisar(a: boolean, b: boolean, c: boolean, d: boolean): boolean {
  // ruleid: anidamiento-profundo-ts
  if (a) {
    if (b) {
      if (c) {
        if (d) {
          return true;
        }
      }
    }
  }
  return false;
}

function revisarPlano(a: boolean, b: boolean, c: boolean): boolean {
  // ok: anidamiento-profundo-ts
  if (a) {
    if (b) {
      if (c) {
        return true;
      }
    }
  }
  return false;
}

// --- ts-ignore-sin-justificar ------------------------------------------------------
// ruleid: ts-ignore-sin-justificar
// @ts-ignore
const configuracion = cargarConfiguracion();

// ok: ts-ignore-sin-justificar
// @ts-expect-error CG-314: el tipado del SDK está incompleto
const ajustes = cargarConfiguracion();

// --- console-log-en-produccion -------------------------------------------------------
export function depurar(estado: string): void {
  // ruleid: console-log-en-produccion
  console.log(estado);
  // ok: console-log-en-produccion
  console.error(estado);
}
