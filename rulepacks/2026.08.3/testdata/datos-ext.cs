// Fixture de semgrep --test — no es código del producto.
// Casos de prueba del pilar datos (stem datos-ext), lenguaje C#.
using System;
using System.Collections.Generic;
using System.Linq;

namespace Fixtures
{
    public class DatosExt
    {
        // --- csharp-dinero-float ---------------------------------------------
        public void CalcularCobro()
        {
            // ruleid: csharp-dinero-float
            double montoTotal = 100.0;
            // ok: csharp-dinero-float
            double distanciaKm = 12.5;
        }

        // --- csharp-datetime-naive -------------------------------------------
        public void MarcarTiempos()
        {
            // ruleid: csharp-datetime-naive
            var creado = DateTime.Now;
            // ok: csharp-datetime-naive
            var registrado = DateTimeOffset.UtcNow;
        }

        // --- csharp-orm-en-bucle ---------------------------------------------
        public void CargarClientes(MiContexto ctx, List<int> ids)
        {
            foreach (int id in ids)
            {
                // ruleid: csharp-orm-en-bucle
                var cliente = ctx.Clientes.FirstOrDefault(c => c.Id == id);
            }
            // ok: csharp-orm-en-bucle
            var primero = ctx.Clientes.FirstOrDefault();
        }
    }
}
