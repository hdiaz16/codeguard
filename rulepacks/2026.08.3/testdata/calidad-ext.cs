// Fixture de semgrep --test — no es código del producto.
// Casos de prueba del pilar calidad (stem calidad-ext), lenguaje C#.
using System;

namespace Fixtures
{
    public class ProcesosCalidad
    {
        public void Ejecutar()
        {
            // ruleid: csharp-catch-swallow
            try { Procesar(); } catch { }
        }

        public void EjecutarTipado()
        {
            // ruleid: csharp-catch-swallow
            try { Procesar(); } catch (InvalidOperationException) { }
        }

        public void EjecutarConRegistro()
        {
            // ok: csharp-catch-swallow
            try { Procesar(); } catch (Exception e) { Registrar(e); throw; }
        }

        private void Procesar() { }

        private void Registrar(Exception e) { }
    }
}
