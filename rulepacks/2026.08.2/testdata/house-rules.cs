// Fixture de semgrep --test — no es código del producto.
using System;

namespace Fixtures
{
    public class ReglasCasaFixture
    {
        public void Procesar()
        {
            // ruleid: csharp-empty-catch
            try { EjecutarTarea(); } catch (Exception e) { }
        }

        public void ProcesarBien()
        {
            // ok: csharp-empty-catch
            try { EjecutarTarea(); } catch (Exception e) { Console.Error.WriteLine(e); }
        }

        public string CadenaConexion()
        {
            // ruleid: hardcoded-connstring
            return "Server=x;Database=demo;Password=changeme";
        }

        public string CadenaConexionBien()
        {
            // ok: hardcoded-connstring
            return Environment.GetEnvironmentVariable("CADENA_CONEXION");
        }

        private void EjecutarTarea()
        {
            Console.WriteLine("tarea");
        }
    }
}
