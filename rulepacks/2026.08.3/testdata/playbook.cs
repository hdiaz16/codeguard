// Fixture de semgrep --test — no es código del producto.
namespace Fixtures
{
    public class PlaybookFixture
    {
        public object BuscarUsuarios(ContextoDatos ctx, string nombre)
        {
            // ruleid: orm-raw-interpolado-csharp
            return ctx.Usuarios.FromSqlRaw($"SELECT Id FROM Usuarios WHERE Nombre = '{nombre}'");
        }

        public object BuscarUsuariosBien(ContextoDatos ctx, int id)
        {
            // ok: orm-raw-interpolado-csharp
            return ctx.Usuarios.FromSqlInterpolated($"SELECT Id FROM Usuarios WHERE Id = {id}");
        }

        public CookieOptions CrearOpciones()
        {
            // ruleid: cookie-sin-httponly-csharp
            return new CookieOptions { Secure = true };
        }

        public CookieOptions CrearOpcionesBien()
        {
            // ok: cookie-sin-httponly-csharp
            return new CookieOptions { HttpOnly = true, Secure = true };
        }
    }
}
