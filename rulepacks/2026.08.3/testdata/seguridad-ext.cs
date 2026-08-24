// Fixture de semgrep --test — no es código del producto.
// Casos positivos (ruleid) y negativos (ok) para las reglas csharp-* y
// cors-wildcard-con-credenciales-net de seguridad-ext.yaml.
// Solo necesita parsear: los tipos no se resuelven.
namespace Fixtures
{
    public class SeguridadExtFixture
    {
        void SqlConcat(string idUsuario, SqlConnection conexion)
        {
            // ruleid: csharp-sql-concat
            var comando = new SqlCommand("SELECT id, nombre FROM usuarios WHERE id = " + idUsuario, conexion);
            // ruleid: csharp-sql-concat
            var interpolado = new NpgsqlCommand($"SELECT id, nombre FROM usuarios WHERE nombre = {idUsuario}", conexion);
            // ok: csharp-sql-concat
            var seguro = new SqlCommand("SELECT id, nombre FROM usuarios WHERE id = @id", conexion);
        }

        void Comandos(string entrada)
        {
            // ruleid: csharp-command-injection
            var infoInsegura = new ProcessStartInfo { FileName = "cmd.exe", UseShellExecute = true };
            // ruleid: csharp-command-injection
            Process.Start("cmd.exe", $"/c {entrada}");
            // ok: csharp-command-injection
            var infoSegura = new ProcessStartInfo { FileName = "git", UseShellExecute = false };
        }

        void JwtSinVerificar(JwtSecurityTokenHandler manejador, string tokenCrudo)
        {
            // ruleid: csharp-jwt-no-verify
            var parametros = new TokenValidationParameters { ValidateIssuerSigningKey = false };
            // ruleid: csharp-jwt-no-verify
            var contenido = manejador.ReadJwtToken(tokenCrudo);
            // ok: csharp-jwt-no-verify
            var parametrosSeguros = new TokenValidationParameters { ValidateIssuerSigningKey = true, ValidateLifetime = true };
        }

        void Evaluar(string codigo)
        {
            // ruleid: csharp-dynamic-eval
            CSharpScript.EvaluateAsync(codigo);
            // ok: csharp-dynamic-eval
            var numero = int.Parse(codigo);
        }

        void Criptografia(Aes cifrador)
        {
            // ruleid: csharp-crypto-debil
            var resumenInseguro = MD5.Create();
            // ruleid: csharp-crypto-debil
            cifrador.Mode = CipherMode.ECB;
            // ok: csharp-crypto-debil
            var resumenSeguro = SHA256.Create();
            // ok: csharp-crypto-debil
            cifrador.Mode = CipherMode.CBC;
        }

        void Aleatorios()
        {
            // ruleid: csharp-random-inseguro
            var generador = new Random();
            // ruleid: csharp-random-inseguro
            var valor = Random.Shared.Next();
            // ok: csharp-random-inseguro
            var seguro = RandomNumberGenerator.GetInt32(100);
        }

        void TlsPermisivo()
        {
            // ruleid: csharp-tls-verify-off
            ServicePointManager.ServerCertificateValidationCallback = (emisor, certificado, cadena, errores) => true;
            // ruleid: csharp-tls-verify-off
            var manejadorInseguro = new HttpClientHandler { ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator };
            // ok: csharp-tls-verify-off
            var manejadorSeguro = new HttpClientHandler { AllowAutoRedirect = false };
        }

        void Xml(XmlDocument documento)
        {
            // ruleid: csharp-xxe
            var opcionesInseguras = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse };
            // ruleid: csharp-xxe
            documento.XmlResolver = new XmlUrlResolver();
            // ok: csharp-xxe
            var opcionesSeguras = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit };
        }

        void Cors(CorsPolicyBuilder politica)
        {
            // ruleid: cors-wildcard-con-credenciales-net
            politica.AllowAnyOrigin().AllowCredentials();
            // ok: cors-wildcard-con-credenciales-net
            politica.WithOrigins("https://app.ejemplo.com").AllowCredentials();
        }
    }
}
