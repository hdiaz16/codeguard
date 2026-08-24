// Fixture de semgrep --test — no es código del producto.
using System.Runtime.Serialization.Formatters.Binary;
using System.Text.Json;

namespace Fixtures
{
    public class SeguridadFixture
    {
        public object Deserializar()
        {
            // ruleid: csharp-binaryformatter
            var formateador = new BinaryFormatter();
            return formateador;
        }

        public string SerializarSeguro(object dato)
        {
            // ok: csharp-binaryformatter
            return JsonSerializer.Serialize(dato);
        }
    }
}
