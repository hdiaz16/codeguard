// Fixture de semgrep --test — no es código del producto.
// Casos de prueba del pilar calidad (stem calidad-ext), lenguaje Java.
package fixtures;

public class CalidadExt {

    // ruleid: java-test-saltado
    @Ignore
    public void pruebaPendiente() {
    }

    // ok: java-test-saltado
    @Disabled("CG-456: reactivar cuando termine la migración de la base")
    public void pruebaDocumentada() {
    }
}
