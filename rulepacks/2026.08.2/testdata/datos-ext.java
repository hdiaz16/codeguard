// Fixture de semgrep --test — no es código del producto.
// Casos de prueba del pilar datos (stem datos-ext), lenguaje Java.
package fixtures;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.List;

public class DatosExt {

    // --- java-dinero-float ---------------------------------------------------
    public void calcularCobro() {
        // ruleid: java-dinero-float
        double montoTotal = 100.0;
        // ok: java-dinero-float
        double distanciaKm = 12.5;
    }

    // --- java-datetime-naive -------------------------------------------------
    public void marcarTiempos() {
        // ruleid: java-datetime-naive
        Date creado = new Date();
        // ruleid: java-datetime-naive
        LocalDateTime corte = LocalDateTime.now();
        // ok: java-datetime-naive
        Instant registrado = Instant.now();
    }

    // --- java-orm-en-bucle ---------------------------------------------------
    public void cargarClientes(EntityManager em, List<Long> ids) {
        for (int i = 0; i < ids.size(); i++) {
            // ruleid: java-orm-en-bucle
            Object cliente = em.find(Cliente.class, ids.get(i));
        }
        // ok: java-orm-en-bucle
        Object primero = em.find(Cliente.class, 1L);
    }
}
