// Fixture de semgrep --test — no es código del producto.
class ReglasCasaFixture {
    void procesar() {
        // ruleid: java-empty-catch
        try {
            ejecutarTarea();
        } catch (Exception e) {
        }
    }

    void procesarBien() {
        // ok: java-empty-catch
        try {
            ejecutarTarea();
        } catch (Exception e) {
            System.err.println("fallo la tarea: " + e.getMessage());
        }
    }

    void ejecutarTarea() {
        System.out.println("tarea");
    }
}
