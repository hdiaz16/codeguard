// Fixture de semgrep --test — no es código del producto.
// Casos positivos (ruleid) y negativos (ok) para las reglas java-* y
// cors-wildcard-con-credenciales-java de seguridad-ext.yaml.
// Solo necesita parsear: los tipos no se resuelven.
package fixtures;

import java.util.Arrays;

class SeguridadExtFixture {

    void sqlConcat(Statement stmt, Connection conn, String idUsuario) throws Exception {
        // ruleid: java-sql-concat
        stmt.executeQuery("SELECT id, nombre FROM usuarios WHERE id = " + idUsuario);
        // ok: java-sql-concat
        conn.prepareStatement("SELECT id, nombre FROM usuarios WHERE id = ?");
    }

    void comandos(String host, String comando) throws Exception {
        // ruleid: java-command-injection
        Runtime.getRuntime().exec("ping -c 1 " + host);
        // ruleid: java-command-injection
        new ProcessBuilder("sh", "-c", comando);
        // ok: java-command-injection
        ProcessBuilder listaSegura = new ProcessBuilder("ls", "-la");
    }

    Object deserializar(ObjectInputStream flujo) throws Exception {
        // ruleid: java-unsafe-deserialization
        Object objeto = flujo.readObject();
        // ruleid: java-unsafe-deserialization
        Yaml cargadorInseguro = new Yaml();
        // ok: java-unsafe-deserialization
        Yaml cargadorSeguro = new Yaml(new SafeConstructor());
        return objeto;
    }

    void jwtSinVerificar(JwtParser analizador, String tokenCrudo) {
        // ruleid: java-jwt-no-verify
        JWT.decode(tokenCrudo);
        // ruleid: java-jwt-no-verify
        analizador.parseClaimsJwt(tokenCrudo);
        // ok: java-jwt-no-verify
        analizador.parseClaimsJws(tokenCrudo);
    }

    void evaluar(ScriptEngine motor, String expresion) throws Exception {
        // ruleid: java-dynamic-eval
        motor.eval(expresion);
        // ok: java-dynamic-eval
        Integer.parseInt(expresion);
    }

    void criptografia() throws Exception {
        // ruleid: java-crypto-debil
        MessageDigest.getInstance("MD5");
        // ruleid: java-crypto-debil
        Cipher.getInstance("AES/ECB/PKCS5Padding");
        // ok: java-crypto-debil
        MessageDigest.getInstance("SHA-256");
        // ok: java-crypto-debil
        Cipher.getInstance("AES/GCM/NoPadding");
    }

    void aleatorios() {
        // ruleid: java-random-inseguro
        Random generador = new Random();
        // ok: java-random-inseguro
        SecureRandom seguro = new SecureRandom();
    }

    void tlsPermisivo(HttpsURLConnection conexion, SSLSocketFactory fabrica) {
        // ruleid: java-tls-verify-off
        conexion.setHostnameVerifier(NoopHostnameVerifier.INSTANCE);
        // ruleid: java-tls-verify-off
        TrustManager confiadoTodo = new X509TrustManager() {
            public void comprobar() { }
        };
        // ok: java-tls-verify-off
        conexion.setSSLSocketFactory(fabrica);
    }

    void xmlInseguro() throws Exception {
        // ruleid: java-xxe
        DocumentBuilderFactory fabricaInsegura = DocumentBuilderFactory.newInstance();
    }

    void xmlSeguro(DocumentBuilderFactory fabrica) throws Exception {
        fabrica.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        // ok: java-xxe
        DocumentBuilderFactory otraFabrica = DocumentBuilderFactory.newInstance();
    }

    void extraer(String directorio, ZipEntry entrada) {
        // ruleid: java-zip-slip
        File destino = new File(directorio, entrada.getName());
        // ok: java-zip-slip
        File fijo = new File(directorio, "salida.txt");
    }

    void responder(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        // ruleid: java-xss-response
        resp.getWriter().println(req.getParameter("nombre"));
        // ok: java-xss-response
        resp.getWriter().println("hola");
    }

    void cors(CorsConfiguration configuracion) {
        // ruleid: cors-wildcard-con-credenciales-java
        configuracion.setAllowedOrigins(Arrays.asList("*"));
        // ok: cors-wildcard-con-credenciales-java
        configuracion.setAllowedOrigins(Arrays.asList("https://app.ejemplo.com"));
    }
}
