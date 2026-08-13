// Fixture de semgrep --test — no es código del producto.
// Casos positivos (ruleid) y negativos (ok) de seguridad-paridad.yaml (java).
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URI;
import java.net.URL;

public class SeguridadParidad {

    public void ssrfMalo(HttpServletRequest request) throws Exception {
        String destino = request.getParameter("url");
        // ruleid: java-ssrf
        URL u = new URL(destino);
        u.openStream().close();
    }

    public void ssrfBueno() throws Exception {
        // ok: java-ssrf
        URL u = new URL("https://interno.bodesa.local/salud");
        u.openStream().close();
    }

    public void cookieMala(HttpServletResponse response) {
        // ruleid: java-cookie-sin-httponly
        Cookie c = new Cookie("sesion", "abc");
        c.setPath("/");
        response.addCookie(c);
    }

    public void cookieBuena(HttpServletResponse response) {
        // ok: java-cookie-sin-httponly
        Cookie c = new Cookie("sesion", "abc");
        c.setPath("/");
        c.setHttpOnly(true);
        c.setSecure(true);
        response.addCookie(c);
    }
}
