// Fixture de semgrep --test — no es código del producto.
// Casos positivos (ruleid) y negativos (ok) de seguridad-paridad.yaml (go).
package testdata

import (
	"html/template"
	"net/http"
)

func xssMalo(delUsuario string) (template.HTML, template.JS, template.HTMLAttr) {
	// ruleid: go-xss
	a := template.HTML(delUsuario)
	// ruleid: go-xss
	b := template.JS(delUsuario)
	// ruleid: go-xss
	c := template.HTMLAttr(delUsuario)
	return a, b, c
}

func xssBueno() (template.HTML, template.JS) {
	// ok: go-xss
	a := template.HTML("<b>texto fijo del programador</b>")
	// ok: go-xss
	b := template.JS("var x = 1;")
	return a, b
}

func ssrfMalo(w http.ResponseWriter, r *http.Request) {
	destino := r.URL.Query().Get("url")
	// ruleid: go-ssrf
	resp, err := http.Get(destino)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

func ssrfBueno(w http.ResponseWriter, r *http.Request) {
	// ok: go-ssrf
	resp, err := http.Get("https://interno.empresa-ejemplo.local/salud")
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

func cookieMala(w http.ResponseWriter) {
	// ruleid: go-cookie-sin-httponly
	http.SetCookie(w, &http.Cookie{Name: "sesion", Value: "abc", Path: "/"})
}

func cookieBuena(w http.ResponseWriter) {
	// ok: go-cookie-sin-httponly
	http.SetCookie(w, &http.Cookie{
		Name:     "sesion",
		Value:    "abc",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}
