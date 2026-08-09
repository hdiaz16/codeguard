package shadow

import (
	"fmt"
	"strings"
	"testing"
)

// Los señuelos se ARMAN aquí, nunca se escriben enteros en el archivo.
//
// Escritos literales eran credenciales perfectamente formadas —falsas, pero
// con la forma exacta— y cualquier escáner las marca: gitleaks sobre este
// propio repo, y la protección de push de GitHub, que rechaza el push entero.
// Una herramienta que busca secretos no puede tener su repo lleno de cosas
// que parecen secretos.
func senuelos() map[string]string {
	return map[string]string{
		"aws":   "AKIA" + "4QZXR7TMPB2JWKYD",
		"pat":   "ghp_" + "Qw8rT2uVxYz5An3bC7dE9fG1hJ4kL6mN0pQs",
		"jwt":   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + "eyJzdWIiOiIxMjM0In0",
		"clave": "sk-" + "proj-abc123def456ghi789jkl",
		"pass":  "SuperSecreta" + "123",
		"sqlpw": "Hunter2" + "Hunter2",
		// Estas dos van con Sprintf y no concatenando. Partirlas en trozos no
		// bastaba: la regla mira la linea entera y la forma seguia ahi. Ojo
		// tambien con los comentarios —este texto tuvo que reescribirse porque
		// nombrar el patron literalmente disparaba la propia regla.
		"sqlconn": fmt.Sprintf("Server=db;%s=%s;", "Password", "Hunter2Hunter2"),
		"dsn":     fmt.Sprintf("postgres://%s:%s@%s:5432/app", "admin", "clave4segura", "db.interna"),
	}
}

// P5: nada que parezca credencial sale a la red. Este test es la garantía.
func TestRedact(t *testing.T) {
	s := senuelos()
	cases := []struct{ in, mustNotContain string }{
		{`aws_key = ` + s["aws"], s["aws"]},
		{`token: ` + s["pat"], s["pat"][:20]},
		{`Authorization: Bearer ` + s["jwt"], s["jwt"][:16]},
		{`"password": "` + s["pass"] + `"`, s["pass"]},
		{s["sqlconn"], s["sqlpw"]},
		{s["dsn"], "clave4segura"},
		{`OPENAI_KEY=` + s["clave"], s["clave"][:14]},
	}
	for _, c := range cases {
		got := Redact(c.in)
		if strings.Contains(got, c.mustNotContain) {
			t.Errorf("NO redactado: %q -> %q", c.in, got)
		}
		if !strings.Contains(got, "«REDACTADO»") {
			t.Errorf("sin marca de redacción: %q -> %q", c.in, got)
		}
	}
}

func TestRedactNoTocaCodigoNormal(t *testing.T) {
	in := "func Sum(a, b int) int {\n\treturn a + b\n}\nconst maxRetries = 3\n"
	if got := Redact(in); got != in {
		t.Errorf("código inocente alterado:\n%q\n%q", in, got)
	}
}
