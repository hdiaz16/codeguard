package shadow

import (
	"strings"
	"testing"
)

// P5: nada que parezca credencial sale a la red. Este test es la garantía.
func TestRedact(t *testing.T) {
	cases := []struct{ in, mustNotContain string }{
		{`aws_key = AKIA4QZXR7TMPB2JWKYD`, "AKIA4QZXR7TMPB2JWKYD"},
		{`token: ghp_Qw8rT2uVxYz5An3bC7dE9fG1hJ4kL6mN0pQs`, "ghp_Qw8rT2uVxYz5An3bC7"},
		{`Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0`, "eyJhbGciOiJIUzI1"},
		{`"password": "SuperSecreta123"`, "SuperSecreta123"},
		{`Server=db;Password=Hunter2Hunter2;`, "Hunter2Hunter2"},
		{`postgres://admin:clave4segura@db.interna:5432/app`, "clave4segura"},
		{`OPENAI_KEY=sk-proj-abc123def456ghi789jkl`, "sk-proj-abc123"},
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
