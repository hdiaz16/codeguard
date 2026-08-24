package govulncheck

import "testing"

// Fuzz del parser de la salida de govulncheck (W6, defecto #2). El contrato: por
// muy rota que llegue la salida —el stream de mensajes JSON de govulncheck es
// prolijo y fácil de truncar—, el parser devuelve (findings, error), nunca
// panic.
func FuzzInterpretar(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("{"))
	f.Add([]byte("basura\x00\xff"))
	f.Add([]byte(`{"finding":{"osv":"GO-2024-0001","trace":[{"module":"m","version":"v1.0.0"}]}}`))
	f.Add([]byte(`{"osv":{"id":"GO-2024-0001","summary":"s"}}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = interpretar(raw, "repo", ".", true)
	})
}
