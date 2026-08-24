package staticcheck

import "testing"

// Fuzz del parser de la salida JSON-por-línea de staticcheck (W6, defecto #2).
// El contrato: una salida corrupta devuelve (findings, error), jamás panic —un
// panic aquí tumbaría la capa de análisis estático entera.
func FuzzInterpretar(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("{"))
	f.Add([]byte("basura\x00\xff"))
	f.Add([]byte(`{"code":"SA4006","severity":"error","location":{"file":"a.go","line":1,"column":2},"message":"m"}`))
	f.Add([]byte("{}\n{}\n"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = interpretar(raw, ".", "repo")
	})
}
