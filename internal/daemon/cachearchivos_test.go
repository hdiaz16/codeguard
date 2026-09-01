package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"codeguard/internal/config"
	"codeguard/internal/engines"
	"codeguard/internal/finding"
	"codeguard/internal/store"
)

func cachePersistenteDePrueba(t *testing.T) (*store.Store, *cacheArchivos) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "cache.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	analysisRoot := t.TempDir()
	c, ok := CachePorArchivo(st, "repo-cache", "", "repo", &config.Config{
		Rulepack: "2026.08.2",
		Hash:     "config-prueba",
	}, analysisRoot).(*cacheArchivos)
	if !ok {
		t.Fatal("CachePorArchivo no devolvió el adaptador persistente")
	}
	return st, c
}

func hallazgoCacheDePrueba() finding.Finding {
	return finding.Finding{
		Engine:      "semgrep",
		RuleKey:     "python-eval",
		Pillar:      finding.Security,
		Severity:    finding.Error,
		Blocking:    true,
		File:        "app.py",
		Line:        4,
		Message:     "eval permite ejecutar código arbitrario",
		Verified:    true,
		Source:      finding.Deterministic,
		LineContent: "eval(entrada)",
	}
}

func ponerCacheCrudo(t *testing.T, st *store.Store, c *cacheArchivos, clave, crudo string) {
	t.Helper()
	if err := st.FileCachePut(c.repoID, c.rulepack, c.configHash, map[string]string{clave: crudo}); err != nil {
		t.Fatal(err)
	}
}

func TestElCacheDistingueVacioValidoDeCorrupcion(t *testing.T) {
	st, c := cachePersistenteDePrueba(t)

	valido := hallazgoCacheDePrueba()
	jsValido, err := json.Marshal([]enCache{{Finding: valido, LineContent: valido.LineContent}})
	if err != nil {
		t.Fatal(err)
	}
	jsIncompleto, err := json.Marshal([]enCache{{Finding: finding.Finding{
		Engine: "semgrep", RuleKey: "python-eval",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	conRutaAbsoluta := valido
	conRutaAbsoluta.File = filepath.Join(t.TempDir(), "app.py")
	jsRutaAbsoluta, err := json.Marshal([]enCache{{
		Finding: conRutaAbsoluta, LineContent: conRutaAbsoluta.LineContent,
	}})
	if err != nil {
		t.Fatal(err)
	}

	casos := map[string]string{
		"limpio":        "[]",
		"null":          "null",
		"json-roto":     "[{",
		"incompleto":    string(jsIncompleto),
		"ruta-absoluta": string(jsRutaAbsoluta),
		"hallazgo":      string(jsValido),
	}
	for clave, crudo := range casos {
		ponerCacheCrudo(t, st, c, clave, crudo)
	}

	got := c.Leer([]string{"limpio", "null", "json-roto", "incompleto", "ruta-absoluta", "hallazgo"})
	if fs, ok := got["limpio"]; !ok || fs == nil || len(fs) != 0 {
		t.Fatalf("[] debe ser un hit limpio válido; resultado=%#v, presente=%v", fs, ok)
	}
	for _, clave := range []string{"null", "json-roto", "incompleto", "ruta-absoluta"} {
		if _, ok := got[clave]; ok {
			t.Errorf("la entrada corrupta %q se sirvió como hit: %#v", clave, got[clave])
		}
	}
	fs, ok := got["hallazgo"]
	if !ok || len(fs) != 1 || fs[0].RuleKey != valido.RuleKey || fs[0].LineContent != valido.LineContent {
		t.Fatalf("el hallazgo válido no sobrevivió al caché: %#v", fs)
	}
}

func TestUnErrorDeLecturaDelCacheFuerzaReanalisis(t *testing.T) {
	st, c := cachePersistenteDePrueba(t)
	ponerCacheCrudo(t, st, c, "sha", "[]")
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	if got := c.Leer([]string{"sha"}); got != nil {
		t.Fatalf("un store averiado debe devolver nil (miss total), no hits: %#v", got)
	}
}

func TestElCacheNoPersisteHallazgosSiLaClaveYaNoEsVigente(t *testing.T) {
	_, c := cachePersistenteDePrueba(t)
	c.Guardar(nil)
	// La protección TOCTOU exige Vigente. Su ausencia no puede convertirse en
	// una entrada reutilizable aunque el hallazgo sea estructuralmente válido.
	c.Guardar([]engines.Cacheable{{
		Clave: "sha-obsoleto", Findings: []finding.Finding{hallazgoCacheDePrueba()},
	}})
	if got := c.Leer([]string{"sha-obsoleto"}); len(got) != 0 {
		t.Fatalf("se persistió una entrada sin prueba de vigencia: %#v", got)
	}
}

func TestElCacheHidrataLaLineaDesdeElArbolExactoAntesDeGuardar(t *testing.T) {
	_, c := cachePersistenteDePrueba(t)
	ruta := filepath.Join(c.analysisRoot, "app.py")
	if err := os.WriteFile(ruta, []byte("eval(entrada)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := hallazgoCacheDePrueba()
	f.Line = 1
	f.LineContent = "" // así llegan Ruff, TSC y otros antes del finalizador
	c.Guardar([]engines.Cacheable{{
		Clave: "sha-hidratado", Vigente: func() bool { return true },
		Findings: []finding.Finding{f},
	}})

	got := c.Leer([]string{"sha-hidratado"})["sha-hidratado"]
	if len(got) != 1 || got[0].LineContent != "eval(entrada)" {
		t.Fatalf("la identidad por línea no se hidrató antes de persistir: %#v", got)
	}
}
