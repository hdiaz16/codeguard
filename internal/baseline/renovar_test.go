package baseline_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"codeguard/internal/baseline"
	"codeguard/internal/finding"
)

// La migración v1→v2 de la baseline, con las condiciones firmadas (turnos
// 76 y 83): re-emite SOLO lo que casa inequívocamente por el alias legacy,
// retira con aviso lo que ya no existe, CONSERVA como v1 lo ambiguo (el caso
// #9: sigue supriendo durante la ventana, el humano decide), y JAMÁS acepta
// un hallazgo vivo que no casaba con ninguna entrada — eso sería regenerar.

func vivo(t *testing.T, rule, file, contenido string, linea int) finding.Finding {
	t.Helper()
	return finding.Finding{Engine: "semgrep", RuleKey: rule, File: file,
		Line: linea, LineContent: contenido, Message: contenido}
}

func escribirBaseline(t *testing.T, repo string, lineas ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(repo, ".codeguard"), 0o755); err != nil {
		t.Fatal(err)
	}
	contenido := "# cabecera de prueba\n" + strings.Join(lineas, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(repo, filepath.FromSlash(baseline.RelPath)),
		[]byte(contenido), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRenovarMigraLoInequivocoYJamasReadmite(t *testing.T) {
	repo := t.TempDir()

	// Tres hallazgos vivos con entradas v1 en la baseline, más UNO NUEVO
	// (posterior a la baseline) que NO tiene entrada: el fixture de Kimi.
	vivos := []finding.Finding{
		vivo(t, "regla-a", "a.go", "linea a", 3),
		vivo(t, "regla-b", "b.go", "linea b", 7),
		vivo(t, "regla-c", "c.go", "linea c", 9),
		vivo(t, "regla-nueva", "d.go", "linea d", 2), // nuevo: debe seguir bloqueando
	}
	fuente := finding.FuenteDeLineas(nil)
	finding.AsignarHuellas(vivos, fuente)

	escribirBaseline(t, repo,
		vivos[0].LegacyFingerprint+"  # regla-a a.go:3",
		vivos[1].LegacyFingerprint+"  # regla-b b.go:7",
		vivos[2].LegacyFingerprint+"  # regla-c c.go:9",
	)

	r, err := baseline.Renovar(repo, vivos)
	if err != nil {
		t.Fatal(err)
	}
	if r.Migradas != 3 || len(r.Desaparecidas) != 0 || len(r.Conservadas) != 0 {
		t.Fatalf("esperaba 3 migradas limpias: %+v", r)
	}

	supr, err := baseline.Load(repo)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range vivos[:3] {
		if !supr[f.Fingerprint] {
			t.Errorf("%s: su v2 no quedó en la baseline renovada", f.RuleKey)
		}
	}
	// EL PUNTO del fixture: el hallazgo nuevo NO entró por ningún camino.
	if supr[vivos[3].Fingerprint] || supr[vivos[3].LegacyFingerprint] {
		t.Error("el hallazgo NUEVO entró a la baseline durante la renovación: eso es re-admisión encubierta")
	}
}

func TestRenovarConservaElCasoNueveYRetiraLoMuerto(t *testing.T) {
	repo := t.TempDir()

	// Dos ocurrencias que COLAPSAN en v1 (misma regla, mismo archivo, mismo
	// texto — el caso #9 literal) y una entrada de deuda que ya no existe.
	vivos := []finding.Finding{
		vivo(t, "ts-innerhtml-var", "main.js", "el.innerHTML = esc(a);", 4),
		vivo(t, "ts-innerhtml-var", "main.js", "el.innerHTML = esc(a);", 9),
	}
	finding.AsignarHuellas(vivos, nil)
	if vivos[0].LegacyFingerprint != vivos[1].LegacyFingerprint {
		t.Fatal("el fixture debe colapsar en v1: es el caso que se está probando")
	}

	muerta := vivo(t, "regla-muerta", "viejo.go", "ya no está", 1)
	muerta.ComputeFingerprint() // la v1 que la baseline vieja tiene escrita

	escribirBaseline(t, repo,
		vivos[0].LegacyFingerprint+"  # ts-innerhtml-var main.js (colapsada, 2 ocurrencias)",
		muerta.Fingerprint+"  # regla-muerta viejo.go:1",
	)

	r, err := baseline.Renovar(repo, vivos)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Conservadas) != 1 {
		t.Errorf("el caso #9 (2 candidatos) exige decisión humana y se conserva como v1: %+v", r)
	}
	if len(r.Desaparecidas) != 1 {
		t.Errorf("la deuda muerta se retira con aviso: %+v", r)
	}
	raw, err := os.ReadFile(filepath.Join(repo, filepath.FromSlash(baseline.RelPath)))
	if err != nil {
		t.Fatal(err)
	}
	texto := string(raw)
	if !strings.Contains(texto, vivos[0].LegacyFingerprint) {
		t.Error("la entrada del caso #9 desapareció: debía CONSERVARSE (sigue supriendo hasta que el humano decida)")
	}
	if strings.Contains(texto, muerta.Fingerprint) {
		t.Error("la entrada muerta sobrevivió a la renovación")
	}
	// Y el comentario humano de la conservada sobrevive tal cual.
	if !strings.Contains(texto, "(colapsada, 2 ocurrencias)") {
		t.Error("el comentario humano de la entrada conservada se perdió")
	}
}
