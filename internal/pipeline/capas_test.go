package pipeline

import (
	"context"
	"errors"
	"io/fs"
	"slices"
	"strings"
	"testing"

	"codeguard/internal/capas"
	"codeguard/internal/config"
	"codeguard/internal/engines"
	"codeguard/internal/finding"
	"codeguard/internal/gitdiff"
)

// motorControlado permite fijar las tres cosas que deciden el estado de una
// capa: si aplica, qué devuelve y con qué error.
type motorControlado struct {
	nombre    string
	aplica    bool
	hallazgos []finding.Finding
	err       error
}

func (m *motorControlado) Name() string               { return m.nombre }
func (m *motorControlado) Applies(engines.Input) bool { return m.aplica }
func (m *motorControlado) Run(context.Context, engines.Input) ([]finding.Finding, error) {
	return m.hallazgos, m.err
}

// El panel tiene que poder decirle al dev qué motores miraron su código y qué
// motores no. Hasta ahora el Result sólo llevaba los que FALLARON (Degraded),
// así que "corrió y no encontró nada" y "no corrió" llegaban a la UI
// exactamente iguales: indistinguibles.
//
// Es el mismo error que este producto existe para no cometer, cometido en la
// superficie que se lo cuenta al usuario.
func TestElResultadoDiceMotorPorMotorSiMiroONo(t *testing.T) {
	motores := []engines.Engine{
		&motorControlado{nombre: "conhallazgos", aplica: true,
			hallazgos: []finding.Finding{mk("r1", "a.go", 1, false)}},
		&motorControlado{nombre: "limpio", aplica: true},
		&motorControlado{nombre: "noaplica", aplica: false},
		&motorControlado{nombre: "ausente", aplica: true, err: fs.ErrNotExist},
		&motorControlado{nombre: "roto", aplica: true, err: errors.New("explotó")},
	}

	res := correrConMotores(t, motores)

	porMotor := map[string]capas.Capa{}
	for _, c := range res.Capas {
		if _, repetido := porMotor[c.Motor]; repetido {
			t.Errorf("%s aparece dos veces en Capas", c.Motor)
		}
		porMotor[c.Motor] = c
	}

	// Ningún motor puede faltar. Si la UI enumera esta lista para decir "esto
	// te vigila", una capa ausente de la lista es una capa que el dev cree que
	// no existe.
	if len(porMotor) != len(motores) {
		t.Fatalf("Capas tiene %d entradas y había %d motores: %+v",
			len(porMotor), len(motores), res.Capas)
	}

	for _, c := range []struct {
		motor, estado string
		hallazgos     int
	}{
		{"conhallazgos", capas.Corrio, 1},
		{"limpio", capas.Corrio, 0}, // ← el caso que antes no se podía distinguir
		{"noaplica", capas.NoAplica, 0},
		{"ausente", capas.Ausente, 0},
		{"roto", capas.Degradada, 0},
	} {
		got := porMotor[c.motor]
		if got.Estado != c.estado {
			t.Errorf("%s: estado %q, esperaba %q", c.motor, got.Estado, c.estado)
		}
		if got.Hallazgos != c.hallazgos {
			t.Errorf("%s: %d hallazgos, esperaba %d", c.motor, got.Hallazgos, c.hallazgos)
		}
	}

	// "Corrió y no encontró nada" tiene que ser DISTINTO de "no aplicó". Es la
	// única aserción de este test que no se puede satisfacer por accidente.
	if porMotor["limpio"].Estado == porMotor["noaplica"].Estado {
		t.Error("un motor que revisó sin encontrar nada y uno que no revisó " +
			"llegan al panel con el mismo estado: el dev no puede saber qué se miró")
	}
}

// Capas y Degraded cuentan la misma historia y no pueden contradecirse: el
// veredicto en texto sale de Degraded y la UI de Capas.
func TestCapasYDegradedNoSeContradicen(t *testing.T) {
	res := correrConMotores(t, []engines.Engine{
		&motorControlado{nombre: "ausente", aplica: true, err: fs.ErrNotExist},
		&motorControlado{nombre: "bueno", aplica: true},
	})

	// Toda capa caída tiene que aparecer también en Degraded, que es de donde
	// sale el texto del veredicto. Una capa marcada como caída en la UI y
	// ausente del veredicto es el panel y la terminal diciendo cosas distintas
	// del mismo commit.
	//
	// Se comprueba en esta dirección y no con un conteo igual porque Degraded
	// lleva además etiquetas que no son motores (`deterministic:diff_too_large`,
	// `squawk:migracion-sin-vigilar`, y el `daemon:offline` que añade el hook).
	caidas := 0
	for _, c := range res.Capas {
		if c.Estado != capas.Degradada && c.Estado != capas.Ausente {
			continue
		}
		caidas++
		if !slices.ContainsFunc(res.Degraded, func(d string) bool {
			return strings.Contains(d, c.Motor)
		}) {
			t.Errorf("la capa %s está caída (%s) y el veredicto no la nombra: %v",
				c.Motor, c.Estado, res.Degraded)
		}
		if c.Detalle == "" {
			t.Errorf("%s cayó sin explicar por qué: el dev no puede actuar sobre eso", c.Motor)
		}
	}
	if caidas != 1 {
		t.Errorf("esperaba exactamente una capa caída, hubo %d: %+v", caidas, res.Capas)
	}
}

func correrConMotores(t *testing.T, motores []engines.Engine) *Result {
	t.Helper()
	res, err := Run(context.Background(), Options{
		Config: &config.Config{Rulepack: "test", RepoRoot: t.TempDir(), MaxDiffLines: 2000},
		Diff: &gitdiff.Diff{
			Files: []gitdiff.ChangedFile{{Path: "a.go", Status: "M"}},
			Lines: 1,
		},
		Engines: motores,
	})
	if err != nil {
		t.Fatalf("no esperaba error: %v", err)
	}
	return res
}
