package pipeline

import (
	"errors"
	"testing"
)

// LA TABLA ENTERA O NADA, como en garantia_test.go: una derivación que
// devolviera siempre Degradado pasaría los casos de degradación y arruinaría
// todos los limpios; una que devolviera siempre Limpio es la enfermedad que
// este tipo existe para curar. Cada fila es un contrato, no un ejemplo.
func TestElVeredictoSeDerivaUnaSolaVezYSinEufemismos(t *testing.T) {
	casos := []struct {
		nombre  string
		res     *Result
		falloEn FalloEn
		err     error
		estado  Estado
		bloquea bool
	}{
		{"corrió completo y no halló nada",
			&Result{Verdict: Pass}, "", nil, Limpio, false},
		{"corrió completo con avisos que no bloquean",
			&Result{Verdict: Pass, AdvisoryFindings: 3}, "", nil, ConAvisos, false},
		{"hallazgos bloqueantes",
			&Result{Verdict: Block, BlockingFindings: 2}, "", nil, Bloqueado, true},
		{"skip deliberado (merge/revert, sin diff, bypass)",
			&Result{Verdict: Skipped, Reason: MotivoMergeORevert}, "", nil, Omitido, false},

		// La frontera de Degradado es SinGarantia y SOLO SinGarantia: una
		// deliberada no degrada, una rota sí, y la mezcla gana la rota.
		{"un motor que aplicaba no está instalado: garantía rota",
			&Result{Verdict: Pass, Degraded: []string{"falta:semgrep"}}, "", nil, Degradado, false},
		{"diff demasiado grande es política anunciada, no degradación",
			&Result{Verdict: Pass, Degraded: []string{"deterministic:diff_too_large"}}, "", nil, Limpio, false},
		{"daemon apagado con avisos: ConAvisos, no Degradado",
			&Result{Verdict: Pass, AdvisoryFindings: 1, Degraded: []string{"daemon:offline"}}, "", nil, ConAvisos, false},
		{"mezcla deliberada+rota: la rota manda",
			&Result{Verdict: Pass, Degraded: []string{"daemon:offline", "trivy:error"}}, "", nil, Degradado, false},
		// El caso que el bug #8 dejó vivo a propósito: el worktree cambió
		// durante el análisis. No está en las exenciones y NO debe estarlo —
		// lo analizado ya no es lo que se commitea.
		{"worktree cambiado durante el análisis: garantía rota",
			&Result{Verdict: Pass, Degraded: []string{"worktree: app.py cambió durante el análisis — …"}}, "", nil, Degradado, false},
		// Degradado gana a ConAvisos: «hallé poco» sin haber mirado todo no
		// es un veredicto sobre el commit, es un veredicto sobre un pedazo.
		{"avisos Y garantía rota: Degradado manda sobre ConAvisos",
			&Result{Verdict: Pass, AdvisoryFindings: 4, Degraded: []string{"rulepack-ausente:2026.08.2"}}, "", nil, Degradado, false},
		// Bloqueado gana a Degradado (lo accionable primero), pero la rota
		// tiene que viajar — eso lo asegura el test del invariante de abajo.
		{"bloqueantes Y garantía rota: Bloqueado, con la rota a bordo",
			&Result{Verdict: Block, BlockingFindings: 1, Degraded: []string{"semgrep:error"}}, "", nil, Bloqueado, true},

		// Fallido no es Omitido: la mentira exacta de daemon.go:370 antes de
		// este tipo. Y la política de bloqueo va por fase, no por texto.
		{"pipeline.Run devolvió error: Fallido y el commit pasa con aviso",
			nil, FalloPipeline, errors.New("git no respondió"), Fallido, false},
		{"config ilegible: Fallido, no skipped",
			nil, FalloConfig, errors.New("yaml: line 3"), Fallido, false},
		{"el daemon murió a media respuesta: Fallido, pasa con aviso",
			nil, FalloDaemon, errors.New("pipe rota"), Fallido, false},
		{"la compuerta de secretos no pudo mirar: fail-closed (§14)",
			nil, FalloSecretos, errors.New("gitleaks no arrancó"), Fallido, true},
		{"staged set indeterminable: fail-closed (§14)",
			nil, FalloStaged, errors.New("git diff falló"), Fallido, true},
		{"fallo sin fase declarada: unknown visible, jamás precisión fingida",
			nil, "", errors.New("¿?"), Fallido, false},
		{"ni resultado ni error: bug del llamador, se dice",
			nil, "", nil, Fallido, false},
		// Un err real gana aunque el llamador haya pasado Result: sin
		// análisis completo no hay veredicto que matizar.
		{"error con Result a medias: Fallido igual",
			&Result{Verdict: Pass}, FalloPipeline, errors.New("se cayó en la etapa 7"), Fallido, false},
	}

	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			o := Finalizar(c.res, c.falloEn, c.err)
			if o.Estado != c.estado {
				t.Errorf("Estado = %q, se esperaba %q", o.Estado, c.estado)
			}
			if got := o.Bloquea(); got != c.bloquea {
				t.Errorf("Bloquea() = %v, se esperaba %v (FalloEn=%q)", got, c.bloquea, o.FalloEn)
			}
		})
	}
}

// El invariante de render del turno 67 empieza aquí: para que TODA superficie
// pueda mostrar «BLOQUEADO, y además el análisis quedó incompleto», la rota
// tiene que viajar DENTRO del outcome aunque el Estado sea Bloqueado. Si un
// refactor la poda «porque el estado ya es blocked», el dev arregla el
// bloqueante, commitea de nuevo y la compuerta rota le llega como sorpresa.
func TestLaGarantiaRotaViajaAunqueElEstadoSeaBloqueado(t *testing.T) {
	o := Finalizar(&Result{
		Verdict:          Block,
		BlockingFindings: 1,
		Degraded:         []string{"semgrep:error", "daemon:offline"},
	}, "", nil)
	if o.Estado != Bloqueado {
		t.Fatalf("Estado = %q", o.Estado)
	}
	if len(o.GarantiaRota) != 1 || o.GarantiaRota[0] != "semgrep:error" {
		t.Errorf("GarantiaRota = %v; debe traer la rota (y solo la rota) aunque el estado sea Bloqueado", o.GarantiaRota)
	}
	if len(o.Degradadas) != 2 {
		t.Errorf("Degradadas = %v; la lista cruda completa viaja para los textos de remedio", o.Degradadas)
	}
}

// Los contadores y la fase del fallo son parte del contrato, no decoración:
// el hook pinta «N bloqueantes», el panel «M suprimidos», y la política de
// flota del futuro decidirá con FalloEn. Si Finalizar deja de copiarlos, toda
// superficie miente a la vez.
func TestLosContadoresYLaFaseViajanEnElOutcome(t *testing.T) {
	o := Finalizar(&Result{
		Verdict: Block, BlockingFindings: 2, AdvisoryFindings: 5,
		Suppressed: 7, Reason: "x",
	}, "", nil)
	if o.Bloqueantes != 2 || o.Avisos != 5 || o.Suprimidos != 7 || o.Razon != "x" {
		t.Errorf("contadores perdidos: %+v", o)
	}
	f := Finalizar(nil, FalloSecretos, errors.New("boom"))
	if f.FalloEn != FalloSecretos || f.Fallo != "boom" {
		t.Errorf("la fase o el texto del fallo se perdieron: %+v", f)
	}
}

// Inmutable de verdad: el outcome se construye al final y persistencia e IPC
// reciben LA MISMA instancia (turno 67, defecto 2). Si compartiera slices con
// Result, cualquier append posterior del productor le cambiaría el pasado a
// lo ya persistido.
func TestElOutcomeNoCompartePasadoConElResult(t *testing.T) {
	res := &Result{Verdict: Pass, Degraded: []string{"falta:ruff"}}
	o := Finalizar(res, "", nil)
	res.Degraded[0] = "mutado"
	if o.Degradadas[0] != "falta:ruff" {
		t.Errorf("el outcome comparte la slice Degraded del Result: %v", o.Degradadas)
	}
	if o.GarantiaRota[0] != "falta:ruff" {
		t.Errorf("GarantiaRota compartida o mal derivada: %v", o.GarantiaRota)
	}
}
