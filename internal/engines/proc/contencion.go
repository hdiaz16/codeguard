package proc

import (
	"context"
	"sync"
)

// Contencion reporta QUÉ capas del sandbox se activaron DE VERDAD para un
// hijo (W4, consejo t.107-116). Hasta 2026-08-23 el fallo del job object se
// descartaba en un `if err == nil` sin else (ni log), y con él se perdía en
// silencio el matarile del árbol por plazo; el del token dejaba una línea de
// log que ningún veredicto veía. La filosofía se mantiene —correr sin
// aislamiento es mejor que no correr, porque la contención es defensa en
// profundidad y no la frontera— pero correr SIN DECIRLO era el bug: esta
// estructura es el decirlo.
type Contencion struct {
	// TokenRestringido: el hijo corrió sin privilegios (contener_windows).
	TokenRestringido bool
	// Job: el árbol de procesos quedó dentro de un job object con límites
	// (memoria, procesos, KILL_ON_JOB_CLOSE).
	Job bool
	// MatarileArbol: al vencer el plazo muere el árbol ENTERO. Exige Job: sin
	// él, el Cancel de CommandContext mata solo la raíz y los nietos
	// sobreviven huérfanos — cambia el riesgo, no solo la limpieza.
	MatarileArbol bool
	// LimitesUI: las 8 restricciones de interfaz (portapapeles, escritorio,
	// ventanas ajenas) se aplicaron.
	LimitesUI bool
	// Detalle explica la PRIMERA capa caída (diagnóstico para el log y
	// `codeguard engines`); vacío cuando todo se activó.
	Detalle string
}

// Completa dice si todas las capas se activaron.
func (c Contencion) Completa() bool {
	return c.TokenRestringido && c.Job && c.MatarileArbol && c.LimitesUI
}

// Degradadas lista las facetas caídas en el vocabulario que viaja al
// veredicto y a la BD. El orden es fijo para que dos corridas iguales
// produzcan el mismo texto.
func (c Contencion) Degradadas() []string {
	var out []string
	if !c.TokenRestringido {
		out = append(out, "token-restringido")
	}
	if !c.Job {
		out = append(out, "job")
	}
	if !c.MatarileArbol {
		out = append(out, "matarile-arbol")
	}
	if !c.LimitesUI {
		out = append(out, "limites-ui")
	}
	return out
}

// Recolector junta los reportes de todos los hijos que un motor lance en una
// corrida. Una faceta queda caída si cayó en CUALQUIER hijo: el veredicto
// habla del peor caso, no del promedio.
type Recolector struct {
	mu   sync.Mutex
	hubo bool
	peor Contencion
}

// Anotar fusiona el reporte de un hijo.
func (r *Recolector) Anotar(c Contencion) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.hubo {
		r.peor, r.hubo = c, true
		return
	}
	r.peor.TokenRestringido = r.peor.TokenRestringido && c.TokenRestringido
	r.peor.Job = r.peor.Job && c.Job
	r.peor.MatarileArbol = r.peor.MatarileArbol && c.MatarileArbol
	r.peor.LimitesUI = r.peor.LimitesUI && c.LimitesUI
	if r.peor.Detalle == "" {
		r.peor.Detalle = c.Detalle
	}
}

// Resultado devuelve el peor caso y si hubo algún hijo que reportara.
func (r *Recolector) Resultado() (Contencion, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.peor, r.hubo
}

type claveRecolector struct{}

// ConRecolector instala un recolector nuevo en el contexto. El pipeline lo
// pone UNA vez por motor y Correr reporta solo: ningún adaptador tiene que
// acordarse de propagar nada (el camino que exige memoria en 36 sitios es el
// camino que diverge — misma doctrina que AsignarHuellas).
func ConRecolector(ctx context.Context) (context.Context, *Recolector) {
	r := &Recolector{}
	return context.WithValue(ctx, claveRecolector{}, r), r
}

func recolectorDe(ctx context.Context) *Recolector {
	r, _ := ctx.Value(claveRecolector{}).(*Recolector)
	return r
}
