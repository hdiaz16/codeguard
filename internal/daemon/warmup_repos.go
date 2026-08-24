package daemon

import "context"

// WarmAll precalienta lo que compite con el presupuesto del hook. Corre en el
// arranque del daemon; nunca está en el camino de ningún commit.
//
// AQUÍ VIVIÓ el precalentamiento de tsc por repo (spike S5), y murió en W4
// (consejo t.110/115, unánime) por tener todo el riesgo y ningún beneficio:
// ejecutaba `npx --no-install tsc` con cwd DENTRO de cada repo recordado, en
// cada arranque del daemon, sin usuario delante y sin pasar por proc.Correr
// (sin token restringido, sin job object) — y su propia medición admitía que
// NO calentaba nada: npx resuelve por nombre de PAQUETE (`typescript`, no
// `tsc`) y cancelaba con «missing packages» sin ejecutar el compilador.
// Recuperar el calentamiento exigiría volver a ejecutar un binario que el
// repo controla; si algún día se quiere, el diseño pasa por el consejo con
// esa superficie dicha. Con él murió la lista warm-repos.txt (RememberRepo/
// podarWarmList): no le quedaba ningún consumidor.
func WarmAll(ctx context.Context) {
	// Semgrep primero: es la capa que compite con el presupuesto del hook.
	// La DB de trivy puede tardar minutos y no bloquea a nadie.
	WarmSemgrep(ctx)
	WarmTrivyDB(ctx)
}
