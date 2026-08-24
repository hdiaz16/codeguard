package pipeline

import "strings"

// SinGarantia separa, de la lista de capas degradadas, las que significan
// «esta compuerta NO MIRÓ» de las que son política deliberada del producto.
//
// EL AGUJERO QUE CIERRA, medido y no razonado. Se montó un repo con una
// inyección SQL de libro —`db.Query("SELECT * FROM users WHERE id=" + id)`, que
// caza la regla `go-sql-concat` del rulepack— y se corrió `codeguard ci` dos
// veces sobre el MISMO código:
//
//	rulepack instalado  → BLOQUEADO, 2 hallazgos, exit 1
//	rulepack ausente    → "OK — 0 bloqueantes", exit 0
//	                      + una línea "capas degradadas: rulepack-ausente:…"
//
// El mismo `main.go`, la misma línea 9. Lo único que cambió es que el
// `rulepack:` del config apuntaba a una versión que ese runner no tenía. Y no
// hace falta mala fe: basta un typo, o un repo pinneado a una versión de
// rulepack que el runner todavía no ha instalado. El fallback junto al binario
// tampoco salva —sólo acierta si el pin coincide EXACTAMENTE con lo instalado—.
//
// Un CI mira el código de salida. La línea de texto no la lee nadie. Así que la
// inyección entraba a main con el job en verde.
//
// Y es la paridad al revés: el gancho local es fail-closed para los secretos, y
// el CI —que es donde vive la garantía— era fail-open para todo lo demás. La
// promesa del producto es «si pasa aquí, pasa allá»; sin esto era «si pasa
// aquí, quizá allá ni miraron».
//
// LISTA NEGRA Y NO LISTA BLANCA, y esto es un cambio. Antes se rompía el job
// sólo si la etiqueta casaba con cuatro patrones conocidos —«rulepack-ausente:»,
// «falta:», «:error», «:plazo»— y TODO lo demás se descartaba en silencio. Eso
// deja el default abierto: una degradación nueva que signifique «no se miró»
// entra por el mismo agujero que este archivo existe para cerrar, con el job en
// verde, y nadie se enteraría hasta repetir la medición de arriba. Así que el
// criterio se invierte: lo degradado rompe el job, y la ÚNICA exención es estar
// nombrada abajo. El desconocido cierra, no calla.
//
// El coste es real y deliberado: quien añada una degradación benigna verá el job
// en rojo hasta registrarla. Ese rojo es la señal de que hay una etiqueta sin
// clasificar — no una avería. Y la frontera para clasificarla sigue siendo la
// misma: ¿había algo que mirar y no se miró?
//
// INVENTARIO de todo lo que hoy llega a Degraded (medido recorriendo los
// emisores, no supuesto: pipeline.go 140/259/306/308/318/324/340 y daemon.go
// 455/533/563):
//
//	rulepack-ausente:…  SÍ — las reglas de la casa no se aplicaron, ninguna
//	falta:<motor>       SÍ — el motor no está en el runner; esa capa no corrió
//	<motor>:error       SÍ — tenía que correr, falló
//	<motor>:plazo       SÍ — no terminó; no miró todo lo que tenía que mirar
//	config:unreadable   SÍ — y ANTES NO ROMPÍA. El config del repo no se pudo
//	                    leer, así que el análisis corrió con el de por defecto:
//	                    los motores que ese repo configuraba pueden no haber
//	                    corrido. Es «no se miró» de manual.
//	pipeline:<err>      SÍ — y ANTES TAMPOCO. El análisis falló entero; no hay
//	                    nada que garantizar.
//	worktree: <files>…  SÍ — el archivo cambió DURANTE el análisis (bug #8, la
//	                    mitad que el caché no cubre): lo analizado ya no es lo
//	                    que se va a commitear. No hay exención posible sin
//	                    reabrir la carrera.
//	config-ejecutable-no-confiada:<motor>  SÍ (W4, Q3) — el motor ejecuta
//	                    config o binarios del repo (eslint.config.js, target
//	                    MSBuild, plugin de mypy) y el usuario no ha confiado en
//	                    ellos, así que NO corrió: esa capa no miró. Se cierra
//	                    con `codeguard confiar` una vez por repo. El default es
//	                    seguro a propósito: ejecutar código no confiado del repo
//	                    es el hueco (probado: toca fuera del árbol).
//	<motor>:cobertura-parcial  SÍ (W6, Q2) — el motor declaró un plan de
//	                    objetivos y no cubrió todos (parser parcial, timeout de
//	                    un objetivo, unidad prometida sin recibo). Corrió y sus
//	                    hallazgos valen, pero lo NO analizado no está limpio: el
//	                    «sin hallazgos» de esa unidad no cubre lo que no se miró.
//	                    Se cierra excluyendo el objetivo a propósito (omisión
//	                    declarada) o arreglando lo que no se pudo analizar.
//
//	deterministic:diff_too_large   NO — política deliberada y ANUNCIADA: el diff
//	                               pasó del tope y se revisan sólo secretos. Es
//	                               una decisión del producto, no una avería.
//	daemon:offline                 NO — sólo existe en el camino del gancho, y
//	                               allí el análisis corre igual en local.
//	squawk:migracion-sin-vigilar   NO — es un aviso de CONFIGURACIÓN del repo
//	                               (hay migraciones fuera de paths.migrations).
//	                               Romper el job por esto contradice la decisión
//	                               de N011: avisar, nunca decidir por el equipo.
//	patron-invalido:<p>            NO — un patrón de exclusión que no compila
//	                               hace que esa ruta NO se excluya (pipeline.go
//	                               136: «el equipo cree que esa ruta está
//	                               excluida y no lo está»), o sea que se analiza
//	                               MÁS de lo previsto. El error va hacia el lado
//	                               seguro y la etiqueta existe para que el typo
//	                               se vea, no para frenar el job.
//	demoted:unavailable            NO — no se pudieron leer las reglas que BAJAN
//	                               severidad, así que los hallazgos salen con la
//	                               suya original: más estricto, no menos. No hay
//	                               agujero de cobertura que garantizar.
//
// La escotilla para quien necesite otra cosa ya existe y no hay que inventar
// ninguna: `codeguard ci --shadow` registra todo y jamás falla el job.
//
// Vive aquí y no en cmd/ para que no acaben existiendo dos criterios: el que
// aplica el CI y el que aplica cualquier superficie que se añada mañana.
func SinGarantia(degraded []string) []string {
	var rotas []string
	for _, d := range degraded {
		if esPoliticaDeliberada(d) {
			continue
		}
		// Todo lo que no sea exención registrada es garantía rota. Una etiqueta
		// desconocida no se descarta nunca en silencio.
		rotas = append(rotas, d)
	}
	return rotas
}

// esPoliticaDeliberada nombra una por una las degradaciones que NO significan
// «no se miró»: las que el producto produce a propósito y las que se equivocan
// hacia el lado seguro. Es la ÚNICA exención, así que quien añada una
// degradación nueva tiene que pasar por aquí y decidir a conciencia de qué lado
// cae — o el job se romperá, que es el default correcto.
//
// Sigue comprobándose antes que nada: si mañana una etiqueta deliberada acaba en
// ":error", esta lista manda y el job no se rompe por una decisión de diseño.
func esPoliticaDeliberada(d string) bool {
	switch d {
	case "deterministic:diff_too_large",
		"daemon:offline",
		// daemon:incompatible es despliegue MIXTO (versiones cruzadas de hook
		// y daemon), no cobertura rota: el análisis corre entero en local,
		// igual que con el daemon apagado. El remedio es actualizar el binario
		// que quedó atrás — doctor lo detecta comparando versiones, y si
		// persiste lo escalará el contador de degradación de W6 (turno 89).
		"daemon:incompatible",
		"squawk:migracion-sin-vigilar",
		"demoted:unavailable":
		return true
	}
	// patron-invalido: lleva el patrón pegado, así que va por prefijo y no por
	// igualdad como los de arriba.
	return strings.HasPrefix(d, "patron-invalido:")
}
