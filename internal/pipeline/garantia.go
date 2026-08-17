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
// POR QUÉ ESTA LISTA Y NO «CUALQUIER DEGRADACIÓN». Romper el job por cualquier
// cosa que ponga algo en Degraded pondría en rojo a repos que hoy funcionan
// bien, y un CI que se pone rojo por motivos que el equipo no puede arreglar se
// desactiva entero en una semana. La frontera es: ¿había algo que mirar y no se
// miró?
//
//	rulepack-ausente:…  SÍ — las reglas de la casa no se aplicaron, ninguna
//	falta:<motor>       SÍ — el motor no está en el runner; esa capa no corrió
//	<motor>:error       SÍ — tenía que correr, falló
//	<motor>:plazo       SÍ — no terminó; no miró todo lo que tenía que mirar
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
		if strings.HasPrefix(d, "rulepack-ausente:") ||
			strings.HasPrefix(d, "falta:") ||
			strings.HasSuffix(d, ":error") ||
			strings.HasSuffix(d, ":plazo") {
			rotas = append(rotas, d)
		}
	}
	return rotas
}

// esPoliticaDeliberada nombra una por una las degradaciones que el producto
// PRODUCE A PROPÓSITO. Se comprueban antes que los sufijos genéricos: si mañana
// alguien inventa una etiqueta deliberada que acabe en ":error", esta lista
// manda y el job no se rompe por una decisión de diseño.
func esPoliticaDeliberada(d string) bool {
	switch d {
	case "deterministic:diff_too_large",
		"daemon:offline",
		"squawk:migracion-sin-vigilar":
		return true
	}
	return false
}
