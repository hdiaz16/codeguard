package finding

import "strings"

// huellaCorta abrevia una huella para enseñarla en el mensaje de un test: n
// bytes DEL CUERPO hex, conservando el prefijo de versión si lo hay. Cortar
// el token completo gastaría el presupuesto visible en "v2:" y enseñaría
// menos entropía (condición del turno 76). Guarda de longitud para evitar
// panics.
//
// Vivió exportada en finding.go, con la promesa de "abreviar una huella para
// mostrarla". Nunca la llamó nadie de producción —ni el panel, ni el CLI, ni
// el reporte—: sus únicos consumidores son los mensajes de fallo de este
// paquete. En la limpieza de 2026-08-25 bajó aquí, que es donde se usa. Si
// algún día la interfaz necesita abreviar huellas, se exporta entonces y con
// un consumidor real detrás.
func huellaCorta(h string, n int) string {
	if n <= 0 {
		return ""
	}
	prefijo := ""
	if resto, con := strings.CutPrefix(h, PrefijoV2); con {
		prefijo, h = PrefijoV2, resto
	}
	if len(h) <= n {
		return prefijo + h
	}
	return prefijo + h[:n]
}
