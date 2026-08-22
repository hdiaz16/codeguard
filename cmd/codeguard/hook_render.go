package main

import (
	"fmt"
	"os"
	"strings"
	"time"
	"unicode"

	"codeguard/internal/pipeline"
)
// aplanado deja un texto de otro origen en UNA línea y sin nada que pueda
// reescribir lo ya impreso, antes de que salga junto al prefijo "CodeGuard ".
//
// Aquí llega texto que no redactamos nosotros: el motivo del análisis omitido
// lo escribe el daemon —y uno de los suyos arrastra el error de koanf, que es
// MULTILÍNEA—, el aviso de paridad lleva dentro el `rulepack` del config.yaml
// del repo, y el mensaje de un hallazgo sale del YAML de una regla, que puede
// venir del rulepack VENDOREADO en el repo analizado. Los tres son contenido
// que viaja versionado: basta clonar un repo para controlarlos.
//
// Sin aplanar, un salto en el sitio justo dibuja una línea que aparenta ser
// nuestra. Está medido: con una regla vendoreada cuyo `message` lleva dos
// saltos, la lista de hallazgos bloqueantes enseñaba
// "CodeGuard  listo — commit permitido" DEBAJO del hallazgo que estaba
// bloqueando el commit.
//
// strings.Fields se lleva por delante todo lo que unicode considera espacio, y
// eso ya cubre los separadores que parten una línea: \n, \r, \t, \v, \f, el NEL
// U+0085 y los U+2028/U+2029 de Unicode. Lo que NO cubre son los controles que
// mueven el cursor sin ser espacio —ESC y sus secuencias ANSI, el retroceso,
// NUL, BEL, DEL—: con un ESC[1A se sube una línea y se reescribe la de arriba,
// y con retrocesos se borra el prefijo "CodeGuard " y se pone otro texto. Se
// llega a la misma falsificación sin usar un solo salto de línea, así que se
// quitan por rango en vez de enumerar secuencias, que es una lista que siempre
// se queda corta.
//
// El tope va por RUNAS: cortar el slice de bytes parte el último carácter
// multibyte y deja un rombo de reemplazo.
func aplanado(s string, topeRunas int) string {
	sinControles := strings.Map(func(r rune) rune {
		// Se conservan los espacios: los aplana Fields justo debajo, y quitarlos
		// aquí pegaría dos palabras.
		if unicode.IsSpace(r) {
			return r
		}
		// IsControl cubre las dos bandas Cc de una vez: la baja (NUL..US, con
		// ESC y el retroceso dentro) y la alta (DEL..U+009F).
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	limpio := strings.Join(strings.Fields(sinControles), " ")
	if runas := []rune(limpio); len(runas) > topeRunas {
		return string(runas[:topeRunas]) + "…"
	}
	return limpio
}

// Dos topes porque son dos clases de texto, no por gusto.
const (
	// topeServicio corta los textos que ORIENTAN: el motivo de un análisis
	// omitido, el aviso de paridad. Un error de esquema puede traer el volcado
	// entero de la estructura y aquí sólo hace falta lo que sitúa el problema.
	topeServicio = 300
	// topeMensaje corta el texto de un hallazgo, que es OTRA cosa: es lo que el
	// desarrollador necesita para arreglar el código, y recortarlo a 300 le
	// quitaría justo la parte que explica qué hacer. El tope existe sólo para
	// que un YAML absurdo no vuelque un megabyte en la terminal; ninguna regla
	// real de las 119 del rulepack se acerca (la más larga anda por 180).
	topeMensaje = 2000
)

// unaSolaLinea es el aplanado de los textos de servicio.
func unaSolaLinea(s string) string { return aplanado(s, topeServicio) }

// mensajeDeHallazgo aplana el texto de un hallazgo conservándolo entero.
//
// Se aplica al MENSAJE y no a la línea ya formateada a propósito: la sangría de
// dos espacios con la que se listan los hallazgos es del formato, no del texto
// ajeno, y aplanar después se la comería. Primero se sanea lo que viene de
// fuera, después se coloca en su sitio.
func mensajeDeHallazgo(s string) string { return aplanado(s, topeMensaje) }


func imprimirVeredictoTerminal(res *pipeline.Result, start time.Time) bool {
	progress := func(s string) { fmt.Fprintf(os.Stderr, "CodeGuard  %s\n", s) }
	gates := "formato/lint/tipos/reglas/migraciones"
	bloquea := res.BlockingFindings > 0 || res.Verdict == pipeline.Block
	if bloquea {
		progress(gates + " ✗")
		for _, f := range res.Findings {
			if f.Blocking {
				progress(fmt.Sprintf("  [%s] %s:%d  %s",
					f.RuleKey, f.File, f.Line, mensajeDeHallazgo(f.Message)))
			}
		}
		if res.BlockingFindings > 0 {
			progress(fmt.Sprintf("BLOQUEADO: %d problema(s) que el CI también rechazaría  (%.1f s)",
				res.BlockingFindings, time.Since(start).Seconds()))
		} else {
			progress("BLOQUEADO: " + unaSolaLinea(res.Reason) +
				fmt.Sprintf("  (%.1f s)", time.Since(start).Seconds()))
			progress("si necesitas commitear ya, `git commit --no-verify` salta la revisión — " +
				"queda constancia de que este commit no se revisó")
		}
	} else if res.Verdict == pipeline.Skipped {
		progress(fmt.Sprintf("%s — SIN REVISAR   (%.1f s)", gates, time.Since(start).Seconds()))
		switch {
		case pipeline.EsDecisionDelEquipo(res.Reason):
			progress("sin archivos que revisar: todos excluidos por la configuración")
		case res.Reason != "":
			progress("no se analizó nada: " + unaSolaLinea(res.Reason))
			progress("el commit sigue permitido, pero esto NO es una revisión limpia")
		default:
			progress("no se analizó nada (el motivo no llegó hasta aquí)")
			progress("el commit sigue permitido, pero esto NO es una revisión limpia")
		}
	} else if len(res.Degraded) > 0 {
		progress(fmt.Sprintf("%s — PARCIAL   (%.1f s)", gates, time.Since(start).Seconds()))
		if res.AdvisoryFindings > 0 {
			progress(fmt.Sprintf("commit permitido sobre lo que SÍ se revisó; %d sugerencia(s) en el panel", res.AdvisoryFindings))
		} else {
			progress("commit permitido sobre lo que SÍ se revisó")
		}
	} else {
		progress(fmt.Sprintf("%s ✓   (%.1f s)", gates, time.Since(start).Seconds()))
		if res.AdvisoryFindings > 0 {
			progress(fmt.Sprintf("listo — commit permitido; %d sugerencia(s) en el panel", res.AdvisoryFindings))
		} else {
			progress("listo — commit permitido")
		}
	}

	if len(res.Degraded) > 0 && res.Verdict != pipeline.Skipped {
		progress("capas no revisadas: " + unaSolaLinea(strings.Join(res.Degraded, ", ")))
		for _, d := range res.Degraded {
			if d == "daemon:offline" {
				fmt.Fprintln(os.Stderr,
					"CodeGuard  el agente no estaba corriendo, así que esta revisión fue en frío y sin\n"+
						"           caché. Arráncalo (cierra y abre sesión, o lanza codeguard-daemon) y el\n"+
						"           siguiente commit se revisa completo y en segundos.")
			}
		}
		var lentos []string
		for _, d := range res.Degraded {
			if m, ok := strings.CutSuffix(d, ":plazo"); ok {
				lentos = append(lentos, m)
			}
		}
		if len(lentos) > 0 {
			fmt.Fprintf(os.Stderr,
				"CodeGuard  %s no cabía(n) en el plazo de esta corrida (la primera es la cara:\n"+
					"           compilar o arrancar node). El caché ya quedó tibio; el próximo commit\n"+
					"           sí los revisa. El CI los aplica igual, así que nada se cuela.\n",
				strings.Join(lentos, " y "))
		}
		for _, d := range res.Degraded {
			if v, ok := strings.CutPrefix(d, "rulepack-ausente:"); ok {
				fmt.Fprintf(os.Stderr,
					"CodeGuard  ATENCIÓN: este repo apunta al rulepack %s y no está instalado.\n"+
						"           Las reglas de la casa NO se aplicaron: el CI puede rechazar este commit.\n"+
						"           Arréglalo con `codeguard repair` o vendorea el rulepack en el repo.\n",
					unaSolaLinea(v))
			}
		}
	}
	return bloquea
}
