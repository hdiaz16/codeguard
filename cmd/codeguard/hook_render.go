package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"codeguard/internal/finding"
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

// imprimirVeredictoTerminal LEE el AnalysisOutcome — nunca re-deriva (regla
// del consejo, turnos 61-68). Antes decidía con res.BlockingFindings y
// len(res.Degraded) crudos, y ese segundo criterio pintaba PARCIAL por
// daemon:offline —una política deliberada: en local el análisis corre entero—
// mientras el CI, con SinGarantia, decía OK del mismo Degraded. El mismo
// commit, dos veredictos. Ahora la frontera de PARCIAL es GarantiaRota, la
// misma en todas las superficies.
//
// Devuelve el bool que bloquea, y es outcome.Bloquea() — la política única de
// outcome.go: hallazgos bloqueantes, o un fallo fail-closed (§14: secretos,
// staged set). Con la condición escrita a los dos lados (aquí y en el exit),
// la primera que se editara distinta dejaría la terminal diciendo BLOQUEADO
// mientras el hook devolvía 0.
func imprimirVeredictoTerminal(o pipeline.AnalysisOutcome, findings []finding.Finding, start time.Time) bool {
	progress := func(s string) { fmt.Fprintf(os.Stderr, "CodeGuard  %s\n", s) }
	gates := "formato/lint/tipos/reglas/migraciones"
	bloquea := o.Bloquea()
	segs := time.Since(start).Seconds()
	switch {
	case bloquea:
		progress(gates + " ✗")
		for _, f := range findings {
			if f.Blocking {
				progress(fmt.Sprintf("  [%s] %s:%d  %s",
					f.RuleKey, f.File, f.Line, mensajeDeHallazgo(f.Message)))
			}
		}
		if o.Bloqueantes > 0 {
			progress(fmt.Sprintf("BLOQUEADO: %d problema(s) que el CI también rechazaría  (%.1f s)", o.Bloqueantes, segs))
		} else {
			progress("BLOQUEADO: " + unaSolaLinea(o.Razon) + fmt.Sprintf("  (%.1f s)", segs))
			progress("si necesitas commitear ya, `git commit --no-verify` salta la revisión — " +
				"queda constancia de que este commit no se revisó")
		}
		// El invariante de render (turno 67): la garantía rota se dice TAMBIÉN
		// bloqueado. Sin esta línea el dev arregla el bloqueante, commitea de
		// nuevo, y la compuerta que no miró le llega como sorpresa.
		if len(o.GarantiaRota) > 0 {
			progress("y además el análisis quedó incompleto — " + unaSolaLinea(strings.Join(o.GarantiaRota, ", ")))
		}
	case o.Estado == pipeline.Fallido:
		// La verdad que el "skipped" del daemon disfrazaba: no es que se
		// decidiera no correr — es que NO PUDO. La línea fuerte va siempre.
		progress(fmt.Sprintf("%s — SIN REVISAR   (%.1f s)", gates, segs))
		progress(fmt.Sprintf("el análisis FALLÓ (%s): %s", o.FalloEn, unaSolaLinea(o.Fallo)))
		progress("el commit sigue permitido, pero esto NO es una revisión limpia")
	case o.Estado == pipeline.Omitido:
		progress(fmt.Sprintf("%s — SIN REVISAR   (%.1f s)", gates, segs))
		switch {
		case pipeline.EsDecisionDelEquipo(o.Razon):
			progress("sin archivos que revisar: todos excluidos por la configuración")
		case o.Razon != "":
			progress("no se analizó nada: " + unaSolaLinea(o.Razon))
			progress("el commit sigue permitido, pero esto NO es una revisión limpia")
		default:
			progress("no se analizó nada (el motivo no llegó hasta aquí)")
			progress("el commit sigue permitido, pero esto NO es una revisión limpia")
		}
	case o.Estado == pipeline.Degradado:
		progress(fmt.Sprintf("%s — PARCIAL   (%.1f s)", gates, segs))
		if o.Avisos > 0 {
			progress(fmt.Sprintf("commit permitido sobre lo que SÍ se revisó; %d sugerencia(s) en el panel", o.Avisos))
		} else {
			progress("commit permitido sobre lo que SÍ se revisó")
		}
	default: // Limpio y ConAvisos
		progress(fmt.Sprintf("%s ✓   (%.1f s)", gates, segs))
		if o.Avisos > 0 {
			progress(fmt.Sprintf("listo — commit permitido; %d sugerencia(s) en el panel", o.Avisos))
		} else {
			progress("listo — commit permitido")
		}
	}

	if o.Estado != pipeline.Omitido && o.Estado != pipeline.Fallido {
		// La lista de capas NO revisadas es la garantía rota, no el Degraded
		// crudo: anunciar "capas no revisadas: daemon:offline" debajo de un ✓
		// era decir dos cosas contrarias en dos líneas seguidas.
		if len(o.GarantiaRota) > 0 {
			progress("capas no revisadas: " + unaSolaLinea(strings.Join(o.GarantiaRota, ", ")))
		}
		// Los remedios sí miran la lista cruda: son textos de orientación por
		// etiqueta (render, no decisión), y daemon:offline tiene el suyo
		// aunque no rompa garantía — la corrida fue en frío y eso se nota.
		for _, d := range o.Degradadas {
			if d == "daemon:offline" {
				fmt.Fprintln(os.Stderr,
					"CodeGuard  el agente no estaba corriendo, así que esta revisión fue en frío y sin\n"+
						"           caché. Arráncalo (cierra y abre sesión, o lanza codeguard-daemon) y el\n"+
						"           siguiente commit se revisa completo y en segundos.")
			}
		}
		var lentos []string
		for _, d := range o.Degradadas {
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
		for _, d := range o.Degradadas {
			if v, ok := strings.CutPrefix(d, "rulepack-ausente:"); ok {
				fmt.Fprintf(os.Stderr,
					"CodeGuard  ATENCIÓN: este repo apunta al rulepack %s y no está instalado.\n"+
						"           Las reglas de la casa NO se aplicaron: el CI puede rechazar este commit.\n"+
						"           Arréglalo con `codeguard repair` o vendorea el rulepack en el repo.\n",
					unaSolaLinea(v))
			}
		}
		// Config-ejecutable no confiada (W4, Q3): el remedio es una acción del
		// usuario (confiar), así que se dice con su comando exacto — no es ruido
		// de máquina como el aislamiento, es una decisión pendiente.
		var motoresSinConfiar []string
		for _, d := range o.GarantiaRota {
			if m, ok := strings.CutPrefix(d, "config-ejecutable-no-confiada:"); ok {
				motoresSinConfiar = append(motoresSinConfiar, m)
			}
		}
		if len(motoresSinConfiar) > 0 {
			fmt.Fprintf(os.Stderr,
				"CodeGuard  %s NO corrió: este repo trae configuración ejecutable (o un binario\n"+
					"           propio) y aún no confías en ella. Un repo hostil podría esconder código\n"+
					"           ahí que toque tu máquina. Si reconoces este repo: `codeguard confiar`.\n",
				unaSolaLinea(strings.Join(motoresSinConfiar, ", ")))
		}
		// El aislamiento degradado (W4, t.116) se dice UNA vez por día, no por
		// commit: es un hecho de la MÁQUINA (Windows Home sin tokens, política
		// de IT), y repetirlo en cada commit enseña a ignorar el naranja —
		// condición de Kimi (t.110). El detalle vive en `codeguard engines`.
		if len(o.AislamientoDegradado) > 0 && avisoAislamientoTocaHoy() {
			fmt.Fprintf(os.Stderr,
				"CodeGuard  aviso (una vez al día): los motores corren con MENOS contención de la\n"+
					"           diseñada — falta: %s. El análisis vale igual; la armadura no está\n"+
					"           completa. Detalle y remedio: `codeguard engines`.\n",
				unaSolaLinea(strings.Join(o.AislamientoDegradado, ", ")))
		}
	}
	return bloquea
}

// avisoAislamientoTocaHoy dice si el aviso de contención aún no salió hoy, y
// lo apunta. Best-effort a los dos lados: sin LOCALAPPDATA (o sin poder
// escribir) el aviso SALE — ante la duda se dice, jamás se calla; y el error
// de escritura solo significa que mañana... saldrá otra vez.
func avisoAislamientoTocaHoy() bool {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		return true
	}
	marca := filepath.Join(base, "codeguard", "aviso-aislamiento.txt")
	hoy := time.Now().Format("2006-01-02")
	if raw, err := os.ReadFile(marca); err == nil && strings.TrimSpace(string(raw)) == hoy {
		return false
	}
	_ = os.MkdirAll(filepath.Dir(marca), 0o755)
	_ = os.WriteFile(marca, []byte(hoy+"\n"), 0o644)
	return true
}
