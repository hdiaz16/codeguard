package pipeline

import "codeguard/internal/capas"

// Este archivo es EL veredicto. Todo él, y solo él.
//
// Lo que había antes, medido superficie por superficie (bitácora 2026-08-22 y
// turno 61 del consejo): cinco vocabularios de veredicto que no se hablaban
// entre sí. El tipado (`pass|block|skipped`) no sabía decir «falló» ni
// «degradado»; la BD sintetizaba un cuarto valor "degraded" al guardar que
// ningún lector entendía (el panel lo pintaba «pasó», el resumen semanal lo
// contaba como «sin nada»); el orbe derivaba el suyo con SoloFaltantes; el
// hook decidía PARCIAL con len(Degraded)>0 crudo; y el daemon convertía un
// error de pipeline.Run en "skipped" — «no pude correr» disfrazado de «decidí
// no correr». El mismo commit podía salir OK en CI, PARCIAL en el hook,
// piedra en el orbe y "degraded" en una BD que nadie sabía leer.
//
// La regla que cierra eso, firmada por el consejo (turnos 61-68): la
// derivación se hace UNA vez, aquí, en el productor; las superficies SOLO
// LEEN. Un consumidor que vuelva a decidir con len(Degraded), con SinGarantia
// o comparando strings de Verdict está reabriendo la enfermedad con mejor
// pintura — hay un mutante nocturno vigilando exactamente eso.

// Estado es el veredicto único del análisis: qué pasó, sin eufemismos.
// Los valores son los que viajan por el cable y se persisten en runs.outcome;
// las constantes llevan el nombre en el idioma de la casa.
type Estado string

const (
	// Limpio: corrió completo, garantía intacta, cero hallazgos.
	Limpio Estado = "clean"
	// ConAvisos: corrió completo, hallazgos que no bloquean.
	ConAvisos Estado = "findings"
	// Bloqueado: hallazgos bloqueantes (o un secreto en la etapa 1).
	Bloqueado Estado = "blocked"
	// Degradado: corrió, pero la garantía está rota — hubo algo que mirar
	// y no se miró (el criterio es SinGarantia, y es el ÚNICO criterio).
	Degradado Estado = "degraded"
	// Fallido: NO pudo correr. No es Omitido: nadie decidió saltárselo.
	// Antes de este tipo, el daemon lo despachaba como "skipped".
	Fallido Estado = "failed"
	// Omitido: se DECIDIÓ no correr (bypass, sin diff, merge/revert, repo
	// no enrolado). La Razon dice cuál de ellas.
	Omitido Estado = "skipped"
)

// FalloEn dice en qué fase murió un análisis Fallido, y existe porque la
// política de bloqueo depende de la fase, no del texto del error (veto de GPT
// en el turno 67: un `Fallo string` libre no alcanza para decidir). Los
// textos quedan para humanos; las decisiones se toman con esto.
type FalloEn string

const (
	FalloConfig   FalloEn = "config"   // el config del repo no se pudo leer
	FalloSecretos FalloEn = "secrets"  // la compuerta de secretos no pudo mirar
	FalloStaged   FalloEn = "staged"   // no se pudo determinar QUÉ se commitea
	FalloPipeline FalloEn = "pipeline" // pipeline.Run devolvió error
	FalloDaemon   FalloEn = "daemon"   // el daemon murió a media respuesta
	// FalloDesconocido es el default fail-visible: un llamador que declara
	// fallo sin decir la fase no gana precisión que no tiene.
	FalloDesconocido FalloEn = "unknown"
)

// AnalysisOutcome es la instancia inmutable que consumen TODAS las
// superficies: hook, CI, orbe, panel, BD y el sync al central reciben esta
// misma struct — nunca recalculan sus campos desde Result. Se construye al
// final (Finalizar) y las slices se copian al entrar: mutar el Result después
// no la cambia.
type AnalysisOutcome struct {
	Estado      Estado `json:"estado"`
	Bloqueantes int    `json:"bloqueantes"`
	Avisos      int    `json:"avisos"`
	Suprimidos  int    `json:"suprimidos"`
	// GarantiaRota es SinGarantia(Degradadas), ya derivado: las capas que
	// significan «no se miró». Viaja resuelto para que ningún consumidor
	// vuelva a llamar al criterio por su cuenta.
	GarantiaRota []string `json:"garantia_rota,omitempty"`
	// Degradadas es la lista cruda completa (rotas + deliberadas), para los
	// textos de remedio («daemon apagado: arranca el panel») — render, no
	// decisión.
	Degradadas []string     `json:"degradadas,omitempty"`
	Capas      []capas.Capa `json:"capas,omitempty"`
	// AislamientoDegradado (W4, t.116): facetas del sandbox que no se
	// activaron. Canal SEPARADO de GarantiaRota a propósito y NO participa en
	// la derivación del Estado: el motor corrió y la cobertura vale — lo
	// degradado es la armadura, no la mirada. Metirlo en SinGarantia pintaría
	// de Degradado cada commit de una máquina que no puede crear tokens
	// restringidos (Windows Home, política de IT) hasta enseñar a ignorar el
	// naranja — exactamente el patrón que el plan combate.
	AislamientoDegradado []string `json:"aislamiento_degradado,omitempty"`
	// Razon acompaña a Omitido (cuál decisión fue) y a veces a Bloqueado
	// (secreto-en-etapa-1); es la Reason de Result tal cual.
	Razon string `json:"razon,omitempty"`
	// FalloEn y Fallo solo acompañan a Fallido: la fase para la política,
	// el texto para el humano.
	FalloEn FalloEn `json:"fallo_en,omitempty"`
	Fallo   string  `json:"fallo,omitempty"`
}

// Finalizar deriva el veredicto único. Es la ÚNICA función que decide un
// Estado en todo el producto, y acepta explícitamente los tres orígenes
// reales: un Result completo (err == nil), un fallo con fase declarada
// (falloEn != ""), y los fallos que ocurren ANTES de pipeline.Run — config
// ilegible en el daemon, staged set indeterminable en el hook — que no tienen
// Result que dar (defecto 1 de GPT: no todo nace de pipeline.Run).
//
// Prioridad, y por qué en este orden:
//   - Fallido gana a todo: sin análisis no hay veredicto que matizar.
//   - Omitido antes que el resto: un skip deliberado no tiene contadores.
//   - Bloqueado gana a Degradado: el hallazgo bloqueante es accionable YA,
//     y la garantía rota no lo diluye — pero viaja en GarantiaRota y toda
//     superficie está obligada a mostrar AMBOS en la misma línea (invariante
//     de render del turno 67; el golden test del hook lo fija).
//   - Degradado gana a ConAvisos/Limpio: un «no hallé nada» sin haber mirado
//     todo no es un limpio — es EXACTAMENTE la mentira medida en garantia.go
//     (la inyección SQL que entró a main con el job en verde).
func Finalizar(res *Result, falloEn FalloEn, err error) AnalysisOutcome {
	if err != nil || falloEn != "" {
		o := AnalysisOutcome{Estado: Fallido, FalloEn: falloEn}
		if o.FalloEn == "" {
			o.FalloEn = FalloDesconocido
		}
		if err != nil {
			o.Fallo = err.Error()
		}
		return o
	}
	if res == nil {
		// Ni resultado ni error es un bug del llamador; se dice, no se tapa.
		return AnalysisOutcome{
			Estado: Fallido, FalloEn: FalloDesconocido,
			Fallo: "sin resultado y sin error: el llamador no dijo qué pasó",
		}
	}
	o := AnalysisOutcome{
		Bloqueantes:          res.BlockingFindings,
		Avisos:               res.AdvisoryFindings,
		Suprimidos:           res.Suppressed,
		GarantiaRota:         SinGarantia(res.Degraded),
		Degradadas:           append([]string(nil), res.Degraded...),
		AislamientoDegradado: append([]string(nil), res.AislamientoDegradado...),
		Capas:                append([]capas.Capa(nil), res.Capas...),
		Razon:                res.Reason,
	}
	switch {
	case res.Verdict == Skipped:
		o.Estado = Omitido
	case res.Verdict == Block:
		o.Estado = Bloqueado
	case len(o.GarantiaRota) > 0:
		o.Estado = Degradado
	case res.AdvisoryFindings > 0:
		o.Estado = ConAvisos
	default:
		o.Estado = Limpio
	}
	return o
}

// Bloquea es la política de bloqueo, junto a la derivación a propósito: si
// viviera en el hook, el CI inventaría la suya y ya serían dos.
//
// NO es `Estado == Bloqueado` a secas (veto de GPT, turno 67, y es correcto):
// el producto tiene DOS fallos fail-closed de diseño (§14) — la compuerta de
// secretos (pipeline_types.go:51) y el staged set indeterminable (si no sé
// QUÉ vas a commitear, no puedo prometer nada sobre ello). Todo otro fallo
// permite el commit con aviso ruidoso: bloquear porque NUESTRA herramienta se
// averió le enseña al dev el reflejo --no-verify, y ese reflejo sobrevive a
// la avería (Kimi, turno 64). El gancho de flota para endurecer esto
// (fail-closed configurable) queda decidible gracias a FalloEn, pero es
// decisión de Héctor y no está implementado.
func (o AnalysisOutcome) Bloquea() bool {
	switch o.Estado {
	case Bloqueado:
		return true
	case Fallido:
		return o.FalloEn == FalloSecretos || o.FalloEn == FalloStaged
	}
	return false
}
