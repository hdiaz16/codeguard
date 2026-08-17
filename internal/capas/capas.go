// Package capas describe, motor por motor, si una capa del análisis miró el
// código y con qué resultado.
//
// Existe como paquete propio y no dentro del pipeline porque el mismo dato lo
// producen unos y lo consumen otros: lo calcula `internal/pipeline`, viaja por
// `internal/ipc`, lo pinta la cabecera del panel y lo guarda `internal/store`
// para el historial. Meter el tipo en cualquiera de ellos obligaría a los demás
// a importar ese, y el transporte y la persistencia no tienen por qué depender
// del orquestador.
//
// El motivo de que exista el dato es más importante que dónde vive: hasta ahora
// el resultado sólo nombraba los motores que FALLARON, así que "corrió y no
// encontró nada" y "no corrió" llegaban a la UI idénticos — el mismo silencio
// que este producto existe para no producir, en la superficie que se lo cuenta
// al desarrollador.
package capas

// Capa es el estado de un motor en UN análisis.
type Capa struct {
	Motor     string `json:"motor"`
	Estado    string `json:"estado"`
	Hallazgos int    `json:"hallazgos"`
	Ms        int64  `json:"ms"`
	// Detalle explica un estado que no se explica solo: por qué no aplicó, o
	// qué le pasó. Vacío cuando el estado ya lo dice todo.
	Detalle string `json:"detalle,omitempty"`
}

const (
	Corrio    = "corrio"    // miró; Hallazgos dice qué encontró, cero incluido
	NoAplica  = "no-aplica" // no había nada de su tipo en el cambio
	Degradada = "degradada" // tenía que mirar y no pudo
	Ausente   = "ausente"   // no está instalado: configuración, no avería
)

// Cayo distingue las capas que dejaron un hueco real en la revisión de las que
// simplemente no tenían nada que hacer. Se pregunta en varios sitios y conviene
// que la respuesta sea una sola.
func (c Capa) Cayo() bool { return c.Estado == Degradada || c.Estado == Ausente }
