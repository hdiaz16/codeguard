package pipeline

import (
	"codeguard/internal/config"
	"codeguard/internal/gitdiff"
)

// FiltrarExcluidos deja fuera lo que el repo declaró como excluido o generado,
// igual que hace la etapa 2 antes de repartir el trabajo a los motores.
//
// Es una puerta al filtro que ya usa el análisis (filterExcluded), no una copia,
// y esa es toda su razón de existir: quien pregunta desde fuera "¿qué capas
// vigilan este repo?" tiene que aplicar EXACTAMENTE el mismo recorte que aplica
// el análisis, o prometerá capas que no correrán nunca. Medido en el propio
// codeguard: sin este filtro salían google-java-format, pmd y dotnet-format por
// unos fixtures .java y .cs que viven bajo testdata, que paths.exclude descarta
// antes de que ningún motor los vea.
//
// Vive en su propio archivo para que ampliar la superficie del paquete no
// obligue a tocar pipeline.go.
func FiltrarExcluidos(cfg *config.Config, files []gitdiff.ChangedFile) []gitdiff.ChangedFile {
	return filterExcluded(cfg, files)
}
