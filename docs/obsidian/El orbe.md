# El orbe 🔮

Plasma de 3 capas portado de **os-samantha** (el asistente personal de Hector, estética *Her*): resplandor que respira + núcleo que morfa como líquido + destello que pulsa, fusionados por un filtro gooey. Paleta MONTAÑA: pizarra, niebla y nieve.

| Estado | Clima | Cuándo |
|---|---|---|
| 🌫️ `idle` | Niebla serena, lenta | Sin trabajo |
| ❄️ `working` | Ventisca brillante, agitada | Analizando (2-6 s) |
| 🌿 `pass` | **Verde salvia luminoso** (15 s) | Commit aprobado y completado |
| 🪨 `blocked` | Granito ferroso **latiendo** | Commit rechazado — persiste hasta abrir el panel |
| 🏜️ `degraded` | Arenisca apagada | Alguna capa no corrió |
| 😴 `offline` | Gris hondo, casi quieto, atenuado | Sin daemon/red |

## Comportamiento

- **Clic** → abre/cierra el panel (que *florece desde el orbe* y se pliega de vuelta)
- **Susurro**: al cambiar de estado, un texto efímero aparece y se desvanece ("analizando…", "commit bloqueado")
- Fijo ante el mouse — no reacciona al cursor, solo al clic
- Los cambios de clima **se funden** (~0.8 s), nunca saltan
- Prohibido por diseño: modales, sonidos, toasts, robar el foco

## El panel

Tarjeta flotante (sistema de profundidad de 3 niveles, cero bordes):
veredicto → paridad CI → bloqueantes (acordeón, badge de pilar) → sugerencias → capas degradadas. Cada tarjeta: código señalado ±3 líneas, por qué importa, cómo arreglarlo, explicación "en palabras simples" y botones útil/falso positivo.

Relacionado: [[Flujo del commit]] · [[Capa LLM]]
