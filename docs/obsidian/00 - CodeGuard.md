# CodeGuard 🏔️

**Agente local de análisis de código previo al commit, con paridad de reglas hacia GitHub Actions.**

> El dev sabe, *antes de commitear*, si su cambio pasará el CI — y por qué no, si no.

## El mapa

- [[Arquitectura]] — las piezas y cómo se hablan
- [[Flujo del commit]] — qué pasa desde `git commit` hasta el verde
- [[Pilares y reglas]] — seguridad · calidad · datos
- [[El orbe]] — los estados y su significado
- [[Capa LLM]] — los dos modelos y la sombra
- [[Telemetría y calibración]] — cómo aprende el sistema
- [[Hardening]] — las reglas de seguridad del propio agente
- [[Onboarding]] — cómo se enrola un repo y un dev

📌 Abre **Mapa.canvas** para el diagrama visual completo.

## Los 7 principios (de la spec)

1. **P1** — Determinista primero, modelo después
2. **P2** — Solo lo determinista bloquea; el LLM aconseja *(no negociable)*
3. **P3** — Paridad estricta agente ↔ CI: mismo binario
4. **P4** — El hook nunca falla por sí mismo *(excepción: secretos, fail-closed)*
5. **P5** — Los secretos se escanean (y se redactan) antes de tocar la red
6. **P6** — Embudo por riesgo, no análisis uniforme
7. **P7** — El agente le habla al autor, nunca al revisor

## Métrica norte

**% de pushes que pasan el CI al primer intento** — medida antes de construir, juzgada después.
