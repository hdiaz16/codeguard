# Hardening

Las reglas de seguridad **del propio agente**. La regla de oro: *un CodeGuard roto degrada a transparente, nunca a candado* — salvo secretos.

## Implementadas y verificadas ✅

1. **Redacción P5**: todo diff/snippet se redacta antes de tocar el LLM (9 familias de patrones, con tests)
2. **Secretos primero, offline, fail-closed** — antes de cualquier red
3. **Los secretos jamás se suprimen ni degradan** (ni baseline ni feedback)
4. **Lectura confinada al repo** — rutas `../../` no escapan
5. **Pipe con SID + DACL** de solo-usuario
6. **API key solo en variable de entorno** — nunca repo/BD/logs
7. **El LLM nunca ejecuta ni bloquea** — sin camino prompt-injection → acción
8. **El daemon sin credenciales de git** — no puede commitear/pushear
9. **Todo texto de terceros escapado en la UI** (sin XSS)
10. **staticcheck 0 hallazgos · gosec triado · tests de contrato verdes**

## Del instalador (diseñadas, pendientes) ⏳

11. Motores por **ruta absoluta + hash pinneado**
12. Escáneres en **Job Objects** + token restringido
13. **Cero elevación** — jamás admin
14. API key al **Credential Manager**
15. **Firma de código** (Q5 — trámite del certificado)
16. Telemetría central: metadatos y fingerprints, **nunca código** (fase 5)

Relacionado: [[Arquitectura]] · [[Capa LLM]]
