# Catálogo de reglas — rulepack 2026.08.3

Referencia del equipo. ⛔ = bloquea el commit (y el CI) · ⚠️ = aviso.
Los hallazgos del LLM (sombra) jamás bloquean — principio P2.

## 🟥 SEGURIDAD

| Regla | Detecta | Gate |
|---|---|---|
| gitleaks (todas las familias) | Secretos en lo staged | ⛔ fail-closed, offline |
| python-eval / ts-eval | eval() — inyección de código | ⛔ |
| python-subprocess-shell | shell=True — inyección de comandos | ⛔ |
| python-yaml-unsafe-load | yaml.load sin Loader seguro | ⛔ |
| go-sql-concat | SQL por concatenación en una línea | ⛔ |
| go-sql-concat-en-variable | SQL armado en una variable y pasado a Query (flujo de datos) | ⛔ |
| csharp-binaryformatter | Deserialización insegura .NET | ⛔ |
| ts-jwt-decode-no-verify | JWT sin verificar firma | ⛔ |
| hardcoded-connstring | Connection string con password | ⛔ |
| ts-innerhtml-var | innerHTML dinámico (XSS) | ⚠️ |
| python-pickle-load | Deserialización pickle | ⚠️ |
| cors-wildcard | CORS con * | ⚠️ |
| trivy | Dependencias con CVE | ⚠️ local / ⛔ CI |

## 🟦 CALIDAD

| Regla | Detecta | Gate |
|---|---|---|
| gofmt / ruff format / dotnet format | Sin formatear (auto-corregible) | ⛔ |
| go vet | Errores de alta certeza en Go | ⛔ |
| ruff check (E4/E7/E9/F) | Errores reales de Python | ⛔ |
| tsc | Errores de tipos/compilación TS | ⛔ |
| ts-explicit-any | any explícito | ⛔ |
| go-ignored-error | _ = err | ⛔ |
| go-close-sin-comprobar-en-escritura | Cerrar un archivo de escritura sin mirar el error | ⚠️ |
| catch-vacio-ts / csharp-empty-catch / java-empty-catch / python-except-pass | Excepción tragada (OWASP A10) | ⛔ |
| todo-sin-ticket | TODO sin ticket | ⚠️ |

## 🟩 DATOS

| Regla | Detecta | Gate |
|---|---|---|
| squawk (12 de alto riesgo: NOT NULL sin default, índice sin CONCURRENTLY, UNIQUE directa, drops, renames, cambio de tipo, serial PK…) | Migraciones que tiran producción | ⛔ |
| squawk (resto: lock_timeout, statement_timeout, IF NOT EXISTS, NOT VALID) | Migraciones frágiles | ⚠️ |
| sql-delete-sin-where / sql-update-sin-where | Afectar la tabla completa | ⛔ |
| ts-query-en-bucle / python-orm-en-bucle / sql-in-loop-ts | N+1 | ⚠️ |
| log-dato-sensible | Password/token/PII hacia logs | ⚠️ |
| sql-select-star | SELECT * | ⚠️ |
| sql-like-comodin-inicial | LIKE '%…' | ⚠️ |

## 📕 PLAYBOOK (2026.08.2)

Reglas del playbook de seguridad de la casa. Las cuatro últimas no son de
Semgrep: miran el repositorio y el cambio, no el contenido de un archivo, así
que viven en `internal/pipeline`.

| Regla | Detecta | Gate |
|---|---|---|
| gha-action-sin-sha | Acción de GitHub anclada por etiqueta movible | ⛔ |
| orm-raw-interpolado (py/ts/c#) | raw() del ORM con interpolación — reabre la inyección | ⛔ |
| cookie-sin-httponly (ts/c#/py) | Cookie de sesión legible desde JavaScript | ⛔ |
| cookie-sin-secure | Cookie que viaja también por HTTP plano | ⚠️ |
| lockfile-ausente | Manifiesto cambiado sin lockfile en el repo | ⛔ |
| lockfile-desincronizado | Manifiesto cambiado, lockfile sin tocar | ⚠️ |
| complejidad-excesiva | Función por encima de `max_complexity` (15) | ⚠️ |
| cambio-demasiado-grande | Más de 400 líneas: la revisión deja de encontrar defectos | ⚠️ |

Por qué esas cuatro sólo avisan: partir un cambio, simplificar una función o
aceptar un lockfile desfasado son decisiones del autor. Bloquear ahí sería que
el agente secuestre el trabajo (P4).

## Notas de gobierno

- Solo lo determinista bloquea. El LLM aconseja (P2, no negociable).
- Los secretos nunca entran a baseline ni se degradan por feedback.
- Una regla con ≥5 votos y >20% de falsos positivos en un repo se degrada
  sola a aviso (auto-calibración) — excepto gitleaks.
- Regla determinista con falso positivo confirmado: se corrige o se
  desactiva; no se tolera (estándar Sonar, spec §6.1).
