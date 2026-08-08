# Catálogo de reglas — rulepack 2026.08.1

Referencia del equipo. ⛔ = bloquea el commit (y el CI) · ⚠️ = aviso.
Los hallazgos del LLM (sombra) jamás bloquean — principio P2.

## 🟥 SEGURIDAD

| Regla | Detecta | Gate |
|---|---|---|
| gitleaks (todas las familias) | Secretos en lo staged | ⛔ fail-closed, offline |
| python-eval / ts-eval | eval() — inyección de código | ⛔ |
| python-subprocess-shell | shell=True — inyección de comandos | ⛔ |
| python-yaml-unsafe-load | yaml.load sin Loader seguro | ⛔ |
| go-sql-concat | SQL por concatenación | ⛔ |
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

## Notas de gobierno

- Solo lo determinista bloquea. El LLM aconseja (P2, no negociable).
- Los secretos nunca entran a baseline ni se degradan por feedback.
- Una regla con ≥5 votos y >20% de falsos positivos en un repo se degrada
  sola a aviso (auto-calibración) — excepto gitleaks.
- Regla determinista con falso positivo confirmado: se corrige o se
  desactiva; no se tolera (estándar Sonar, spec §6.1).
