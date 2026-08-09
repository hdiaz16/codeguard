# CodeGuard

Agente local de análisis pre-commit para Windows. Corre en la máquina del
desarrollador, revisa lo que está a punto de commitear y **bloquea sólo lo que
el CI también rechazaría**.

No es un linter más: es la promesa de que si el commit pasa aquí, pasa allá.

```
CodeGuard  secretos ✓
CodeGuard  formato/lint/tipos/reglas/migraciones ✗
CodeGuard    [gha-action-sin-sha] .github/workflows/ci.yml:7  Acción anclada por etiqueta, no por SHA
CodeGuard    [lockfile-ausente] package.json:1  package.json cambió y el proyecto no tiene lockfile
CodeGuard    [orm-raw-interpolado-ts] src/api.ts:2  Consulta cruda del ORM con plantilla interpolada
CodeGuard    [cookie-sin-httponly] src/api.ts:3  Cookie de sesión sin httpOnly
CodeGuard  BLOQUEADO: 4 problema(s) que el CI también rechazaría  (4.6 s)
```

## Principios

Cinco reglas que mandan sobre cualquier decisión de diseño:

| | |
|---|---|
| **P1** | Sólo lo determinista bloquea. Lo que bloquea aquí, bloquea en el CI. |
| **P2** | El modelo aconseja y **jamás** bloquea. |
| **P3** | El veredicto se explica: regla, archivo, línea, por qué importa y qué hacer. |
| **P4** | El agente no secuestra el trabajo. Si algo falla, degrada y avisa; no impide commitear. |
| **P5** | Nada que parezca una credencial sale a la red. La redacción ocurre antes de cualquier llamada. |

## Qué revisa

**112 reglas propias** repartidas en tres pilares —seguridad, calidad y datos—
sobre nueve motores:

| Motor | Cubre |
|---|---|
| gitleaks | Secretos en lo staged · compuerta *fail-closed* |
| Semgrep CE | El rule pack de la casa (Go, Python, TS/JS, C#, Java) |
| Squawk | Migraciones de PostgreSQL con riesgo de tirar producción |
| Trivy | Dependencias con CVE |
| gofmt · go vet | Go |
| ruff | Python |
| tsc | TypeScript |
| dotnet format | C# |

Más las reglas que no miran el contenido de un archivo sino la forma del
cambio: lockfile desincronizado, complejidad ciclomática por función, y
cambios por encima de las 400 líneas revisables.

## Cómo se siente al usarlo

Un **orbe** en la esquina de la pantalla cambia de color según el estado
—reposo, analizando, limpio, bloqueado, degradado, sin conexión— y de él sale
el panel con los hallazgos, cada uno con su fragmento de código señalado.

Un **explorador 3D** mapea el repositorio a nivel de función: quién llama a
quién, qué consulta sale de dónde, y dónde cayeron los hallazgos del último
análisis. Todo local, sin navegador.

Cada proyecto mantiene su propio contexto: que uno esté bloqueado no bloquea
a los demás.

## Instalación

Con el paquete instalador (lo genera `dist\build-dist.ps1` si hay Inno Setup):

```
CodeGuard-Setup.exe          # asistente gráfico; /VERYSILENT para reparto masivo
```

O con el script clásico:

```powershell
powershell -ExecutionPolicy Bypass -File dist\install.ps1
```

Sin permisos de administrador. Instala binarios y motores bajo
`%LOCALAPPDATA%\CodeGuard`, deja el daemon arrancando con la sesión y verifica
cada motor descargado contra el checksum publicado por sus autores. El setup
queda registrado en «Aplicaciones instaladas» con su desinstalador.

Después, en cada repositorio:

```powershell
codeguard init      # detecta lenguajes, genera config, hooks y baseline
```

## Comandos

| | |
|---|---|
| `init` | Enrola un repo: config + hooks + baseline + registro |
| `install` | Sólo hooks, para quien recibe la config por `git pull` |
| `status --todos` | Verifica el enrolamiento de todos los repos |
| `report` | Genera `HALLAZGOS.md` para pasárselo a un agente de codificación |
| `graph --deep` | Abre el explorador 3D del repo |
| `config` | Configura el modelo (proveedor, endpoint, clave) |
| `engines` | Verifica la identidad de los motores y su contención |
| `repair` | Revisa y repara dependencias y rulepack |
| `baseline` · `stats` · `rules suggest` · `ci` | |

## El modelo es opcional y se elige

La capa de consejo habla el dialecto de OpenAI y el de Anthropic, con
preajustes para Azure AI Foundry, OpenAI, Anthropic, OpenRouter, Groq,
DeepSeek, Ollama y LM Studio. Los dos últimos corren en la propia máquina: el
código no sale de ahí.

La API key **nunca** se escribe en un archivo de CodeGuard — la configuración
guarda sólo el nombre de la variable de entorno que la contiene.

## Contención

Los motores son binarios de terceros, así que corren acotados:

- **Entorno acotado** — lista de permitidos, no de prohibidos. La API key del
  modelo no viaja a ningún motor.
- **Token restringido** — sin privilegios salvo recorrer directorios.
- **Job object** — mueren con el plazo junto a todos sus hijos, con tope de
  memoria y de procesos, y sin acceso al portapapeles ni al escritorio.
- **Identidad verificada** — cada motor descargable se compara contra el
  SHA-256 que publicaron sus autores.

Lo que *no* hace: no restringe el sistema de archivos. Un motor tiene que leer
el repositorio.

## Rendimiento

Medido sobre repos reales (`tests/suite.ps1`, 36 aserciones):

| | |
|---|---|
| Hook | p50 4.7 s · p95 6.3 s |
| Daemon | 38 MB |
| Binarios | 29.8 MB |
| Rule pack | 2026.08.2 — 112 reglas |

## Construir

```powershell
go build ./...
go test ./...
powershell -ExecutionPolicy Bypass -File tests\suite.ps1   # e2e, necesita el daemon vivo
```

Go 1.26 · Wails v3 · SQLite sin cgo · sin dependencias de red en tiempo de
análisis.

## Estado

Funciona de punta a punta y se usa a diario en varios repositorios. Lo que
falta antes de repartirlo a un equipo grande está documentado sin adornos:
mayor cobertura de tests unitarios, un piloto con varios desarrolladores para
calibrar la tasa de falsos positivos, y un certificado de firma de código.
