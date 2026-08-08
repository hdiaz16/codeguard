# Arquitectura

Dos procesos + el CI corriendo el mismo binario ([[00 - CodeGuard|principio P3]]).

```mermaid
flowchart TB
    subgraph MAQUINA["💻 Máquina del dev"]
        GIT["git commit"] --> HOOK["codeguard.exe hook<br/>(efímero, ~12 MB)"]
        HOOK -->|"1· secretos OFFLINE<br/>(gitleaks, fail-closed)"| HOOK
        HOOK <-->|"named pipe<br/>SID + DACL"| DAEMON["codeguard-daemon.exe<br/>(Wails, ~16 MB, tray)"]
        DAEMON --> ENGINES["motores en paralelo:<br/>semgrep · tsc · squawk ·<br/>trivy · gofmt · vet · ruff"]
        DAEMON --> ORBE["🔮 orbe de plasma"]
        DAEMON --> PANEL["panel flotante"]
        DAEMON --> DB[("SQLite local:<br/>runs · findings ·<br/>feedback · llm_calls")]
    end
    DAEMON -.->|"sombra async<br/>diff REDACTADO"| FOUNDRY["☁️ Azure AI Foundry<br/>Kimi K3 + GPT-5.6-sol"]
    subgraph CI["⚙️ GitHub Actions (windows-latest)"]
        CIBIN["codeguard.exe ci<br/>SOLO capa determinista"] --> SARIF["SARIF → pestaña Security"]
    end
    GIT -.->|push| CI
```

## Decisiones clave (ADRs)

| | Decisión | Por qué |
|---|---|---|
| ADR-02 | Solo lo determinista bloquea | FP >20-30% = abandono de la herramienta |
| ADR-03 | Mismo binario local y CI | La paridad por construcción, no por promesa |
| ADR-04 | Wails v3, no Electron | 27 MB de binarios vs 120-150 MB |
| ADR-05 | Modelo vía Foundry (nube) | Sin techo de precisión de modelos locales |
| ADR-09 | Windows único target | 99.99% de los devs |
| ADR-12 | Aislamiento por privilegios del SO, no VM | Una sandbox no cabe en 5 s de presupuesto |

Relacionado: [[Flujo del commit]] · [[Hardening]]
