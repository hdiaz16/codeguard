# Grafo de paquetes

El grafo de dependencias **real** del código, extraído del compilador de Go (`go list`). Si este diagrama y el código divergen, el diagrama está mal — regenerarlo, no dibujarlo.

```mermaid
flowchart TB
    subgraph BINARIOS["📦 binarios"]
        CLI["cmd/codeguard<br/>(hook · ci · init · stats)"]
        DAE["cmd/daemon<br/>(orbe + panel)"]
    end

    subgraph ORQUESTACION["⚙️ orquestación"]
        DAEMON["daemon<br/>(servidor pipe + warmup)"]
        PIPELINE["pipeline<br/>(etapas 0-2, 7 + supresiones)"]
        SHADOW["shadow<br/>(etapas 3-6 + redacción P5)"]
    end

    subgraph MOTORES["🔍 motores"]
        ENG["engines<br/>(interfaz)"]
        GL["gitleaks"]
        SG["semgrep"]
        SQ["squawk"]
        TV["trivy"]
        LT["linters<br/>(gofmt·vet·ruff·tsc·dotnet)"]
    end

    subgraph NUCLEO["🧱 núcleo (sin dependencias hacia arriba)"]
        FIND["finding<br/>(modelo + fingerprint)"]
        GIT["gitdiff"]
        CFG["config"]
        IPC["ipc<br/>(pipe SID+DACL)"]
        FOUND["foundry<br/>(cliente LLM + stream)"]
        STORE["store<br/>(SQLite + migraciones)"]
        BASE["baseline"]
        SARIF["sarif"]
    end

    CLI --> PIPELINE & DAEMON & SHADOW & SARIF & BASE
    DAE --> DAEMON & SHADOW & FOUND
    DAEMON --> PIPELINE & SHADOW & IPC & BASE
    DAEMON --> SG & SQ & TV & LT
    PIPELINE --> ENG & GL & CFG
    SHADOW --> FOUND & IPC & STORE & CFG
    GL & SG & SQ & TV & LT --> ENG
    ENG --> FIND & GIT
    IPC --> FIND & GIT
    FOUND --> CFG
    STORE --> FIND
    BASE --> FIND
    SARIF --> FIND
```

## La lectura arquitectónica

- **El núcleo no depende de nadie de arriba** — `finding`, `gitdiff`, `config` son hojas puras: cambiar la UI o los motores jamás los toca.
- **Todos los motores dependen solo de la interfaz** `engines` — agregar un lenguaje nuevo (Java, Kotlin) es un paquete nuevo que implementa `Engine`, sin tocar nada más.
- **`shadow` no conoce a los motores ni al pipeline** — la capa LLM está aislada: apagarla es no llamarla.
- Los dos binarios comparten todo por debajo — la paridad P3 por construcción.

Cómo regenerarlo: `go list -f '{{.ImportPath}}: {{range .Imports}}{{.}} {{end}}' ./cmd/... ./internal/...`

Relacionado: [[Arquitectura]] · [[00 - CodeGuard]]
