# Flujo del commit

Lo que vive el dev, de `git commit` al verde. El veredicto bloqueante tarda 2-6 s; las sugerencias del modelo llegan después y **jamás retrasan el commit**.

```mermaid
sequenceDiagram
    actor Dev
    participant Git
    participant Hook as hook (efímero)
    participant Daemon as daemon
    participant Orbe as 🔮 orbe
    participant Kimi as ☁️ Kimi (sombra)

    Dev->>Git: git commit
    Git->>Hook: pre-commit
    Note over Orbe: 🌫️ niebla → ❄️ ventisca
    Hook->>Hook: 1· secretos (offline, fail-closed)
    Hook->>Daemon: diff staged (pipe, deadline 5s)
    Daemon->>Daemon: 2· motores en paralelo<br/>(corta a los lentos antes del deadline)
    Daemon-->>Hook: veredicto + hallazgos
    alt BLOQUEADO
        Hook-->>Git: exit 1 — el commit NO existe
        Note over Orbe: 🪨 granito latiendo
        Daemon->>Dev: panel florece: código señalado +<br/>"en palabras simples" (GPT-5.6-sol)
        Dev->>Dev: corrige → reintenta
    else APROBADO
        Hook-->>Git: exit 0 — commit COMPLETADO
        Git->>Git: prepare-commit-msg sella<br/>trailer Codeguard-Run-Id
        Note over Orbe: 🌿 verde salvia (15 s)
        Daemon->>Kimi: 3-6· sombra async (diff redactado)<br/>solo si riesgo ≥ umbral
        Kimi-->>Daemon: hallazgos → verificación<br/>anti-alucinación → shown=0
    end
```

## Reglas del flujo

- **El verde y el commit son el mismo instante** — no hay aprobación posterior.
- `--no-verify` existe: el commit pasa, pero `post-commit` lo registra como bypass (señal de producto, no castigo).
- Todo intento (bloqueado o no) queda en [[Telemetría y calibración|la telemetría]].
- Si CodeGuard truena, el commit pasa ([[00 - CodeGuard|P4]]) — salvo secretos.

Relacionado: [[El orbe]] · [[Pilares y reglas]]
