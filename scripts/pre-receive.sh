#!/usr/bin/env bash
# ==============================================================================
# CodeGuard Enterprise — Git Pre-Receive Server-Side Hook Template
# ==============================================================================
# Este hook se instala en el servidor Git (GitHub Enterprise / GitLab Server / Gitea)
# para actuar como compuerta de seguridad en la frontera de red.
#
# Comportamiento:
# 1. Analiza cada commit entrante antes de persistirlo en el repositorio canónico.
# 2. Rechaza el 'git push' de inmediato si contiene secretos o carece de
#    atestación criptográfica válida emitida por CodeGuard.
# ==============================================================================

set -euo pipefail

ZERO_REV="0000000000000000000000000000000000000000"

while read -r oldrev newrev refname; do
    # Si la rama fue eliminada, permitir la operación
    if [ "$newrev" = "$ZERO_REV" ]; then
        continue
    fi

    # Determinar el rango de commits a inspeccionar
    if [ "$oldrev" = "$ZERO_REV" ]; then
        COMMIT_RANGE="$newrev --not --all"
    else
        COMMIT_RANGE="$oldrev..$newrev"
    fi

    # Verificar atestaciones y ejecutar escaneo server-side con CodeGuard
    if command -v codeguard >/dev/null 2>&1; then
        echo "🛡️ CodeGuard: Verificando integridad de commits para $refname..."
        
        # 1. Verificar atestaciones criptográficas
        if ! codeguard verify-attestation --range "$COMMIT_RANGE" --fail-closed >/dev/null 2>&1; then
            echo "" >&2
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
            echo " ❌ PUSH RECHAZADO POR CODEGUARD (POLÍTICA DE SEGURIDAD)" >&2
            echo "    Uno o más commits en $refname carecen de atestación criptográfica" >&2
            echo "    válida (posible uso de 'git commit --no-verify' o hooks desactivados)." >&2
            echo "    Ejecuta 'codeguard scan' localmente y vuelve a hacer el commit." >&2
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
            echo "" >&2
            exit 1
        fi
    fi
done

exit 0
