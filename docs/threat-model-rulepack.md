# Threat model — cadena de confianza del rulepack (W3)

Una página. Qué protege la firma del rulepack, qué no, y qué pasa cuando algo
falla. Diseño firmado por el consejo (plan-calidad-mundial t.95-105).
Contacto de seguridad: hfdb16@hotmail.com.

## Qué se firma y quién verifica

Cada release de rulepack publica su árbol (bytes exactos, testdata podado) +
`manifest.json` (schema, versión del rulepack, generated_at, files con
sha256+tamaño, digest del árbol `codeguard-rulepack-tree-v1`) +
`manifest.sig` (Ed25519 sobre los bytes exactos del JSON — escrito una vez,
jamás re-serializado). `dist/build-dist.ps1` obtiene la pública desde la clave
DPAPI y la inyecta con `-ldflags -X` en el REGISTRO estricto del binario
(`internal/manifest/claves.go`); el resolutor verifica
(`rulepack.Resolver`): firma válida + versión firmada == nombre del
directorio + árbol coincidente = `Verified`. Costo medido del re-hash
completo por resolución (sin caché mtime — un reemplazo del mismo tamaño con
timestamp restaurado lo evadiría): p50 1.0 ms / p95 1.3 ms sobre el árbol
real de 161 reglas, contra un presupuesto de hook de ~5 s.

La verificación es 100 % LOCAL: si el central cae no pasa nada — no hay
dependencia de red, y esa es la anti-promesa deliberada de `internal/attest`
(desactivado, sin promesa externa; la attestation por dispositivo es
compuerta de FLOTA).

## Dónde vive la clave privada (DECIDIDO 2026-08-23)

**En la máquina de release, cifrada con DPAPI de Windows** (atada a la
cuenta: ilegible desde otra cuenta u otra máquina), generada y usada por
`codeguard-release` (`keygen` / `sign-rulepack`), con **respaldo offline**
impreso UNA sola vez al generarla (USB/papel, fuera de la máquina). Razón:
el release ES local (`dist/build-dist.ps1`); subir la clave a la nube sin
que nada la use ahí solo agranda la superficie. Cuando exista un workflow de
release automatizado (era de flota), se migra a un environment secret con
revisores requeridos o a hardware. La clave jamás entra al repo; la pública
viaja embebida en el binario por release.

`build-dist.ps1` es fail-closed: si no puede leer una clave real aborta antes
de compilar, y si cualquier rulepack no se puede firmar no produce la
distribución. Los builds normales de desarrollo dejan el registro vacío para
no convertir una clave de prueba en una raíz de confianza accidental.

## Política por origen del rulepack

| Origen | Exigencia | Fallo ⇒ |
|---|---|---|
| Instalado (junto al binario / LOCALAPPDATA) | manifiesto firmado válido + versión coincidente + árbol coincidente | RECHAZO con nombre y diagnóstico por archivo, fail-visible; JAMÁS cae en silencio al vendoreado. Recuperación: versión instalada anterior que verifica, o reinstalar |
| Vendoreado en el repo analizado | sin firma exigida (reglas del propio equipo) | se DICE (source=vendored) y su digest se estampa igual en veredicto/BD |
| Binario sin claves embebidas (desarrollo, o anterior al primer release firmado) | no puede exigir firma | `Verified=false` sin error; la exigencia se enciende sola en el primer binario con clave. Un binario de desarrollo JAMÁS embebe claves de prueba: sería la puerta trasera perfecta |

Además: si el árbol cambia MIENTRAS corre el análisis, el veredicto se
degrada con `rulepack:changed-during-analysis` y la identidad deja de
prometer el digest (la misma clase de carrera que el worktree del bug #8).

## Rotación y compromiso

- **Rotación planificada**: release nuevo con AMBAS públicas embebidas
  durante una ventana; los manifests nuevos firman con la nueva; al cierre
  de la ventana muere la vieja.
- **Clave COMPROMETIDA**: binario de emergencia que ELIMINA la pública vieja
  de inmediato — sin ventana dual (mantenerla dejaría al atacante firmando
  manifests válidos para todos los binarios no actualizados).
- **Riesgo aceptado y cuantificado**: entre la filtración y que el último
  binario viejo se actualice, un atacante con la privada puede firmar
  manifests maliciosos válidos PARA ESOS BINARIOS VIEJOS. La ventana dura lo
  que tarde la actualización de binarios (hoy manual: reinstalar; sin flota
  no hay push forzado). Mitiga: aviso por el sitio/canal, y el digest
  estampado en runs deja auditable QUÉ reglas corrieron en cada commit del
  periodo.

## Lo que esto NO es (honestidad de alcance)

- **No es anti-rollback**: la versión firmada + nombre del directorio
  impiden el MISBINDING (presentar 2026.07 como 2026.08), pero un downgrade
  deliberado del pin a una versión vieja legítima es OPERACIÓN PERMITIDA Y
  VISIBLE (versión+digest estampados lo hacen auditable). La época
  monotónica firmada es compuerta de flota.
- **No protege contra el dueño de la máquina**: quien controla el equipo
  puede parchear el binario mismo. El firmado Authenticode del INSTALADOR es
  otra capa (Azure Artifact Signing, ~$10 USD/mes, pendiente de suscripción
  personal de Azure — decisión abierta), fuera de la ruta crítica de
  solitario y bloqueante solo de flota.
- **No borra el pasado**: clones previos del historial y cachés de terceros
  quedan fuera del alcance de cualquier firma.
