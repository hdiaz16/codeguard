# Estado de estabilización de CodeGuard

Fecha de corte: 2026-08-31
Versión candidata: `1.0.0-rc2`
Rulepack: `2026.08.3` (161 reglas)

## Objetivo

Pulir las funciones existentes, cerrar brechas de seguridad y entregar un
producto estable y confiable sin ampliar su alcance funcional. Las correcciones
resuelven la causa raíz y los fallos de cobertura nunca se presentan como éxito.

## Completado y verificado

- El hook analiza el árbol staged exacto, respeta índices alternos y vuelve a
  comprobar su identidad para cerrar la ventana TOCTOU.
- El protocolo IPC v2 impide que una instalación mezclada caiga silenciosamente
  al análisis antiguo del working tree.
- Los outcomes canónicos (`clean`, `findings`, `blocked`, `degraded`, `failed`,
  `skipped`) se propagan al hook, daemon, panel, orbe, historial y SARIF.
- Una capa obligatoria degradada bloquea según la política y jamás produce un
  verde falso.
- Cachés corruptas, parciales o sin identidad son miss; los resultados dependen
  del contenido, configuración, rulepack y versión del motor.
- La instalación y actualización usan preparación, swap transaccional,
  rollback y comprobación de salud. Las pruebas limpia, sobre la misma versión
  y sobre una instalación existente terminaron con un daemon, un runtime Python
  y un WebView.
- El desinstalador retira daemon, autoarranque, binarios, motores y WebView; la
  prueba desde estado cero confirmó que no quedaban procesos ni instalación.
- Los motores se obtienen de repositorios o índices oficiales, con versiones y
  hashes fijados. El wheelhouse Python se resuelve exclusivamente desde PyPI y
  se instala offline con `--require-hashes`.
- El rulepack se firma y verifica; una firma, versión, archivo o digest
  incorrectos se rechazan.
- Las 161 reglas Semgrep tienen mensaje, causa (`why`) y corrección concreta
  (`fix_hint`). Una prueba impide publicar reglas que omitan esos campos.
- Bandit y Gosec enriquecen cada hallazgo de forma determinista por CWE con
  impacto y remediación. La IA sólo aporta una sugerencia contextual opcional,
  acotada y rotulada para revisión humana; nunca decide el veredicto.
- El panel y el orbe se validaron renderizados: contenido, colores, iconos,
  estados, degradación, detalle técnico, impacto, arreglo y rótulo de IA
  corresponden al resultado real y usan lenguaje profesional para desarrollo.

## Evidencia de esta versión

- `go test -short ./...`: pasa.
- Auditoría del rulepack: 161 reglas, 0 sin mensaje, 0 sin `why`, 0 sin
  `fix_hint`.
- `dist/build-dist.ps1`: pasa; genera binarios `1.0.0-rc2`, rulepack firmado y
  wheelhouse oficial cerrado de 77 paquetes.
- Repositorio E2E detectó Go, Java, Python, SQL y TypeScript.
- Un commit con secreto real de prueba fue bloqueado por Gitleaks y HEAD no
  avanzó.
- La falla nativa de Semgrep en Windows se reporta como degradación y bloquea
  cuando la política exige esa capa; no se oculta ni se cachea como limpio.

## Limitaciones conocidas antes de GA

- Semgrep 1.175 falla en este entorno Windows al crear `socketpair`; es una
  limitación reproducida del binario oficial. CodeGuard falla de forma segura,
  pero falta una solución oficial compatible para recuperar esa cobertura.
- `google-java-format` 1.36.1 requiere JDK 21 y esta máquina tiene JDK 17. El
  estado se informa como capa no ejecutable; las integraciones Java deben
  repetirse en una máquina con JDK 21.
- Los binarios y el instalador aún no tienen firma Authenticode. Para GA faltan
  certificado, SBOM publicado, auditoría independiente y piloto sostenido.

## Siguiente fase

Publicar `v1.0.0-rc2` como prerelease, validar su instalación desde el artefacto
publicado en una máquina limpia y ejecutar un piloto de 72 horas antes de
considerar la etiqueta estable.
