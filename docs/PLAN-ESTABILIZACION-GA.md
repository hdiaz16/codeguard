# Plan de estabilización de CodeGuard 1.0 GA

**Inicio:** 2026-08-30
**Horizonte orientativo:** 8–12 semanas
**Objetivo:** convertir el release candidate actual en un producto estable,
confiable y operable por un equipo que no conoce su implementación.
**Regla de alcance:** no se añaden motores, reglas, pantallas, plataformas,
integraciones ni capacidades de LLM. Sólo se permiten correcciones de
seguridad, exactitud, confiabilidad, rendimiento, instalación, accesibilidad,
documentación y soporte de las funciones que ya existen.

Este documento sustituye como plan operativo a los planes históricos de
`remediacion/`. Esos documentos conservan valor forense, pero mezclan defectos
ya cerrados, hipótesis antiguas y expansión de producto. Ningún elemento se
considera abierto o cerrado por lo que diga un documento histórico: se
reproduce contra el `HEAD` actual y se registra aquí.

---

## 1. Resultado que se busca

CodeGuard estará listo para llamarse **estable** cuando pueda responder con
evidencia afirmativa a estas preguntas:

1. ¿Un resultado limpio significa que todas las capas aplicables miraron
   exactamente el contenido que se iba a commitear?
2. ¿Cualquier fallo de una capa aparece como degradación o bloqueo conforme a
   la política, y nunca como un falso verde?
3. ¿Un repositorio hostil es incapaz de robar secretos, sustituir políticas o
   usar un motor para ejecutar con más autoridad de la necesaria?
4. ¿Instalar, actualizar, reparar, revertir y desinstalar convergen aunque el
   proceso se interrumpa a mitad?
5. ¿El mismo commit recibe el mismo veredicto local y en CI, o una explicación
   estructurada y accionable de la diferencia?
6. ¿El daemon puede vivir días, recuperarse de fallos y conservar datos sin
   procesos zombis, bloqueos o crecimiento no acotado?
7. ¿Una persona ajena al proyecto puede entender y reparar cualquier estado
   degradado sin leer el código?

La meta no es “tener muchos tests”. La meta es que cada promesa del producto
tenga un test de contrato, una métrica en operación y una respuesta definida
ante fallo.

---

## 2. Congelación de alcance

### Permitido durante la estabilización

- Corregir falsos verdes, falsos bloqueos y discrepancias local/CI.
- Reducir privilegios, acceso a disco, entorno y red.
- Endurecer IPC, almacenamiento, rulepacks, cachés y cadena de suministro.
- Hacer idempotentes instalación, actualización, reparación y desinstalación.
- Mejorar mensajes, jerarquía visual, accesibilidad y consistencia del panel.
- Eliminar código muerto, duplicación, estados imposibles y documentación
  desactualizada.
- Reducir latencia, consumo, procesos, escrituras y ruido sin cambiar el
  resultado correcto.
- Añadir fixtures, fuzz, mutaciones, fault injection, benchmarks y telemetría
  estrictamente operacional sin contenido del repositorio.

### Prohibido hasta después de GA

- Nuevos motores o familias de reglas.
- Soporte macOS/Linux.
- Nuevas visualizaciones del grafo o nuevos estados del orbe.
- Nuevos proveedores o capacidades LLM.
- Portal cloud, panel de flota, SSO, RBAC o nuevas integraciones SCM.
- Attestation de flota o enforcement remoto nuevo.
- Cambios cosméticos sin relación con un recorrido crítico o una métrica.

Toda propuesta nueva va a una lista `DESPUES-DE-GA.md`; no entra en el backlog
activo aunque parezca pequeña.

---

## 3. Gates de salida de GA

GA no depende de una fecha. Depende de que se cumplan simultáneamente los
siguientes gates durante **14 días consecutivos** sobre el candidato final.

### Seguridad

- Cero vulnerabilidades críticas o altas conocidas sin corregir.
- Cero caminos reproducibles de secreto → red, log, UI, argumento de proceso,
  telemetría o proceso hijo no autorizado.
- Cero sustituciones silenciosas de binario, rulepack o configuración de
  confianza.
- Cero falsos verdes al fallar token, Job Object, plazo, parser, red, disco,
  caché, migración o motor.
- Instalador y binarios Authenticode firmados; hashes y SBOM publicados.
- Auditoría adversarial independiente cerrada; todo crítico/alto corregido y
  repetido como prueba permanente.

### Exactitud y paridad

- 100 % de paridad local/CI sobre el corpus controlado de commits.
- Cero resultados limpios sobre una capa aplicable que no observó todos sus
  objetivos declarados.
- Cero hallazgos servidos con archivo, línea, versión o configuración obsoleta.
- Staging parcial, `commit -a`, amend, merge, rename, delete, submódulo,
  worktree y rutas Unicode tienen comportamiento probado y documentado.
- Baseline, feedback y caché no pueden suprimir secretos ni resultados de otro
  contrato/versionado.

### Confiabilidad

- Dos ejecuciones limpias consecutivas de la suite completa desde un checkout
  limpio; `-race`, shuffle, fuzz curado y CodeQL verdes.
- 30 instalaciones limpias automatizadas, 20 actualizaciones N−1→N, 10
  rollbacks N→N−1 y 20 desinstalaciones sin residuos críticos.
- Prueba de 72 horas del daemon sin bloqueo, procesos zombis ni crecimiento de
  memoria superior al 10 % después del calentamiento.
- Inyección de corte después de cada paso de instalación y migración: la
  siguiente ejecución converge sin pérdida ni estado fantasma.
- Base SQLite recuperable y consistente después de cierre abrupto, disco lleno,
  lock concurrente y migración interrumpida.

### Experiencia y operación

- Tasa de falso bloqueo ≤1 % en el piloto.
- Tasa de bypass objetivo <5 %; si supera 15 %, se detiene el rollout.
- Disponibilidad de análisis ≥99,9 % durante el piloto, excluyendo estados
  declarados como no aplicables.
- p50 ≤5 s y p95 ≤12 s en repositorios del piloto; los casos que compilan un
  proyecto completo se reportan por separado y nunca quedan sin presupuesto.
- 90 % de los estados degradados se resuelven con el mensaje mostrado, sin
  intervención del autor.
- Cero contradicciones entre terminal, orbe, panel, SARIF, base y comentario de
  PR para el mismo `AnalysisOutcome`.

### Validación externa mínima

- ≥10 repositorios, ≥20 desarrolladores, ≥500 intentos de commit y ≥14 días.
- Al menos tres stacks distintos y dos máquinas que no hayan sido preparadas
  por el autor.
- Un informe final con latencia, bypass, falso positivo por regla, capas
  degradadas, discrepancias de paridad e incidentes prevenidos.

---

## 4. Clasificación de trabajo

### P0 — detiene todo

Cualquier falso verde, fuga de secreto, RCE desde repositorio, bypass de
identidad/política, corrupción o pérdida de datos, bloqueo permanente del
commit, instalador que afirma éxito sin producto operativo, deadlock o fallo
que invalida la promesa local/CI.

Un P0 exige:

1. Reproductor mínimo antes del arreglo.
2. Test rojo que demuestre el daño, no sólo la función interna.
3. Arreglo de causa raíz.
4. Mutación que demuestre que el test caza la regresión.
5. Validación por una persona distinta o, si no existe, revisión adversarial
   separada al menos 24 horas y contra un binario limpio.

### P1 — necesario para GA

Falso bloqueo no generalizado, degradación mal explicada, actualización no
idempotente, inconsistencia UI/terminal, fuga de recursos, latencia fuera de
presupuesto, recuperación deficiente o documentación operativa incorrecta.

### P2 — pulido condicionado

Claridad, accesibilidad, eliminación de duplicación, ruido visual, mensajes y
mejoras de mantenimiento. Sólo se atiende cuando P0 está en cero y P1 tiene
dueño y fecha.

---

## 5. Plan para empezar hoy

### Bloque 1 — 90 minutos: congelar y capturar la verdad

1. Declarar `HEAD` actual como línea base de estabilización y no mover la
   versión de release hasta obtener una corrida reproducible.
2. Crear un tablero único con columnas: `nuevo`, `reproducido`, `test rojo`,
   `arreglado`, `validación adversarial`, `cerrado`.
3. Copiar a ese tablero sólo riesgos reproducidos contra el código actual.
   `remediacion/ESTADO.md` y `TRIAJE-MEDIAS.md` son entradas de investigación,
   no estado vigente.
4. Registrar las versiones exactas de Windows, Go, Python, Java, .NET, Node y
   motores presentes en la máquina de referencia.
5. Capturar: `git status`, commit, `codeguard version`, `codeguard doctor
   --global`, `codeguard status --todos` y `codeguard engines --auditar`.

**Salida:** una línea base que otra persona puede reconstruir.

### Bloque 2 — 2 horas: establecer el gate de verdad

1. Ejecutar desde checkout limpio la suite normal y luego la suite `-race` con
   los motores fijados.
2. Conservar salida completa, duración, skips y procesos que sobrevivan.
3. Clasificar cada skip: `no aplica por diseño`, `fixture externo pendiente` o
   `defecto`. Ningún skip ambiguo entra a GA.
4. Confirmar en GitHub que `tests`, CodeQL, rulepack y auditoría de motores son
   checks requeridos para `master`.
5. Repetir la suite una segunda vez: la primera encuentra dependencias; la
   segunda detecta estado residual, cachés y falta de idempotencia.

**Salida:** primer semáforo real de CI. Si no está verde dos veces, no se hace
trabajo P2.

### Bloque 3 — 2 horas: cerrar exposiciones inmediatas

1. Retirar `-ApiKey` de la interfaz del instalador. Aunque la clave se pase al
   hijo por stdin, ya llegó como argumento al proceso PowerShell y puede quedar
   en historial/lista de procesos. Usar configuración posterior o lectura
   segura interactiva.
2. Confirmar que ninguna clave real permanece en entorno, registro, logs,
   historial, argumentos o fixtures. Rotar cualquier clave que haya aparecido.
3. Abrir un P0 para dependencias Python sin hashes de artefacto: construir un
   wheelhouse/requirements con hashes exactos y `--require-hashes`.
4. Verificar permisos/DACL de pipe, bóveda, DB, logs, manifests y clave privada
   de release en una instalación real.
5. Confirmar que el instalador no puede publicarse como estable sin
   Authenticode.

**Salida:** registro de seguridad inicial, con dueño y prueba de cierre.

### Bloque 4 — 60 minutos: fijar presupuestos

Medir un commit limpio, uno bloqueado, uno degradado y uno políglota, en frío y
caliente. Registrar tiempo total, tiempo por motor, CPU, memoria, procesos y
escrituras. Los números de hoy son la referencia; ninguna corrección puede
degradarlos más de 10 % sin decisión explícita.

### Fin del primer día

El primer día termina con:

- Congelación de alcance escrita y aceptada.
- Estado actual reproducible.
- Lista P0/P1 basada en pruebas, no en documentos antiguos.
- Suite ejecutada dos veces o un bloqueo concreto documentado.
- La fuga por `-ApiKey` clasificada y con test planificado.
- Presupuesto inicial de rendimiento.
- Próximas cinco tareas ordenadas; nunca más de dos en curso.

---

## 6. Fases de ejecución

## Fase 0 — Fuente única de verdad y CI confiable

**Duración:** días 1–3.

### Trabajo

- Revalidar cada N/H/W histórico que siga pareciendo abierto contra `HEAD`.
- Marcar los documentos históricos como `ARCHIVO / NO ES ESTADO ACTUAL` y
  enlazar este plan.
- Generar las cifras de motores, reglas, versión y artefactos desde una sola
  fuente; README, sitio, instalador y UI no deben mantener copias manuales.
- Hacer requeridos todos los checks de seguridad y pruebas.
- Garantizar checkout limpio antes y después de la suite.
- Registrar skips como datos estructurados y fallar si aparece uno nuevo sin
  allowlist, razón y caducidad.
- Añadir un resumen de cobertura: paquetes, motores reales ejercitados,
  fixtures omitidos y duración.

### Gate

- Dos corridas consecutivas limpias desde checkout nuevo.
- Cero test vacuo: cada test de motor demuestra que el proceso arrancó o usa un
  stub cuyo contrato se valida por separado.
- El estado actual vive en un solo documento/tablero.

---

## Fase 1 — Exactitud: nunca decir “limpio” sin haber mirado

**Duración:** semanas 1–2.

### 1. Contenido preparado frente a worktree

Es la brecha más importante respecto de la promesa central. Con staging parcial
algunos motores leen el disco y no el contenido del índice.

En las primeras 48 horas se toma una decisión explícita:

- **Opción recomendada:** materializar el índice en un workspace temporal
  controlado y ejecutar allí todos los motores aplicables, conservando caches
  externos seguros. El contenido examinado debe ser byte por byte el que entra
  al commit.
- **Opción de contención temporal:** declarar que la paridad no está garantizada
  con staging parcial, degradar el resultado —no sólo avisar— y retirar cualquier
  texto que prometa equivalencia total en ese caso.

No se admite mantener la promesa absoluta y analizar otra cosa.

### 2. Matriz del veredicto

Construir una tabla exhaustiva para `clean`, `findings`, `blocked`, `degraded`,
`failed` y `skipped`, cruzada con:

- hallazgos bloqueantes/no bloqueantes;
- motor ausente, timeout, salida truncada y parser roto;
- rulepack ausente, vendoreado, adulterado o cambiado durante el análisis;
- baseline válida/inválida/ambigua;
- daemon online/offline/incompatible;
- almacenamiento disponible/no disponible.

Terminal, hook, CI, SARIF, panel, orbe, DB y sync deben derivar del mismo valor
tipado. Los snapshots de todas las combinaciones son gate de PR.

### 3. Contrato de cobertura por motor

Para cada motor se prueba:

- cuándo aplica;
- qué archivos/unidades prometió mirar;
- cuáles miró realmente;
- cómo demuestra que arrancó;
- qué códigos de salida son hallazgo, error o uso inválido;
- qué pasa si una unidad falla y las demás pueden seguir;
- qué configuración, versión y contenido forman la clave de caché.

Cero hallazgos sólo se transforma en limpio cuando el conjunto observado es
igual al conjunto prometido.

### 4. Caché y baseline

- Toda clave incluye contenido, ruta cuando afecta semántica, motor, versión,
  configuración, rulepack digest y versión del verificador/parser.
- Un hit se rehidrata contra el mundo actual; ubicación ambigua o ausente
  invalida y reanaliza.
- Corrupción, entrada de versión antigua o fallo de lectura es miss visible,
  nunca acierto vacío.
- Baseline y feedback tienen pruebas permanentes de que jamás afectan secretos.
- `--rebaseline` enumera y confirma qué bloqueantes dejarán de bloquear.

### Gate

- Cero mutantes que conviertan error/degradación en limpio.
- 100 % de paridad sobre el corpus controlado.
- Staging parcial tiene una política verdadera y probada.

---

## Fase 2 — Frontera de seguridad y cadena de suministro

**Duración:** semanas 2–4; puede avanzar en paralelo con Fase 1 sólo después de
tener CI confiable.

### 1. Corpus de repositorios hostiles

Mantener fixtures permanentes que intenten:

- path traversal, symlink/junction y colisión de mayúsculas;
- reemplazar rulepack, motor, config o binario por PATH poisoning;
- ejecutar código desde ESLint, MSBuild, Python, Java o archivos de proyecto;
- leer un señuelo fuera del repositorio;
- escribir fuera del scratch permitido;
- abrir red directa, por proxy o desde un proceso nieto;
- heredar claves, tokens, credenciales git o variables nuevas desconocidas;
- inyectar HTML/JS en panel, terminal, SARIF o comentarios de PR;
- inyectar instrucciones al LLM mediante mensajes de regla;
- producir zip-slip, bomba de descompresión, salida infinita o proceso infinito;
- cambiar rulepack/config/worktree durante el análisis.

Cada intento debe fallar o producir degradación visible. Ninguno puede terminar
en limpio.

### 2. Restricción del sistema de archivos

La brecha aceptada actual —los motores pueden escribir donde escribe el
usuario— necesita decisión antes de GA.

1. Medir por motor todas las escrituras necesarias.
2. Separar repositorio/materialización de sólo lectura y scratch/caches de
   escritura.
3. Prototipar un lanzador ya contenido en Job Object y un token
   write-restricted/AppContainer.
4. Si un motor no puede funcionar bajo la frontera, degradarlo con causa; no
   ejecutarlo con autoridad completa silenciosamente.
5. Probar escape por hijos, junctions, hardlinks y rutas largas.

El gate no exige una tecnología concreta; exige que el riesgo residual esté
medido, sea visible y que motores con configuración ejecutable no obtengan
escritura global sin una decisión explícita.

### 3. Distribución verificable

- Authenticode para instalador, CLI y daemon.
- SBOM CycloneDX/SPDX por release.
- Manifest con SHA-256 de cada artefacto distribuido.
- Rulepack Ed25519 verificado end-to-end, con bit flip, misbinding, replay,
  corte de escritura, rotación y last-known-good.
- Python con wheelhouse y hashes; Go con módulo/sumas fijadas; winget documenta
  la frontera de confianza.
- `codeguard-release.exe` no se versiona como binario opaco: se construye desde
  fuente dentro del proceso de release o se publica como artefacto firmado.
- Publicar procedimiento de compromiso y rotación de clave.

### 4. Secretos y privacidad

- Eliminar entrada de claves por argumento.
- Canary corpus para P5 sobre diff, mensajes, logs, DB, UI, SARIF, sync y LLM.
- Capturar el tráfico del canario y demostrar cero contenido prohibido.
- Retención, borrado y exportación local probados.
- Revisar permisos de archivos y backups de la clave de release.

### Gate

- Auditoría adversarial independiente sin críticos/altos abiertos.
- Instalador firmado y SBOM verificable.
- Cero egress de canarios y cero ejecución no contenida silenciosa.

---

## Fase 3 — Ciclo de vida y recuperación

**Duración:** semanas 3–5.

### Instalación

Probar instalación limpia con combinaciones: sin Go, sin Python, sin Java,
JDK antiguo, sin .NET, PATH largo, usuario sin admin, locale español/inglés,
proxy, red interrumpida, disco lleno, antivirus lento y dos instaladores a la
vez. El resultado sólo puede ser:

- completo y verificado;
- incompleto con lista exacta de capas afectadas y reparación;
- fallido con rollback al estado anterior.

Nunca “LISTO” con daemon, rulepack o compuerta de secretos inoperantes.

### Actualización y rollback

- Matriz N−1→N y N→N−1 para binario, daemon, protocolo, DB y rulepack.
- Escrituras atómicas y last-known-good.
- Un daemon viejo rechaza protocolo nuevo de forma estructurada.
- Una actualización interrumpida converge al reintentar.
- Rollback conserva datos compatibles o explica por qué requiere backup.

### Repair y doctor

- `repair` es idempotente y no confía en artefactos del repo analizado.
- `doctor --json` es la misma fuente que usan init, panel y soporte.
- Cada diagnóstico incluye hecho, impacto, reparación y código estable.
- Ejecutar repair diez veces no cambia un sistema sano.

### Desinstalación

- Sin procesos, iconos, startup, perfiles, motores o credenciales residuales.
- `-Datos` y conservación de datos se prueban por separado.
- Nunca borra herramientas Python compartidas ni contenido versionado del repo
  sin explicarlo.
- Desenrolar repositorios y desinstalar la aplicación siguen siendo operaciones
  distintas.

### Daemon, IPC y base

- Una sola instancia real bajo carrera de 20 procesos.
- Handshake N/N−1/N−2.
- Deadline en toda llamada; ningún goroutine/proceso sobrevive al cierre.
- Fault injection de pipe roto, cliente muerto, mensaje truncado y payload
  incompatible.
- Migraciones con lock, checksum, idempotencia y recuperación por corte.
- SQLite con busy, disco lleno, WAL corrupto recuperable y export atómico.

### Gate

- Todas las cifras de ciclos del gate de confiabilidad cumplidas.
- Cero estado fantasma después de instalación, init, bloqueo o desinstalación.

---

## Fase 4 — Pulido de UX y rendimiento

**Duración:** semanas 5–6.

No se rediseña el producto. Se pulen los recorridos existentes:

1. Instalar y verificar.
2. Enrolar primer repo.
3. Commit limpio.
4. Commit bloqueado por secreto.
5. Commit bloqueado por regla.
6. Análisis parcial/degradado.
7. Bypass y su registro.
8. Reparar motor ausente o incompatible.
9. Actualizar y desinstalar.

Para cada recorrido:

- terminal, orbe y panel muestran el mismo estado;
- nunca se revela el valor de un secreto;
- el mensaje responde qué pasó, qué se revisó, qué no, impacto y siguiente
  acción;
- el panel no roba foco ni tapa un estado real con demo/progreso viejo;
- textos de terceros se escapan y acotan;
- teclado, contraste, zoom 200 %, lector de pantalla y resolución pequeña son
  utilizables;
- no hay errores genéricos cuando existe una causa conocida.

### Rendimiento

- Benchmarks frío/caliente y con caché vacía/llena.
- Repos pequeño, mediano, monorepo y 100k archivos.
- Disco lento, Defender activo y CPU limitada.
- Presupuesto por motor y del hook total.
- Perfil de CPU/memoria antes de optimizar; nada de optimizaciones por intuición.
- Soak de 72 horas con commits repetidos, aperturas de panel y cambios de repo.
- Contadores de procesos, handles, goroutines, memoria, WAL y caché.

### Gate

- Métricas de experiencia/rendimiento cumplidas.
- Cero contradicciones de estado en snapshots de los recorridos críticos.

---

## Fase 5 — Release candidate y piloto

**Duración:** semanas 7–10.

### Entrada al piloto

- P0 = 0; P1 con riesgo residual explícito = 0.
- Suite verde durante siete días.
- Instalador firmado y rollback probado.
- Threat model, seguridad, privacidad, instalación, troubleshooting y
  limitaciones actualizados.
- Canal de reporte de seguridad y plantilla de soporte disponibles.
- Freeze total: durante el piloto sólo entran fixes de defectos reproducidos.

### Rollout por anillos

1. Autor, 2 repos, 2 días.
2. Dos usuarios técnicos, 3–5 repos, 3 días.
3. Cinco usuarios, una semana.
4. ≥20 usuarios y ≥10 repos hasta completar 14 días y 500 commits.

Cada anillo avanza sólo si:

- no hay P0;
- falso bloqueo ≤1 %;
- bypass <15 % y descendiendo;
- paridad inexplicada = 0;
- no hay contenido P5 fuera de su frontera;
- p95 y disponibilidad están dentro del gate.

### Informe de piloto

Publicar números, no impresiones:

- instalaciones/actualizaciones exitosas;
- commits limpios, bloqueados, degradados y omitidos;
- FP por regla y motor;
- bypass por repo y motivo;
- latencia p50/p95/p99;
- disponibilidad por capa;
- diferencias local/CI;
- incidentes prevenidos;
- tickets y tiempo de resolución sin ayuda del autor;
- retención al día 7 y 14.

---

## 7. Backlog inicial ordenado

| ID | Prioridad | Trabajo | Criterio de cierre |
|---|---|---|---|
| STAB-001 | P0 | Suite reproducible en checkout limpio | Dos corridas verdes, sin procesos residuales ni skips ambiguos |
| STAB-002 | P0 | Resolver staging parcial/worktree | Se analiza el índice exacto o se degrada y limita la promesa explícitamente |
| STAB-003 | P0 | Eliminar claves por argumentos | Canary ausente de command line, historial, entorno, logs y procesos hijos |
| STAB-004 | P0 | Hashes exactos para motores Python | Instalación offline desde wheelhouse verificado y `--require-hashes` |
| STAB-005 | P0 | Rulepack firmado end-to-end | Alteración, replay y corte son rechazo visible con recuperación |
| STAB-006 | P0 | Corpus de repo hostil | Todos los escapes fallan o degradan; ninguno termina limpio |
| STAB-007 | P0 | Política de escritura de motores | Config ejecutable sin escritura global silenciosa; riesgo residual documentado |
| STAB-008 | P0 | Authenticode y SBOM | Artefactos firmados, hash/SBOM publicados y verificados en VM limpia |
| STAB-009 | P0 | Matriz única de outcomes | Todas las superficies pasan snapshots del mismo contrato |
| STAB-010 | P0 | Fault injection de caché/cobertura | Timeout, parser, truncamiento, corrupción y miss jamás dan falso limpio |
| STAB-011 | P1 | Instalación/repair idempotentes | 30 ciclos y cortes por paso convergen |
| STAB-012 | P1 | Upgrade/rollback N/N−1 | 20 upgrades y 10 rollbacks conservan operación/datos |
| STAB-013 | P1 | IPC y migraciones bajo carrera | Matrices de compatibilidad y 20 procesos sin corrupción/deadlock |
| STAB-014 | P1 | Soak daemon 72 h | Sin zombis, deadlocks ni crecimiento >10 % post-warmup |
| STAB-015 | P1 | Presupuestos de latencia | p50/p95 cumplen en corpus y piloto |
| STAB-016 | P1 | Unificar documentación vigente | README, sitio, UI e instalador generados/verificados desde fuentes únicas |
| STAB-017 | P1 | Recorridos UX críticos | Estados coherentes, accesibles y accionables en terminal/orbe/panel |
| STAB-018 | P1 | Runbooks de operación | Persona ajena resuelve ≥90 % de degradaciones con el mensaje/runbook |
| STAB-019 | P1 | Auditoría independiente | Cero críticos/altos abiertos y regresiones convertidas en tests |
| STAB-020 | P1 | Piloto instrumentado | Gates de 20 devs, 10 repos, 500 commits y 14 días cumplidos |

No se abre STAB-011 en adelante mientras STAB-001 no produzca una línea base
confiable. No se inicia piloto con ningún STAB-00x abierto.

---

## 8. Método de cierre de cada defecto

Cada ticket usa esta plantilla:

1. **Promesa afectada:** principio o gate que se rompe.
2. **Daño observable:** qué ve el usuario y qué ocurrió realmente.
3. **Reproductor:** repo/fixture, comandos y resultado exacto.
4. **Clasificación:** falso limpio, falso bloqueo, fuga, corrupción, UX,
   rendimiento u operabilidad.
5. **Test rojo:** debe fallar por el daño, no por detalles internos.
6. **Causa raíz:** la abstracción o contrato que permitió la clase.
7. **Arreglo:** mínimo que cierra la clase completa.
8. **Mutación:** cómo se rompe a propósito para validar el guardián.
9. **Compatibilidad:** N/N−1, baseline, caché, DB y protocolo.
10. **Observabilidad:** cómo se sabrá si reaparece en producción.
11. **Validación adversarial:** quién, contra qué binario y con qué resultado.
12. **Riesgo residual:** explícito, con dueño y caducidad; nunca escondido en un
    comentario.

Un ticket no se cierra por “los tests pasan”. Se cierra cuando el reproductor
ya no causa daño, la mutación pone rojo el guardián y todas las superficies
dicen la misma verdad.

---

## 9. Documentos obligatorios antes de GA

- Arquitectura y fronteras de confianza vigentes.
- Threat model general, además del específico de rulepacks.
- Política de seguridad y divulgación responsable.
- Inventario/SBOM y procedimiento de release firmado.
- Política de rotación/compromiso de claves.
- Matriz de compatibilidad de Windows y toolchains.
- Guía de instalación, actualización, rollback, repair y desinstalación.
- Runbook por cada estado degradado estable.
- Política de datos: qué se guarda, dónde, retención, exportación y borrado.
- Limitaciones conocidas, especialmente staging parcial y aislamiento de disco
  si no quedaron cerrados por completo.
- Changelog y notas de migración N−1→N.
- Informe del piloto y riesgos residuales aceptados.

Todos deben describir el comportamiento real del binario publicado. Ejemplos,
cifras e inventarios que puedan generarse no se copian manualmente.

---

## 10. Cadencia de trabajo

### Diario

- 15 min: revisar P0, CI y procesos/corridas nocturnas.
- Máximo dos tickets activos.
- Primero reproductor/test; después código.
- Cerrar el día con checkout limpio y evidencia adjunta.

### Dos veces por semana

- Revisión adversarial de los fixes cerrados.
- Ejecutar corpus hostil y suite en máquina limpia.
- Revisar métricas contra presupuestos.
- Eliminar/actualizar documentación que contradiga el binario.

### Semanal

- Release candidate interno firmado y reproducible.
- Upgrade y rollback desde el candidato anterior.
- Soak/nightly, fuzz y auditoría de motores.
- Informe de una página: P0/P1 abiertos, gates, riesgos y decisión go/no-go.

### Regla de go/no-go

Un solo falso verde, fuga P5, corrupción, P0 o diferencia local/CI inexplicada
reinicia la ventana de 14 días. La fecha nunca gana al gate.

---

## 11. Orden recomendado de las próximas cinco tareas

1. **STAB-001:** obtener dos corridas reproducibles y entender los procesos Go
   que sobreviven o tardan de forma anómala.
2. **STAB-003:** retirar `-ApiKey` y probar el canary en todas las superficies.
3. **STAB-002:** decidir y cerrar la diferencia índice/worktree.
4. **STAB-009/STAB-010:** congelar el contrato de outcomes y atacar todos los
   caminos de falso verde mediante fault injection.
5. **STAB-004/STAB-005:** cerrar hashes Python y probar la cadena firmada del
   rulepack como una sola frontera de distribución.

Sólo después conviene abordar aislamiento de escritura, lifecycle completo,
pulido visual y piloto. Este orden prioriza que CodeGuard diga la verdad antes
de hacerlo más cómodo o más rápido.

---

## 12. Definición final de “estable y confiable”

CodeGuard 1.0 GA no significa “no tiene bugs”. Significa:

- sus fallos conocidos no producen un falso verde;
- sus fronteras de confianza están medidas y declaradas;
- el contenido analizado coincide con el contenido prometido;
- su distribución puede verificarse;
- su ciclo de vida converge ante interrupciones;
- su daemon soporta uso prolongado;
- sus mensajes permiten operar sin el autor;
- y esas propiedades fueron observadas en máquinas y repositorios ajenos
  durante una ventana sostenida.

Hasta cumplirlo, la denominación correcta sigue siendo **release candidate**.
