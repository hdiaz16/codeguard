# Hardening

Las reglas de seguridad **del propio agente**. La regla de oro: *un CodeGuard roto degrada a transparente, nunca a candado* — salvo secretos.

## Implementadas y verificadas ✅

1. **Redacción P5**: todo diff/snippet se redacta antes de tocar el LLM (9 familias de patrones, con tests)
2. **Secretos primero, offline, fail-closed** — antes de cualquier red
3. **Los secretos jamás se suprimen ni degradan** (ni baseline ni feedback)
4. **Lectura confinada al repo** — rutas `../../` no escapan
5. **Pipe con SID + DACL** de solo-usuario
6. **API key en el Administrador de credenciales** — nunca repo/BD/logs, y desde la Ola R1 tampoco en `HKCU\Environment`: se lee en el momento de usarla y la copia vieja se migra y se borra al arrancar el daemon. No es una frontera frente a código que corre como el mismo usuario, pero sale del texto plano y deja de heredarse a cada proceso hijo
7. **El LLM nunca ejecuta ni bloquea** — sin camino prompt-injection → acción
8. **El daemon sin credenciales de git** — no puede commitear/pushear
9. **Todo texto de terceros escapado en la UI** (sin XSS)
10. **staticcheck 0 hallazgos · gosec triado · tests de contrato verdes**

11. **Motores por hash fijado** — `motores.json` con SHA-256 del artefacto real; `codeguard engines` lo recomprueba en cada máquina, y el instalador verifica el zip **antes** de extraer
12. **Escáneres en Job Object + token restringido** — medido, no supuesto: 5 privilegios fuera → 1 dentro (sólo `SeChangeNotify`, que hace falta para recorrer directorios). El job mata a los nietos: se comprobó con un nieto desligado, y contra el control de que **sin** job sobrevive
13. **Entorno por lista de permitidos** — 42 variables retenidas en una máquina típica; la API key del modelo no llega a ningún motor. Lista de permitidos y no de prohibidos: una de prohibidos deja pasar el siguiente secreto que alguien añada
14. **Auditoría de nuestra propia cadena** — `engines --auditar` escanea con trivy lo que repartimos, y tumba el CI si hay crítico/alto sin aceptar. Con control que falla (un Log4Shell de prueba): un escáner ciego y uno sano dan la misma salida cuando no hay nada que encontrar
15. **Riesgos aceptados con firma y caducidad** — `excepciones.json`: sin `aceptada_por` no aplican, caducan solas, y se imprimen enteras en cada ejecución
16. **Vigía semanal** (`.github/workflows/motores.yml`) — un CVE nuevo en una versión ya fijada no espera a que empujemos código
17. **El informe no declara terminado lo que no revisó** — `COMPLETADO` exige que no queden bloqueantes **y** que todas las capas hayan corrido; si no, dice `PARCIAL` con qué faltó. Importa porque `HALLAZGOS.md` es el archivo que se le entrega a un agente de código como criterio de terminado

## Cobertura frente a lo que más se explota

78 reglas de seguridad, **las 78 con CWE y OWASP** — sin eso no se puede responder "¿cubrimos X?" sin leerlas una por una, y la matriz salía con huecos falsos. Cubren **18 CWE distintos**, más dos clases que no son reglas sino motores: dependencias vulnerables (trivy + govulncheck con alcanzabilidad de símbolo) y secretos (gitleaks, fail-closed).

Los huecos **medidos**, no supuestos: autorización y autenticación (CWE-862/863/306/287, cero reglas), CSRF (CWE-352, cero), subida de archivos (CWE-434), redirección abierta y SSTI, ReDoS, y las inyecciones primas (LDAP, NoSQL, CSV). Un hallazgo que sólo apareció al mirar la matriz por lenguaje: **el trabajo de paridad cubrió los motores, no las reglas** — un repo de C# corría los mismos motores que uno de Python sin una sola regla de XSS, path traversal ni SSRF. **Cerrado** con la Ola 1 (11 reglas): esas cuatro clases ya no tienen asimetrías en los seis lenguajes.

Lo que **no** aplica y conviene decirlo para que la tabla no parezca suspender: buena parte del CWE Top 25 es memoria (787, 125, 416, 119, 476). CodeGuard cubre Python, TS/JS, Go, Java y C# —lenguajes con memoria gestionada— y no soporta C/C++. Eso es el alcance, no un hueco.

El detalle, la matriz completa y el plan por olas: **[[Plan - Remediación y cobertura]]**.

## Pendientes ⏳

18. **Cero elevación** — jamás admin
19. **Firma de código** — trámite del certificado. Mientras tanto el EDR marca el instalador como sospechoso, y con razón: sin firma es indistinguible de un dropper
20. **Restricción de escritura en el sandbox** — hoy no se restringe el sistema de archivos. Ver abajo
21. Telemetría central: metadatos y fingerprints, **nunca código** (fase 5)

## El sandbox: lo que hace y lo que no

Tres capas, ninguna es una máquina virtual: entorno acotado, token sin privilegios, y Job Object con tope de memoria (4 GB), de procesos (64) y sin acceso a portapapeles, escritorio ni ventanas ajenas.

**Lo que NO hace: restringir el sistema de archivos.** Un motor comprometido puede leer cualquier cosa que el usuario pueda leer, y **escribir** también. Para una herramienta que corre en cada commit, escribir es el verbo que importa.

El siguiente paso real es un **token write-restricted** (`CreateRestrictedToken` con `WRITE_RESTRICTED` y un SID restrictivo): las lecturas siguen intactas —el motor necesita leer el repo— y las escrituras sólo se permiten donde ese SID esté en la ACL. Lo que lo convierte en un proyecto y no en un parche es que varios motores escriben caché *dentro* del repo: `.mypy_cache`, `__pycache__`, la caché de ruff, la de semgrep, y los caches de Go y npm fuera de él. Cada uno hay que enumerarlo y darle ACL, y el que se olvide falla de la peor manera: el motor no puede escribir, se cae, y la capa aparece como degradada.

La ventana entre `Start` y `AssignProcessToJobObject` no se puede cerrar desde `os/exec`: Go no expone `ProcThreadAttributeList` en Windows, así que `PROC_THREAD_ATTRIBUTE_JOB_LIST` —que asignaría el job en la creación— queda fuera. La salida limpia es un lanzador intermedio ya dentro del job: todo lo que cree un proceso de un job nace dentro de ese job, sin ventana. Cuesta un proceso extra por motor.

Relacionado: [[Arquitectura]] · [[Capa LLM]]
