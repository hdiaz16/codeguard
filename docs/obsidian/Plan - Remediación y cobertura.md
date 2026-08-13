# Plan — Remediación y cobertura

Dos cosas distintas en un solo documento, porque se financian con el mismo tiempo:

1. **Remediación**: las debilidades **del propio CodeGuard** que siguen abiertas.
2. **Cobertura**: qué vulnerabilidades del código ajeno detectamos y cuáles no.

Todo lo que dice este documento está **medido**, y donde no se ha medido lo dice. La regla es la de la casa: *lo que no se mide no se afirma*.

---

# Parte 1 — Remediación de nuestras debilidades

Ordenadas por lo que costaría si alguien las explota, no por lo fácil que sean de arreglar.

## R1 · La API key vive en un sitio que otro programa puede leer 🔴

**Qué pasa**: la clave del modelo se guarda en `HKCU\Environment`. Cualquier proceso corriendo como el usuario la lee sin pedir permiso a nadie.

**Por qué importa más de lo que parece**: el entorno acotado (42 variables retenidas) impide que la clave baje a los motores. Eso protege hacia abajo. No protege hacia el lado: un `.exe` que el usuario abra de un correo la lee igual.

**Arreglo**: Windows Credential Manager (`CredRead`/`CredWrite`), con `CRED_TYPE_GENERIC` y persistencia local. La lectura la hace sólo el daemon, y la pantalla de configuración escribe ahí en vez de en el registro.

**Cuidado con**: el arreglo tiene una trampa conocida — hoy `RefrescarVariables()` existe justamente porque la clave *no* llegaba al daemon tras reiniciar, y la capa LLM estuvo dormida por eso sin que nadie lo notara. Migrar sin cerrar ese camino repite el fallo. La migración tiene que leer del Credential Manager **y**, si no hay nada, del registro, avisando de que hay que migrar.

**Esfuerzo**: 1 día. **Bloqueado por**: nada.

## R2 · El instalador sin firmar dispara el EDR 🔴

**Qué pasa**: `A suspicious file was observed`, severidad Medio, cada vez que se construye o instala. El patrón —sin firmar, recién creado, empaquetado, suelta un `.tmp` y lo lanza, arrancado desde una shell— es punto por punto la silueta de un *dropper*, y el EDR no tiene con qué distinguirlo.

**Por qué importa**: no es sólo ruido. Es (a) que Seguridad puede bloquear el despliegue el día que escale una de esas alertas, (b) que Windows avisa "editor desconocido" en cada máquina nueva, y (c) que **sin firma no hay winget, y sin winget no hay actualización de flota** — que es lo que bloquea R4.

**Arreglo**: certificado de firma de código (OV o EV). El `.iss` ya tiene la línea prevista.

**Esfuerzo**: trámite, no código. **Bloqueado por**: decisión de Héctor.

## R3 · El sandbox no restringe la escritura 🟠

**Qué pasa**: las tres capas (entorno acotado, token sin privilegios, Job Object) están medidas y funcionan — 5 privilegios fuera, 1 dentro; el job mata a los nietos, comprobado contra su control. Lo que **no** hay es restricción del sistema de archivos. Un motor comprometido escribe donde el usuario pueda escribir.

**Por qué importa**: para una herramienta que corre en cada commit, escribir es el verbo que importa. Un motor que modifica el código *después* de analizarlo pasa la compuerta y entra al repositorio.

**Arreglo**: token *write-restricted* (`CreateRestrictedToken` con `WRITE_RESTRICTED` y un SID restrictivo). Las lecturas quedan intactas —el motor necesita leer el repo— y las escrituras sólo valen donde ese SID esté en la ACL.

**Por qué no es un parche de una tarde**: varios motores escriben caché. Dentro del repo: `.mypy_cache`, `__pycache__`, la de ruff, la de semgrep. Fuera: `GOCACHE`, `GOMODCACHE`, caché de npm, base de trivy. **Cada ruta hay que enumerarla y darle ACL**, y la que se olvide falla de la peor manera: el motor no puede escribir, se cae, y la capa sale como degradada — es decir, dejamos de revisar algo y el aviso es una línea que nadie lee.

**Primer paso, y es medición**: instrumentar una corrida completa con Process Monitor filtrando por escrituras de cada motor, y sacar la lista real. No la lista que creemos.

**Esfuerzo**: 1 semana con la medición delante. **Bloqueado por**: nada, pero conviene hacerlo después de R2 (romper motores en las máquinas del equipo sin poder desplegar el arreglo rápido es mala combinación).

**Límite que no depende de nosotros**: la ventana entre arrancar el proceso y meterlo en el job no se cierra desde `os/exec` — Go no expone `ProcThreadAttributeList` en Windows, así que `PROC_THREAD_ATTRIBUTE_JOB_LIST` queda fuera. La salida limpia es un lanzador intermedio ya dentro del job: todo lo que cree un proceso de un job nace dentro de él. Cuesta un proceso extra por motor.

## R4 · Una máquina que no actualiza corre motores viejos para siempre 🟠

**Qué pasa**: el anclaje de versiones garantiza que dos instalaciones **nuevas** coincidan. No hace nada por la máquina que instaló hace tres meses: sigue con gitleaks 8.30.0 mientras el CI usa 8.30.1, y **nada lo compara**.

**Por qué importa**: erosiona la promesa central del producto —*si el commit pasa aquí, pasa allá*— de la peor forma posible: intermitente, y meses después.

**Arreglo, en dos mitades**:
- *Detectar*: que el informe registre las versiones de motor que produjeron cada veredicto, y que el CI compare las suyas con las de la última corrida local del repo. Barato y suficiente para saber que existe el problema.
- *Corregir*: winget, que necesita R2.

**Esfuerzo**: 2 días la detección. **Bloqueado por**: R2 para la corrección.

## R5 · Un repo anclado a un rulepack retirado analiza con cero reglas 🟠

**Qué pasa**: el rulepack va anclado por repo en `.codeguard/config.yaml` y es obligatorio. Si apunta a una versión que ya no se distribuye, degrada a transparente: las 119 reglas de la casa se saltan, y lo único que lo dice es una línea de *capas no revisadas*. `codeguard repair` mueve el ancla — pero sólo si alguien lo corre.

**Por qué importa**: es el fallo que ya ocurrió en bds.portal, y es la forma canónica del problema que este proyecto persigue: **una compuerta que aparenta revisar y no revisa**.

**Arreglo**: que el hook detecte el ancla rota y lo diga como advertencia destacada del veredicto —no como una línea más—, con la orden exacta para arreglarlo. Y que `codeguard status` lo saque en primera línea.

**Esfuerzo**: medio día. **Bloqueado por**: nada. Es lo más barato de esta lista y de las que más pesa.

## R6 · La compuerta del CI no obliga 🟠

**Qué pasa**: el CI corre en `--shadow`. Un control que no impide nada no es un control, y es lo primero que mira un auditor de la 27001.

**Bloqueado por**: la calibración (§17), que necesita **2+ semanas y 500+ hallazgos etiquetados**, y va por **0 votos**. Sin precisión medida, quitar el `--shadow` es apostar la confianza del equipo a que no haya una racha de falsos positivos la primera semana.

**Esfuerzo**: el trabajo es votar en el panel. Nada de código.

## R7 · Las excepciones de baseline no tienen dueño, motivo ni caducidad 🟡

**Qué pasa**: `baseline.txt` son huellas sueltas. Irónicamente el esquema **ya tiene** las columnas `reason`, `scope` y `expires_at` (migrations/001) sin usar.

**Arreglo**: exactamente el mismo mecanismo que ya funciona en `excepciones.json` para los CVE de los motores — firma, motivo, caducidad, y se imprimen enteras. El diseño está probado; es portarlo.

**Esfuerzo**: 2 días. **Bloqueado por**: nada. Es el hueco más barato de la 27001.

## R8 · Los registros son locales y borrables 🟡

**Qué pasa**: SQLite en `%LOCALAPPDATA%`, que el propio dev puede borrar. El bypass **sí** se registra —`--no-verify` no nos oculta el salto, y eso es una fortaleza real— pero nadie lo revisa: no hay informe ni umbral.

**Arreglo**: la telemetría central ya está construida y probada (marca de agua ULID, idempotente, reanudable). Falta un DSN.

**Bloqueado por**: decidir dónde vive el Postgres.

---

# Parte 2 — Cobertura de las vulnerabilidades más explotadas

## Lo que hay hoy, medido

`rulepacks/2026.08.2` tiene **119 reglas**, de las cuales **67 son de seguridad**. Al empezar este plan, **18 de esas 67 no llevaban CWE**: es decir, no se podía responder *"¿cubrimos X?"* sin leerse las reglas una por una, y la matriz de cobertura salía con huecos falsos (SQL injection aparecía sin cubrir en Go teniendo `go-sql-concat`). **Ya están las 67 etiquetadas** con CWE y OWASP; el escaneo del corpus da 171 hallazgos antes y después, o sea que el etiquetado no cambió ni una detección.

Cobertura real, por CWE y lenguaje (`·` = sin regla):

| CWE | py | ts | js | go | java | c# |
|---|---|---|---|---|---|---|
| CWE-22 · path traversal / zip-slip | 1 | 1 | 1 | 1 | 1 | · |
| CWE-78 · inyección de comandos | 1 | 1 | 1 | 1 | 1 | 1 |
| CWE-79 · XSS | · | 1 | 1 | · | 1 | · |
| CWE-89 · inyección SQL | 2 | 2 | 2 | 2 | 1 | 2 |
| CWE-95 · inyección de código (eval) | 1 | 1 | 1 | · | 1 | 1 |
| CWE-295 · validación de certificado | 1 | 1 | 1 | 1 | 1 | 1 |
| CWE-327 · criptografía débil | 1 | 1 | 1 | 1 | 1 | 1 |
| CWE-338 · PRNG débil | 1 | 1 | 1 | 1 | 1 | 1 |
| CWE-347 · firma JWT sin verificar | 1 | 1 | 1 | 1 | 1 | 1 |
| CWE-489 · depuración en producción | 1 | 1 | 1 | · | · | · |
| CWE-502 · deserialización insegura | 2 | 1 | 1 | · | 1 | 1 |
| CWE-611 · XXE | 1 | · | · | · | 1 | 1 |
| CWE-614 / 1004 · cookies sin flags | 1 | 1 | 1 | · | · | 1 |
| CWE-798 · credenciales en el código | 2 | 2 | 1 | 2 | 2 | 2 |
| CWE-829 · acción de CI sin SHA | *(yaml)* | | | | | |
| CWE-918 · SSRF | 1 | 1 | 1 | · | · | · |
| CWE-942 · CORS permisivo | 1 | 2 | 2 | 1 | 2 | 2 |

**18 CWE distintos.** Y los motores aportan dos clases más que no son reglas: **dependencias vulnerables** (trivy + govulncheck con alcanzabilidad de símbolo) y **secretos filtrados** (gitleaks, fail-closed).

## Contra qué se compara

La referencia es el **CWE Top 25** cruzado con lo que de verdad se explota en la calle (catálogo KEV de CISA). Dos advertencias honestas:

- La edición del Top 25 que uso puede no ser la vigente; **confírmala en cwe.mitre.org** antes de enseñar esta tabla fuera del equipo. Las posiciones se mueven cada año, pero los huecos de abajo no dependen del orden.
- Buena parte del Top 25 es **memoria** (CWE-787, 125, 416, 119, 476): desbordamientos, uso después de liberar, lectura fuera de rango. **No aplican a nuestro alcance**: CodeGuard cubre Python, TS/JS, Go, Java y C#, que son lenguajes con memoria gestionada, y no soportamos C/C++. Eso no es un hueco, es el alcance — pero hay que decirlo, porque si no la tabla parece que suspende y no es verdad.

## Los huecos reales

### Hueco A · Nada de autorización ni autenticación 🔴
**CWE-862 / 863 / 306 / 287.** Cero reglas. Es, junto a la inyección, lo que más aparece en brechas reales: un endpoint que se olvidó de comprobar quién llama.

Es la clase más difícil para análisis estático porque exige conocer el framework. Pero hay patrones tratables y de altísimo valor:
- ASP.NET: controlador o acción sin `[Authorize]` cuando el resto del controlador sí lo tiene.
- Express: `router.<verbo>` que no pasa por el middleware de auth del propio repo.
- Django/Flask: vista sin `@login_required` / `@permission_required`.
- Spring: `@RestController` sin `@PreAuthorize` donde sus hermanos sí lo llevan.

La forma de que no sea ruido es **la comparación con el propio repo**: no "falta `[Authorize]`" en abstracto, sino "los otros 14 métodos de este controlador lo llevan y este no". Eso es una regla con contexto y una tasa de falsos positivos manejable.

### Hueco B · CSRF 🔴
**CWE-352.** Cero reglas — la palabra "csrf" sólo aparece dentro de un regex de PRNG débil. Detectable: formularios sin token, `SameSite=None` sin justificación, deshabilitar la protección del framework (`@csrf_exempt`, `.DisableCsrf()`, `csurf` ausente).

### Hueco C · Subida de archivos sin restringir 🟠
**CWE-434.** Cero reglas. Guardar lo subido bajo la raíz web, sin validar tipo real, o usando el nombre que manda el cliente. Patrones concretos y baratos en los cinco lenguajes.

### Hueco D · Redirección abierta y SSTI 🟠
**CWE-601 y CWE-1336.** Cero reglas. Redirigir a un destino que viene del request; plantilla construida por concatenación (Jinja2, Razor, Thymeleaf, template literals).

### Hueco E · ReDoS 🟠
**CWE-1333.** Cero reglas, y es de los que más caen en producción sin que nadie los llame "seguridad": una expresión regular con anidamiento cuantificado sobre entrada del usuario cuelga el proceso. Encaja con la clase que ya sabemos manejar (el plazo por motor).

### Hueco F · Inyecciones que faltan 🟡
**CWE-90 (LDAP), CWE-943 (NoSQL), CWE-1236 (CSV/fórmulas).** Tenemos SQL y comandos; faltan las primas. NoSQL importa con Mongo (`$where`, `$regex` con dato del usuario).

### Hueco G · Asimetrías dentro de lo que ya cubrimos 🟠
Esto es lo que la matriz destapó y es el hallazgo más útil de todo el ejercicio: **el trabajo de paridad de lenguajes cubrió los motores, no las reglas**. Un repo de C# tiene los mismos motores que uno de Python, pero no las mismas reglas:

- **XSS (CWE-79)**: sólo ts/js y Java. Faltan Python (`mark_safe`, `|safe`, `render_template_string`) y C# (`Html.Raw`, `HtmlString`).
- **Path traversal (CWE-22)**: falta C#.
- **SSRF (CWE-918)**: faltan Go, Java y C#.
- **XXE (CWE-611)**: falta Go (y ts/js, aunque ahí es menos común).
- **Cookies sin flags**: faltan Go y Java.
- **Depuración en producción**: faltan Go, Java y C#.

Cerrar estas es lo más barato de toda la Parte 2: las reglas ya existen y están probadas en otro lenguaje; es portarlas con su positivo y su negativo en el corpus.

## Plan por olas

Cada regla nueva entra **con su par de fixtures** en el corpus (positivo y negativo). Sin eso no entra: el corpus ya cazó 5 reglas muertas de nacimiento, y una regla que no dispara es una compuerta que aparenta cubrir y no cubre.

**Ola 1 — cerrar asimetrías** (~15 reglas). Portar XSS, path traversal, SSRF, XXE, cookies y debug a los lenguajes que les faltan. Bajo riesgo: patrones ya validados. *Estimado: 3 días.*

**Ola 2 — lo que más se explota y no tenemos** (~12 reglas). CSRF y subida de archivos en los cinco lenguajes, redirección abierta, ReDoS. *Estimado: 4 días.*

**Ola 3 — autorización** (~10 reglas). El hueco A, con la comparación contra el propio repo. **Esta ola va detrás de la calibración**, y no por capricho: es la clase con más riesgo de falsos positivos, y meterla con 0 votos de precisión medida es la mejor forma de que el equipo aprenda a ignorar el panel. *Estimado: 1 semana.*

**Ola 4 — inyecciones restantes y SSTI** (~8 reglas). LDAP, NoSQL, CSV, plantillas. *Estimado: 3 días.*

## Y la regla que se aplica a todo esto

Ninguna ola cuenta como cerrada por haber escrito las reglas. Cuenta cuando el corpus pasa con ellas dentro **y** cuando alguien comprueba que cazan sobre código real. Es la misma lección que dejó la auditoría de la cadena, que estuvo meses firmando "limpio" sin mirar un solo archivo: **entre "está limpio" y "no miré" no hay diferencia visible desde fuera, sólo una prueba que falle cuando debe fallar.**

Relacionado: [[Hardening]] · [[Pilares y reglas]] · [[Plan - Motor avanzado]] · [[Plan - Paridad de lenguajes]]
