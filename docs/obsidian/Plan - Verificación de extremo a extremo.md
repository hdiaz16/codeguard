# Plan — Verificación de extremo a extremo

El objetivo es poder decir, **con evidencia y no con lectura de código**, que cada pieza está cableada y hace lo que dice. La regla es la misma de toda la casa: *lo que no se mide no se afirma*, y una compuerta que no se ha visto fallar cuando debe fallar no está verificada.

## De dónde partimos

Ya existe el arnés (`internal/pipeline/extremo_a_extremo_test.go`): monta un repo real con una violación deliberada por motor, corre el **binario real** y compara lo declarado contra lo demostrado. Estado medido hoy:

| | motores |
|---|---|
| **CAZÓ** (8) | gitleaks · semgrep · gofmt · govet · staticcheck · ruff · squawk · mypy |
| **NO APLICA** (3) | google-java-format · pmd (sin JDK) · dotnet-format (sin `.csproj`) |
| **SIN PRUEBA** (6) | trivy · govulncheck · tsc · eslint · dotnet-build · dotnet-vuln |

Y el propio arnés dio **tres falsos negativos** antes de servir, lo cual fija el método: se verifica conduciendo el binario, no llamando al pipeline en proceso.

## Lo que este plan añade, y por qué no basta con los motores

Cerrar las seis casillas es necesario pero **no es lo que más pesa**. El arnés mide "¿cada motor ve lo suyo?". El sistema tiene compuertas que no son motores y que, si están mal cableadas, fallan exactamente igual de silenciosas:

- La **baseline** suprime hallazgos. Si suprimiera de más —o suprimiera un secreto— nadie lo notaría: el veredicto sale verde y verde es lo que se espera.
- El **caché** da por bueno un análisis anterior. Si no invalida cuando debe, el veredicto de hoy es el de la semana pasada.
- La **paridad hook/CI** es la promesa central del producto. Nadie la ha comprobado ejecutando las dos rutas sobre el mismo commit.

Por eso el plan va ordenado por **consecuencia si está roto**, no por facilidad.

---

## Fase 1 — Invariantes de seguridad 🔴

Lo que nunca puede pasar, aunque todo lo demás funcione.

### 1.1 · La baseline no puede suprimir un secreto
La especificación dice que los secretos jamás se suprimen ni se degradan (§14, punto 3 de Hardening). **Está afirmado; no está demostrado ejecutando.**

*Prueba*: repo con un secreto, `codeguard baseline` para intentar aceptarlo, y comprobar que el gancho **sigue bloqueando**. Después, meter a mano la huella del secreto en `baseline.txt` y comprobar que tampoco así pasa.

*Por qué importa*: es la única compuerta fail-closed. Si la baseline pudiera taparla, bastaría un `codeguard baseline` distraído para desarmar lo único que no admite discusión.

### 1.2 · La baseline suprime lo preexistente y **sólo** lo preexistente
*Prueba*: repo con dos hallazgos, aceptar uno en la baseline, introducir uno nuevo idéntico en otro archivo, y comprobar que el nuevo bloquea. La huella incluye ruta y contenido de línea: hay que ver que un cambio de línea produce huella distinta.

*Por qué importa*: "sólo lo nuevo bloquea" es lo que hace adoptable el producto. Si la huella fuera demasiado laxa, aceptar un hallazgo aceptaría también los que vengan después.

### 1.3 · El bypass queda registrado
`--no-verify` no ejecuta el gancho, pero `prepare-commit-msg` sí corre.

*Prueba*: commit con `--no-verify` y comprobar que queda rastro en la base local.

*Esfuerzo Fase 1*: 1 día.

---

## Fase 2 — La promesa central: paridad local/CI 🔴

### 2.1 · Mismo commit → mismo veredicto por las dos rutas
*Prueba*: sobre el repo de verificación, correr `hook pre-commit` y `codeguard ci --base X --head Y`, y comparar **hallazgo por hallazgo** (huella, no sólo el número). Las diferencias esperadas están documentadas —trivy y govulncheck bloquean en CI y avisan en local (§7)— así que la prueba las conoce y las exige, en vez de tolerar cualquier diferencia.

*Por qué importa*: "si el commit pasa aquí, pasa allá" es la frase que vende el producto. Nunca se ha comprobado ejecutando las dos.

### 2.2 · El rulepack anclado es el mismo en las dos rutas
*Prueba*: forzar un rulepack ausente y comprobar que las dos rutas lo dicen; y que con el rulepack presente, las dos aplican el mismo número de reglas.

*Esfuerzo Fase 2*: 1,5 días.

---

## Fase 3 — El caché, que puede dar por bueno lo viejo 🟠

### 3.1 · Acierta cuando debe
*Prueba*: dos corridas seguidas sin tocar nada → la segunda mucho más rápida y **con hallazgos idénticos**. Comprobar los dos: un caché que acierta y devuelve otra cosa es peor que uno que no acierta.

### 3.2 · Invalida cuando debe — cuatro ejes, uno por uno
El caché lleva en su clave contenido + rulepack + hash de config + **versión de CodeGuard** (§9). Cada eje se prueba por separado, porque tres de cuatro funcionando se ve igual que cuatro:

1. cambiar el contenido del archivo,
2. cambiar la versión del rulepack,
3. cambiar la config del repo,
4. cambiar la versión del binario.

*Por qué importa*: si el eje de la versión no invalidara, actualizar CodeGuard dejaría vigentes los veredictos del binario anterior — justo lo que la actualización pretende corregir.

*Esfuerzo Fase 3*: 1 día.

---

## Fase 4 — Cerrar las seis casillas SIN PRUEBA 🟠

Ordenadas por lo que cuesta montarlas.

### 4.1 · dotnet-format y dotnet-build (el SDK ya está instalado)
Un `.csproj` mínimo con un `.cs` mal formateado y otro que no compila. Riesgo conocido: `dotnet build` puede decir "limpio" cuando MSBuild lo considera al día — por eso el motor usa `-t:Rebuild`, y la prueba debe correr **dos veces** para confirmar que la segunda también ve el error.

### 4.2 · trivy y dotnet-vuln
Necesitan un manifiesto con una dependencia vulnerable **real y fijada por versión**. Se elige una con CVE público y antiguo (no una reciente, que puede desaparecer del feed). La prueba se salta sin red, y lo dice.

### 4.3 · govulncheck
Además del manifiesto, hace falta que el código **llame** al símbolo vulnerable: govulncheck reporta por alcanzabilidad, así que un fixture que sólo declare la dependencia demostraría lo contrario de lo que queremos.

### 4.4 · tsc
`tsconfig.json` + un error de tipos. Requiere `typescript` instalado; hoy hay node pero no tsc. Decidir si se instala en la máquina de CI del arnés o la casilla se queda documentada.

### 4.5 · eslint
Es el más caro: exige `node_modules`. **Alternativa a evaluar primero**: el motor corre eslint *o* biome, y biome es un binario único sin `node_modules`. Si biome basta para demostrar el cableado, la prueba cuesta una décima parte.

*Esfuerzo Fase 4*: 2–3 días, y depende de red.

---

## Fase 5 — Las rutas que nadie ha ejercitado 🟡

### 5.1 · Con daemon y sin daemon dan lo mismo
El daemon acelera; no debe cambiar el veredicto. *Prueba*: misma corrida con el daemon arriba y abajo, comparando hallazgos.

### 5.2 · `prepare-commit-msg` y `post-commit`
Existen y se instalan; no se han ejercitado en una prueba.

### 5.3 · La capa LLM nunca bloquea y redacta antes de enviar
*Prueba*: con la capa encendida, un repo con secretos y datos personales; comprobar que (a) el veredicto no cambia por lo que diga el modelo y (b) lo que se envía va redactado. Esto último se comprueba interceptando la llamada, no confiando en que la función existe.

*Esfuerzo Fase 5*: 2 días.

---

## Lo que NO se va a poder verificar así, y hay que decirlo

- **La interfaz** (orbe, panel, tooltips): se verifica mirándola. Ninguna prueba automática dice que el orbe se ve bien.
- **La telemetría central**: el mecanismo está probado, pero sin un Postgres real no hay extremo a extremo posible. Depende de una decisión tuya, no de código.
- **El instalador y la firma**: se verifican instalando en una máquina limpia.
- **La calibración (§17)**: necesita 500+ hallazgos votados. No es verificable, es acumulable.

Decirlo importa: un informe que presenta 20 casillas verdes y calla las cuatro que no se pueden medir vale menos que uno que enseña las 24.

---

## Orden propuesto y criterio de cierre

1. **Fase 1** (invariantes de seguridad) — 1 día
2. **Fase 2** (paridad local/CI) — 1,5 días
3. **Fase 3** (caché) — 1 día
4. **Fase 4** (las seis casillas) — 2–3 días
5. **Fase 5** (rutas sin ejercitar) — 2 días

**Criterio de cierre de cada fase**: la prueba existe, pasa, **y se ha comprobado que falla cuando debe fallar** — revirtiendo el arreglo o rompiendo la condición a propósito. Sin ese segundo paso una prueba verde no significa nada, que es la lección que dejó el escáner de la cadena de suministro firmando "limpio" sin mirar un solo archivo.

Relacionado: [[Plan - Remediación y cobertura]] · [[Hardening]] · [[Arquitectura]]
