/* ══════════════════════════════════════════════════════════════════════════
   La demo animada.

   Esto NO es un vídeo. No hay grabación de pantalla ni archivo de vídeo en
   ninguna parte: es el DOM reconstruyendo el camino de un commit bloqueado
   —terminal, orbe, capas, panel— con un guion de pasos temporizados.

   Se hizo así por dos razones, y la segunda pesa más:
     · aquí no hay forma de grabar la pantalla ni de generar un vídeo;
     · un vídeo de 30 s pesa megas, se ve borroso en una pantalla grande, no
       se puede leer con un lector de pantalla y envejece a la primera vez
       que cambia un texto del producto. Esto pesa unos kilobytes, es texto
       de verdad y sale de la misma fuente de datos que el resto del sitio.

   Los textos son los del producto: el ejemplo de bloqueo del README, con sus
   cuatro reglas, que existen en el rulepack 2026.08.2.
   ══════════════════════════════════════════════════════════════════════════ */

import { crearOrbe } from "./orbe.js";
import { DEMO } from "./datos.js";

/** Escapa texto que va a insertarse como HTML. */
function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

/* ── El guion. Cada paso es {en: ms, hacer: fn}. Los tiempos son absolutos
      desde el arranque, así que reposicionar la reproducción es exacto. ── */

const HALLAZGOS = [
  {
    regla: "gha-action-sin-sha",
    archivo: ".github/workflows/ci.yml",
    linea: 7,
    mensaje: "Acción anclada por etiqueta, no por SHA",
    pilar: "seguridad",
    porque: "Una etiqueta se puede reescribir para apuntar a otro commit; un SHA no. Es la vía de entrada a la cadena de suministro del CI.",
    codigo: [
      { n: 6, t: "      steps:" },
      { n: 7, t: "        - uses: actions/checkout@v4", culpable: true },
      { n: 8, t: "        - run: npm ci" },
    ],
  },
  {
    regla: "lockfile-ausente",
    archivo: "package.json",
    linea: 1,
    mensaje: "package.json cambió y el proyecto no tiene lockfile",
    pilar: "calidad",
    porque: "Sin lockfile, tu máquina y el CI resuelven versiones distintas de las mismas dependencias. La paridad se rompe antes de empezar.",
    codigo: [
      { n: 1, t: '{', culpable: true },
      { n: 2, t: '  "name": "ejemplo-web",' },
      { n: 3, t: '  "dependencies": { "pg": "^8.13.0" }' },
    ],
  },
  {
    regla: "orm-raw-interpolado-ts",
    archivo: "src/api.ts",
    linea: 2,
    mensaje: "Consulta cruda del ORM con plantilla interpolada",
    pilar: "seguridad",
    porque: "La plantilla mete el valor en el texto del SQL antes de que la base lo vea. Con parámetros, el valor nunca llega a ser sintaxis.",
    codigo: [
      { n: 1, t: "export async function buscar(termino: string) {" },
      { n: 2, t: "  return db.$queryRawUnsafe(`SELECT * FROM docs WHERE t = '${termino}'`)", culpable: true },
      { n: 3, t: "}" },
    ],
  },
  {
    regla: "cookie-sin-httponly",
    archivo: "src/api.ts",
    linea: 3,
    mensaje: "Cookie de sesión sin httpOnly",
    pilar: "seguridad",
    porque: "Sin httpOnly, cualquier script de la página puede leer la cookie de sesión. Un XSS deja de ser una molestia y pasa a ser una sesión robada.",
    codigo: [
      { n: 2, t: "res.cookie('sid', token, {" },
      { n: 3, t: "  secure: true, sameSite: 'lax'", culpable: true },
      { n: 4, t: "});" },
    ],
  },
];

export function montarDemo({ reducido }) {
  const tablero = document.getElementById("demo-tablero");
  const cuerpo = document.getElementById("terminal-cuerpo");
  const panel = document.getElementById("demo-panel");
  const veredicto = document.getElementById("panel-veredicto");
  const meta = document.getElementById("panel-meta");
  const panelCuerpo = document.getElementById("panel-cuerpo");
  const cajaOrbe = document.getElementById("demo-orbe");
  const botonPlay = document.getElementById("demo-play");
  const textoPlay = document.getElementById("demo-play-texto");
  const iconoPlay = botonPlay?.querySelector(".icono-play");
  const iconoPausa = botonPlay?.querySelector(".icono-pausa");
  const botonReiniciar = document.getElementById("demo-reiniciar");
  const barra = document.getElementById("demo-progreso-barra");
  if (!tablero || !cuerpo) return;

  const orbe = crearOrbe({ tam: 76, estado: "idle", aura: true, burbuja: true });
  cajaOrbe.appendChild(orbe.el);

  // ── utilidades de la terminal ────────────────────────────────────────────
  function fila(html, clase = "") {
    const el = document.createElement("div");
    el.className = "fila " + clase;
    el.innerHTML = html;
    cuerpo.appendChild(el);
    cuerpo.scrollTop = cuerpo.scrollHeight;
    return el;
  }
  function cg(html, clase = "") {
    return fila(`<span class="prefijo">CodeGuard </span>${html}`, clase);
  }

  let filaEscribiendo = null;
  function tecleando(texto, indice) {
    if (!filaEscribiendo) {
      filaEscribiendo = fila(`<span class="cmd"><span class="sigil">❯</span><span class="letras"></span><span class="cursor"></span></span>`);
    }
    filaEscribiendo.querySelector(".letras").textContent = texto.slice(0, indice);
  }
  function terminarTecleo() {
    if (!filaEscribiendo) return;
    filaEscribiendo.querySelector(".cursor")?.remove();
    filaEscribiendo = null;
  }

  // ── el panel ─────────────────────────────────────────────────────────────
  function pintarHallazgo(h) {
    const el = document.createElement("article");
    el.className = "hallazgo";
    el.innerHTML = `
      <div class="hallazgo-cabeza">
        <span class="regla">${esc(h.regla)}</span>
        <span class="msg">${esc(h.mensaje)}</span>
        <span class="pilar ${esc(h.pilar)}">${esc(h.pilar)}</span>
      </div>
      <div class="hallazgo-cuerpo">
        <p class="ruta">${esc(h.archivo)}:${h.linea}</p>
        <div class="pozo">${h.codigo
          .map((l) => `<span class="ln${l.culpable ? " culpable" : ""}"><span class="num">${l.n}</span>${esc(l.t)}</span>`)
          .join("")}</div>
        <p class="porque"><b>Por qué importa.</b> ${esc(h.porque)}</p>
      </div>`;
    panelCuerpo.appendChild(el);
  }

  // ── el guion ─────────────────────────────────────────────────────────────
  const COMANDO = 'git commit -m "cache de sesiones en el borde"';
  const pasos = [];
  let t = 0;

  const push = (espera, hacer) => { t += espera; pasos.push({ en: t, hacer }); };

  // 1· se teclea el commit
  for (let i = 1; i <= COMANDO.length; i++) {
    push(i === 1 ? 500 : 26, () => tecleando(COMANDO, i));
  }
  push(340, () => {
    terminarTecleo();
    orbe.estado("working");
    orbe.susurrar("revisando tu cambio", { permanente: true });
  });

  // 2· la compuerta de secretos
  push(420, () => cg('<span class="tenue">etapa 1 · secretos (offline, fail-closed)</span>'));
  push(760, () => cg('secretos <span class="ok">✓</span>'));

  // 3· las capas encendiéndose. Sólo las que de verdad aplican a estos
  //    archivos: ver el porqué en DEMO, en datos.js.
  const listaCapas = document.createElement("div");
  push(260, () => {
    cg(`<span class="tenue">etapa 2 · ${DEMO.aplican.length} capas aplican a este cambio</span>`);
    listaCapas.className = "fila tenue";
    cuerpo.appendChild(listaCapas);
  });
  DEMO.aplican.forEach((motor, i) => {
    push(300 + (i % 3) * 90, () => {
      listaCapas.innerHTML = `<span class="prefijo">CodeGuard </span>` +
        DEMO.aplican.slice(0, i + 1).map((m) => `<span class="ok">${esc(m)} ✓</span>`).join(" · ");
      cuerpo.scrollTop = cuerpo.scrollHeight;
      orbe.susurrar(`${i + 1} de ${DEMO.aplican.length} capas`, { permanente: true });
    });
  });
  // «no aplica» no es lo mismo que «no corrió», y decirlo es la mitad del
  // producto: sin esta línea, once capas calladas se leen como once huecos.
  push(360, () => {
    cg(`<span class="tenue">${DEMO.noAplican} capas no aplican — ${esc(DEMO.motivoNoAplican)}</span>`);
  });

  // 4· el veredicto
  push(520, () => {
    cg('formato/lint/tipos/reglas/migraciones <span class="mal">✗</span>');
  });
  HALLAZGOS.forEach((h) => {
    push(230, () => {
      cg(`  <span class="regla">[${esc(h.regla)}]</span> ${esc(h.archivo)}:${h.linea}  ${esc(h.mensaje)}`);
    });
  });
  push(400, () => {
    cg('<span class="mal">BLOQUEADO: 4 problema(s) que el CI también rechazaría</span>');
    orbe.estado("blocked");
    orbe.susurrar("espera, hay algo", { permanente: true });
  });

  // 5· el panel florece desde el orbe
  push(520, () => {
    panel.setAttribute("aria-hidden", "false");
    panel.classList.add("abierto");
    veredicto.textContent = "4 problemas detienen el commit";
    veredicto.className = "panel-veredicto block";
    meta.textContent = `${DEMO.repo} · ${DEMO.rama} · ${DEMO.archivos} archivos`;
  });
  HALLAZGOS.forEach((h) => {
    push(260, () => pintarHallazgo(h));
  });

  push(900, () => {
    cg('<span class="tenue">el commit no existe: corrige y vuelve a intentarlo</span>');
    orbe.susurrar("espera, hay algo", { permanente: true });
  });

  const DURACION = t + 1400;

  // ── motor de reproducción ────────────────────────────────────────────────
  let inicio = 0;
  let transcurrido = 0;
  let corriendo = false;
  let cuadro = null;
  let siguiente = 0;

  function limpiar() {
    cuerpo.replaceChildren();
    panelCuerpo.replaceChildren();
    panel.classList.remove("abierto");
    panel.setAttribute("aria-hidden", "true");
    veredicto.textContent = "esperando el primer análisis…";
    veredicto.className = "panel-veredicto";
    meta.textContent = "";
    filaEscribiendo = null;
    orbe.estado("idle");
    orbe.callar();
    siguiente = 0;
    transcurrido = 0;
    if (barra) barra.style.width = "0%";
  }

  function tic(ahora) {
    if (!corriendo) return;
    const t = transcurrido + (ahora - inicio);
    while (siguiente < pasos.length && pasos[siguiente].en <= t) {
      pasos[siguiente].hacer();
      siguiente++;
    }
    if (barra) barra.style.width = `${Math.min(100, (t / DURACION) * 100)}%`;
    if (t >= DURACION) {
      pausar();
      transcurrido = DURACION;
      marcarFin();
      return;
    }
    cuadro = requestAnimationFrame(tic);
  }

  function marcarFin() {
    if (textoPlay) textoPlay.textContent = "Repetir";
    iconoPlay?.removeAttribute("hidden");
    iconoPausa?.setAttribute("hidden", "");
  }

  function reproducir() {
    if (corriendo) return;
    if (transcurrido >= DURACION) { limpiar(); }
    corriendo = true;
    inicio = performance.now();
    cuadro = requestAnimationFrame(tic);
    if (textoPlay) textoPlay.textContent = "Pausa";
    iconoPlay?.setAttribute("hidden", "");
    iconoPausa?.removeAttribute("hidden");
    botonPlay?.setAttribute("aria-label", "Pausar la demostración");
  }

  function pausar() {
    if (!corriendo) return;
    corriendo = false;
    transcurrido += performance.now() - inicio;
    cancelAnimationFrame(cuadro);
    if (textoPlay) textoPlay.textContent = "Continuar";
    iconoPlay?.removeAttribute("hidden");
    iconoPausa?.setAttribute("hidden", "");
    botonPlay?.setAttribute("aria-label", "Reproducir la demostración");
  }

  botonPlay?.addEventListener("click", () => (corriendo ? pausar() : reproducir()));
  botonReiniciar?.addEventListener("click", () => {
    pausar();
    limpiar();
    reproducir();
  });

  /** El resultado final, de golpe: lo que se enseña con movimiento reducido. */
  function saltarAlFinal() {
    limpiar();
    pasos.forEach((p) => p.hacer());
    terminarTecleo();
    if (barra) barra.style.width = "100%";
    transcurrido = DURACION;
    marcarFin();
  }

  if (reducido) {
    saltarAlFinal();
    return;
  }

  limpiar();

  // Arranca sola al entrar en pantalla, una vez. Y se pausa al salir: seguir
  // animando algo que nadie está mirando es gastar batería por deporte.
  let yaArrancó = false;
  const vigia = new IntersectionObserver(
    (entradas) => {
      for (const e of entradas) {
        if (e.isIntersecting && !yaArrancó) {
          yaArrancó = true;
          reproducir();
        } else if (!e.isIntersecting && corriendo) {
          pausar();
        }
      }
    },
    { threshold: 0.35 },
  );
  vigia.observe(tablero);
}
