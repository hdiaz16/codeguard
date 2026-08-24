/* ══════════════════════════════════════════════════════════════════════════
   Portada: arranque, scroll y las secciones que se pintan desde los datos.

   Las librerías y por qué:
     · GSAP + ScrollTrigger — el scrub por scroll. Se podría hacer con
       IntersectionObserver a mano, pero no la parte que importa: que la
       animación sea FUNCIÓN de la posición de scroll y no una animación
       disparada por un umbral. ScrollTrigger además recalcula bien cuando el
       documento cambia de alto, que aquí pasa todo el rato.
     · Lenis — interpola el scroll del navegador. Sin él, cada muesca de la
       rueda del ratón mueve el orbe a saltos: el camino se ve pisado en vez
       de recorrido.
   ══════════════════════════════════════════════════════════════════════════ */

import "@fontsource-variable/inter";
import "@fontsource/jetbrains-mono/400.css";
import "@fontsource/jetbrains-mono/500.css";

import "../estilos/base.css";
import "../estilos/orbe.css";
import "../estilos/montanas.css";
import "../estilos/portada.css";

import { gsap } from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import Lenis from "lenis";
import { inject } from "@vercel/analytics";

import { crearOrbe } from "./orbe.js";
import { montarAmbiente } from "./ambiente3d.js";
import { montarRecorrido } from "./recorrido.js";
import { montarDemo } from "./demo.js";
import { montarMontanas } from "./montanas.js";
import {
  MOTORES, SECRETOS, REGLAS_DE_FORMA, ESTADOS, ESTADOS_CAPA, PRINCIPIOS,
  NOMBRES_MOTORES,
} from "./datos.js";

gsap.registerPlugin(ScrollTrigger);

// Analítica de Vercel: cuenta de páginas sin cookies. inject() añade el
// script de /_vercel/insights una sola vez; en dev no manda nada.
inject();

const reducido = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

/* ── escape para todo lo que se inserte como HTML ──────────────────────── */
const esc = (s) =>
  String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

/* ══ 1 · scroll suave ═══════════════════════════════════════════════════ */
let lenis = null;

function montarScroll() {
  if (reducido) return;

  lenis = new Lenis({
    duration: 1.05,
    // Exponencial descendente: llega rápido y frena tarde. Es la curva que se
    // siente como inercia y no como un retardo.
    easing: (t) => Math.min(1, 1.001 - Math.pow(2, -10 * t)),
    smoothWheel: true,
    // En táctil NO: el scroll del dedo ya tiene su propia física, y meterle
    // otra encima se siente como si el dedo resbalara.
    syncTouch: false,
  });

  lenis.on("scroll", ScrollTrigger.update);
  gsap.ticker.add((tiempo) => lenis.raf(tiempo * 1000));
  gsap.ticker.lagSmoothing(0);
}

function irA(destino) {
  const el = typeof destino === "string" ? document.querySelector(destino) : destino;
  if (!el) return;
  if (lenis) lenis.scrollTo(el, { offset: -80 });
  else el.scrollIntoView({ block: "start" });
}

/* ══ 2 · barra ══════════════════════════════════════════════════════════ */
function montarBarra() {
  const barra = document.getElementById("barra");
  const menu = document.getElementById("barra-menu");

  const miniOrbe = document.querySelector('[data-orbe="24"]');
  if (miniOrbe) {
    const o = crearOrbe({ tam: 24, estado: "idle", aura: false });
    miniOrbe.appendChild(o.el);
  }

  const alPosarse = () => barra.classList.toggle("posada", window.scrollY > 24);
  alPosarse();
  window.addEventListener("scroll", alPosarse, { passive: true });

  menu?.addEventListener("click", () => {
    const abierto = barra.classList.toggle("desplegada");
    menu.setAttribute("aria-expanded", String(abierto));
  });

  // Los enlaces internos pasan por Lenis: si no, el salto nativo y el scroll
  // interpolado se pelean y la página acaba en un sitio que no es.
  document.querySelectorAll('a[href^="#"]').forEach((a) => {
    a.addEventListener("click", (e) => {
      const destino = a.getAttribute("href");
      if (destino === "#" || destino.length < 2) return;
      const el = document.querySelector(destino);
      if (!el) return;
      e.preventDefault();
      barra.classList.remove("desplegada");
      menu?.setAttribute("aria-expanded", "false");
      irA(el);
    });
  });
}

/* ══ 3 · portada ════════════════════════════════════════════════════════ */
function montarPortada() {
  const caja = document.getElementById("portada-orbe");
  if (!caja) return;

  // El tamaño se elige por ancho de ventana y no con una media query en CSS:
  // el desenfoque del filtro gooey depende del tamaño, y ese número lo
  // calcula la fábrica de orbes, no la hoja de estilos.
  const ancho = window.innerWidth;
  const tam = ancho < 520 ? 138 : ancho < 900 ? 162 : 176;

  // El héroe es EL ORBE ORIGINAL — el gooey de tres capas, la imagen del
  // sistema. Se probó una esfera 3D por shader y se retiró por decisión del
  // dueño del producto: se leía como una esfera cualquiera, no como la
  // insignia. La dimensión 3D del sitio vive en la ATMÓSFERA (ambiente3d.js),
  // no en sustituir la identidad.
  const etiqueta = "El orbe de CodeGuard, de guardia";
  const orbe = crearOrbe({ tam, estado: "idle", aura: true, burbuja: "lateral", etiqueta });
  caja.appendChild(orbe.el);

  if (reducido) return;

  // Susurra al llegar, como en el escritorio — pero sólo si hay sitio.
  //
  // En estrecho la cápsula no cabe ni al lado (se sale) ni debajo (ahí está el
  // titular) ni encima (ahí está la pastilla, que a ese ancho ocupa dos
  // líneas). Un susurro que tapa texto no es un detalle bonito: es un estorbo.
  // Se pierde poco — los seis climas con su susurro tienen su propia sección
  // más abajo, con espacio de sobra.
  if (window.innerWidth > 720) {
    setTimeout(() => orbe.susurrar("de guardia", { ms: 4200 }), 1100);
  }

  // La entrada: el orbe crece desde su propia luz y el texto sube detrás.
  gsap.from(orbe.el, { scale: 0.62, opacity: 0, duration: 1.1, ease: "power3.out" });
  gsap.from(
    [".portada-pastilla", ".portada-titulo", ".portada-bajada", ".portada-acciones", ".portada-datos"],
    { y: 26, opacity: 0, duration: 0.85, stagger: 0.09, ease: "power3.out", delay: 0.18 },
  );

  // Al bajar de la portada el orbe se aparta con una parallax corta. Sólo
  // transform y opacity: el compositor lo lleva sin repintar.
  gsap.to(caja, {
    yPercent: 26,
    opacity: 0.25,
    ease: "none",
    scrollTrigger: { trigger: ".portada", start: "top top", end: "bottom top", scrub: 0.4 },
  });
}

/* ══ 4 · listas pintadas desde los datos ════════════════════════════════ */

function pintarCapasDelNodo() {
  const lista = document.getElementById("capas-lista");
  if (!lista) return;
  lista.innerHTML = NOMBRES_MOTORES.map((m) => `<li>${esc(m)}</li>`).join("");

  if (reducido) {
    lista.querySelectorAll("li").forEach((li) => li.classList.add("viva"));
    return;
  }
  // Se encienden una a una cuando el nodo entra en pantalla: es el mismo
  // gesto que hace el orbe de verdad mientras corre el análisis.
  ScrollTrigger.create({
    trigger: lista,
    start: "top 82%",
    once: true,
    onEnter: () => {
      lista.querySelectorAll("li").forEach((li, i) => {
        setTimeout(() => li.classList.add("viva"), i * 85);
      });
    },
  });
}

function pintarMotores() {
  const acordeon = document.getElementById("motores-acordeon");
  const filtro = document.getElementById("motores-filtro");
  if (!acordeon) return;

  const todos = [SECRETOS, ...MOTORES];

  // Veinte tarjetas abiertas a la vez eran una pared. Esto es la misma
  // información —nada se quita, nada se resume de más— en un acordeón:
  // colapsada, la fila pesa una línea; abierta, trae exactamente lo que
  // traía la tarjeta. <details> nativo porque el teclado y el lector de
  // pantalla ya saben qué hacer con él sin una sola línea de ARIA a mano.
  const fila = (m) => `
    <details class="motor" data-pilar="${esc(m.pilar)}"${m.destacado ? " open" : ""}>
      <summary class="motor-resumen">
        <span class="motor-nombre">${esc(m.nombre)}</span>
        <span class="motor-lenguajes">${m.lenguajes.map((l) => `<span>${esc(l)}</span>`).join("")}</span>
        <span class="pilar ${esc(m.pilar)}">${esc(m.pilar)}</span>
        <svg class="motor-flecha" viewBox="0 0 24 24" aria-hidden="true"><path d="M7 10l5 5 5-5"/></svg>
      </summary>
      <div class="motor-detalle">
        <dl>
          <div><dt>Qué mira</dt><dd>${esc(m.mira)}</dd></div>
          <div><dt>Cuándo bloquea</dt><dd class="bloqueo-si">${esc(m.bloquea)}</dd></div>
        </dl>
        <p class="motor-porque">${esc(m.porque)}</p>
        <p class="motor-pie">
          <span class="origen">${esc(m.origen)}</span>
          <span>caché: ${esc(m.cache)}</span>
        </p>
      </div>
    </details>`;

  acordeon.innerHTML = todos.map(fila).join("");

  // El filtro por pilar. Son tres categorías reales del producto, no una
  // taxonomía inventada para el sitio.
  const pilares = ["todos", "seguridad", "calidad", "datos"];
  filtro.innerHTML = pilares
    .map((p) => `<button type="button" data-pilar="${p}" aria-pressed="${p === "todos"}">${p === "todos" ? "Todos" : esc(p)}</button>`)
    .join("");

  filtro.addEventListener("click", (e) => {
    const boton = e.target.closest("button");
    if (!boton) return;
    const elegido = boton.dataset.pilar;
    filtro.querySelectorAll("button").forEach((b) =>
      b.setAttribute("aria-pressed", String(b.dataset.pilar === elegido)));
    acordeon.querySelectorAll(".motor").forEach((t) => {
      t.hidden = elegido !== "todos" && t.dataset.pilar !== elegido;
    });
    ScrollTrigger.refresh();
  });

  if (!reducido) {
    gsap.from(acordeon.querySelectorAll(".motor"), {
      y: 16, opacity: 0, duration: 0.45, stagger: 0.025, ease: "power2.out",
      scrollTrigger: { trigger: acordeon, start: "top 84%", once: true },
    });
    // Un <details> que cambia de alto en pleno scrub de ScrollTrigger deja el
    // resto de la página temblando: hay que decirle que vuelva a medir.
    acordeon.addEventListener("toggle", () => ScrollTrigger.refresh(), true);
  }
}

function pintarListasSimples() {
  const forma = document.getElementById("forma-lista");
  if (forma) {
    forma.innerHTML = REGLAS_DE_FORMA
      .map((r) => `<li><b>${esc(r.nombre)}</b><span>${esc(r.que)}</span></li>`)
      .join("");
  }

  const vocab = document.getElementById("vocabulario-lista");
  if (vocab) {
    vocab.innerHTML = ESTADOS_CAPA
      .map((c) => `<li><b>${esc(c.nombre)}</b><span>${esc(c.que)}</span></li>`)
      .join("");
  }

  const principios = document.getElementById("principios-lista");
  if (principios) {
    principios.innerHTML = PRINCIPIOS
      .map((p) => `<li><span class="pid">${esc(p.id)}</span><span>${esc(p.texto)}</span></li>`)
      .join("");
    if (!reducido) {
      gsap.from(principios.querySelectorAll("li"), {
        y: 18, opacity: 0, duration: 0.5, stagger: 0.07, ease: "power2.out",
        scrollTrigger: { trigger: principios, start: "top 84%", once: true },
      });
    }
  }
}

/* ══ 5 · los seis estados del orbe ══════════════════════════════════════ */
function montarEstados() {
  const escena = document.getElementById("estados-orbe");
  const lista = document.getElementById("estados-lista");
  if (!escena || !lista) return;

  const ancho = window.innerWidth;
  const orbe = crearOrbe({
    tam: ancho < 620 ? 130 : 168,
    estado: "idle",
    aura: true,
    burbuja: true,
    etiqueta: "Demostración de los estados del orbe",
  });
  escena.appendChild(orbe.el);

  lista.innerHTML = ESTADOS.map((e, i) => `
    <button class="estado-fila" role="tab" type="button"
            data-estado="${esc(e.id)}" aria-selected="${i === 0}">
      <span class="estado-viñeta" data-viñeta="${esc(e.id)}"></span>
      <span>
        <span class="estado-nombre">${esc(e.nombre)}<span class="estado-clima">${esc(e.clima)}</span></span>
        <span class="estado-susurro">«${esc(e.susurro)}»</span>
        <span class="estado-cuando">${esc(e.cuando)}</span>
      </span>
    </button>`).join("");

  // Cada fila lleva su propio orbe en miniatura: así los seis climas se ven a
  // la vez, que es lo que no se puede hacer en el escritorio.
  lista.querySelectorAll("[data-viñeta]").forEach((hueco) => {
    const mini = crearOrbe({ tam: 26, estado: hueco.dataset.viñeta, aura: false });
    hueco.appendChild(mini.el);
  });

  function elegir(id) {
    const dato = ESTADOS.find((e) => e.id === id);
    if (!dato) return;
    orbe.estado(id);
    orbe.susurrar(dato.susurro, { permanente: true });
    lista.querySelectorAll(".estado-fila").forEach((f) =>
      f.setAttribute("aria-selected", String(f.dataset.estado === id)));
  }

  lista.addEventListener("click", (e) => {
    const fila = e.target.closest(".estado-fila");
    if (fila) elegir(fila.dataset.estado);
  });
  // El teclado recorre los estados con las flechas, como cualquier lista de
  // pestañas.
  lista.addEventListener("keydown", (e) => {
    if (!["ArrowDown", "ArrowUp"].includes(e.key)) return;
    const filas = Array.from(lista.querySelectorAll(".estado-fila"));
    const actual = filas.findIndex((f) => f.getAttribute("aria-selected") === "true");
    const siguiente = (actual + (e.key === "ArrowDown" ? 1 : -1) + filas.length) % filas.length;
    e.preventDefault();
    filas[siguiente].focus();
    elegir(filas[siguiente].dataset.estado);
  });

  elegir("idle");

  // Al entrar en pantalla hace el recorrido de climas una vez: quieto no se
  // entiende que se FUNDEN, que es la mitad de la gracia.
  if (reducido) return;
  ScrollTrigger.create({
    trigger: escena,
    start: "top 74%",
    once: true,
    onEnter: () => {
      const orden = ["working", "pass", "blocked", "idle"];
      orden.forEach((id, i) => setTimeout(() => elegir(id), 900 + i * 1300));
    },
  });
}

/* ══ 6 · cierre ═════════════════════════════════════════════════════════ */
function montarCierre() {
  const caja = document.getElementById("cierre-orbe");
  if (!caja) return;
  const orbe = crearOrbe({ tam: 96, estado: "pass", aura: true, etiqueta: "El orbe en verde: el commit pasó" });
  caja.appendChild(orbe.el);
}

/* ══ 7 · entradas de sección ════════════════════════════════════════════ */
function montarEntradas() {
  if (reducido) return;
  document.querySelectorAll(".seccion-cabeza").forEach((cabeza) => {
    gsap.from(cabeza.children, {
      y: 22, opacity: 0, duration: 0.7, stagger: 0.08, ease: "power3.out",
      scrollTrigger: { trigger: cabeza, start: "top 86%", once: true },
    });
  });
}

/* ══ arranque ═══════════════════════════════════════════════════════════ */
function arrancar() {
  // La atmósfera va primero: es el fondo de todo lo demás. Con
  // prefers-reduced-motion pinta un solo cuadro quieto; sin WebGL no se crea
  // y queda la niebla estática de body::before — el mismo cuadro, en quieto.
  montarAmbiente({ reducido });
  montarScroll();
  montarBarra();
  // La cordillera va antes que el orbe: es el fondo sobre el que sale, igual
  // que en el splash del instalador.
  montarMontanas(document.getElementById("montanas"), { reducido });
  montarPortada();
  pintarCapasDelNodo();
  pintarMotores();
  pintarListasSimples();
  montarEstados();
  montarCierre();
  montarEntradas();
  montarRecorrido({ gsap, ScrollTrigger, reducido });
  montarDemo({ reducido });

  // Las tipografías cambian el alto de todo al cargar, y la rama se construyó
  // midiendo el alto anterior. Sin este refresco la rama pasa al lado de las
  // marcas en vez de por ellas — se ve, y se ve mal.
  if (document.fonts?.ready) {
    document.fonts.ready.then(() => ScrollTrigger.refresh());
  }
  window.addEventListener("load", () => ScrollTrigger.refresh());
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", arrancar);
} else {
  arrancar();
}
