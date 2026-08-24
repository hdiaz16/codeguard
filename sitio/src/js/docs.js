/* ══════════════════════════════════════════════════════════════════════════
   Documentación: índice lateral, buscador y las tablas que se pintan desde
   los datos.

   Aquí NO se cargan GSAP ni Lenis. A la documentación se viene con prisa a
   buscar la bandera de un comando, y meterle scroll interpolado sólo
   conseguiría que la barra de la derecha mienta sobre dónde estás.
   ══════════════════════════════════════════════════════════════════════════ */

import "@fontsource-variable/inter";
import "@fontsource/jetbrains-mono/400.css";
import "@fontsource/jetbrains-mono/500.css";

import "../estilos/base.css";
import "../estilos/orbe.css";
import "../estilos/portada.css";
import "../estilos/docs.css";

import { inject } from "@vercel/analytics";

import { crearOrbe } from "./orbe.js";
import {
  COMANDOS, MOTORES, SECRETOS, COMPUERTAS, ESTADOS, ESTADOS_CAPA,
} from "./datos.js";

// Analítica de Vercel: cuenta de páginas sin cookies. inject() añade el
// script de /_vercel/insights una sola vez; en dev no manda nada.
inject();

const esc = (s) =>
  String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

/**
 * Marca `así` como código. Los textos de datos.js llevan nombres de claves de
 * configuración entre acentos graves, igual que en los comentarios del
 * repositorio de donde salen; escaparlos y luego reponer sólo esta etiqueta
 * deja el texto seguro y legible.
 */
const conCodigo = (s) => esc(s).replace(/`([^`]+)`/g, "<code>$1</code>");

/* ══ 1 · el orbe de la marca ════════════════════════════════════════════ */
function montarMarca() {
  const hueco = document.querySelector('[data-orbe="24"]');
  if (!hueco) return;
  hueco.appendChild(crearOrbe({ tam: 24, estado: "idle", aura: false }).el);
}

/* ══ 2 · comandos ═══════════════════════════════════════════════════════ */
function pintarComandos() {
  const caja = document.getElementById("comandos-lista");
  if (!caja) return;

  // Agrupados por el mismo criterio que usa la ayuda del binario: primero lo
  // que se hace una vez, luego lo del día a día.
  const grupos = [];
  for (const c of COMANDOS) {
    let g = grupos.find((x) => x.nombre === c.grupo);
    if (!g) grupos.push((g = { nombre: c.grupo, items: [] }));
    g.items.push(c);
  }

  caja.innerHTML = grupos
    .map(
      (g) => `
      <h3 id="comandos-${esc(g.nombre.toLowerCase().replace(/\s+/g, "-"))}">${esc(g.nombre)}</h3>
      ${g.items.map(ficha).join("")}`,
    )
    .join("");

  function ficha(c) {
    const banderas = c.banderas?.length
      ? `<dl class="banderas">${c.banderas
          .map((b) => `<dt>${esc(b.f)}</dt><dd>${esc(b.que)}</dd>`)
          .join("")}</dl>`
      : "";
    const notas = c.notas?.length
      ? `<ul class="notas">${c.notas.map((n) => `<li>${conCodigo(n)}</li>`).join("")}</ul>`
      : "";
    const despues = c.despues ? `<p class="despues">${conCodigo(c.despues)}</p>` : "";
    return `
      <article class="comando" id="cmd-${esc(c.id)}" data-busca="${esc(
        `${c.uso} ${c.corto} ${c.detalle} ${(c.banderas || []).map((b) => b.f + " " + b.que).join(" ")}`,
      )}">
        <h3 id="comando-${esc(c.id)}"><span class="uso">${esc(c.uso)}</span></h3>
        <p class="corto">${esc(c.corto)}</p>
        <p class="detalle">${conCodigo(c.detalle)}</p>
        ${banderas}${notas}${despues}
      </article>`;
  }
}

/* ══ 3 · motores ════════════════════════════════════════════════════════ */
function pintarMotores() {
  const caja = document.getElementById("motores-lista");
  if (!caja) return;

  const todos = [SECRETOS, ...MOTORES];
  caja.innerHTML = todos
    .map(
      (m) => `
      <article class="motor-doc" id="motor-${esc(m.id)}" data-busca="${esc(
        `${m.nombre} ${m.pilar} ${m.lenguajes.join(" ")} ${m.mira} ${m.bloquea} ${m.porque} ${m.origen}`,
      )}">
        <header>
          <h3>${esc(m.nombre)}</h3>
          <span class="pilar ${esc(m.pilar)}">${esc(m.pilar)}</span>
          <span class="lenguas">${m.lenguajes.map((l) => `<span>${esc(l)}</span>`).join("")}</span>
        </header>
        <dl>
          <div><dt>Qué mira</dt><dd>${conCodigo(m.mira)}</dd></div>
          <div><dt>Cuándo bloquea</dt><dd>${conCodigo(m.bloquea)}</dd></div>
          <div><dt>De dónde sale</dt><dd>${esc(m.origen)}</dd></div>
          <div><dt>Caché</dt><dd>${esc(m.cache)}</dd></div>
        </dl>
        <p class="porque">${conCodigo(m.porque)}</p>
      </article>`,
    )
    .join("");
}

/* ══ 4 · tablas ═════════════════════════════════════════════════════════ */
function pintarTablas() {
  const compuertas = document.getElementById("compuertas-tabla");
  if (compuertas) {
    compuertas.innerHTML = COMPUERTAS.map(
      (c) => `<tr><td><code>${esc(c.clave)}</code></td><td><code>${esc(c.valor)}</code></td><td>${conCodigo(c.que)}</td></tr>`,
    ).join("");
  }

  const estados = document.getElementById("estados-tabla");
  if (estados) {
    estados.innerHTML = ESTADOS.map(
      (e) => `<tr><td><code>${esc(e.id)}</code></td><td>${esc(e.clima)}</td><td>«${esc(e.susurro)}»</td><td>${esc(e.cuando)}</td></tr>`,
    ).join("");
  }

  const capas = document.getElementById("capas-tabla");
  if (capas) {
    capas.innerHTML = ESTADOS_CAPA.map(
      (c) => `<tr><td><code>${esc(c.id)}</code></td><td>${esc(c.que)}</td></tr>`,
    ).join("");
  }
}

/* ══ 5 · índice lateral ═════════════════════════════════════════════════ */
function montarIndice() {
  const nav = document.getElementById("lateral-nav");
  if (!nav) return;

  const secciones = Array.from(document.querySelectorAll(".docs-seccion"));

  nav.innerHTML = secciones
    .map((s) => {
      const subs = Array.from(s.querySelectorAll("h3[id]"))
        // Las fichas de comando y de motor ya tienen su propia lista dentro;
        // meterlas aquí daría un índice de sesenta entradas que no se lee.
        .filter((h) => !h.id.startsWith("comando-") && !h.closest(".motor-doc"))
        .map((h) => `<li><a href="#${h.id}">${esc(h.textContent.replace("#", "").trim())}</a></li>`)
        .join("");
      return `
        <div class="lateral-grupo">
          <p>${esc(s.dataset.titulo || s.id)}</p>
          <ul>
            <li><a href="#${s.id}" class="raiz">Resumen</a></li>
            ${subs}
          </ul>
        </div>`;
    })
    .join("");

  // Un ancla junto a cada título, para poder copiar el enlace de un punto
  // concreto. Se ve al pasar por encima.
  document.querySelectorAll(".docs-seccion > h2, .docs-seccion h3[id]").forEach((h) => {
    const id = h.id || h.closest(".docs-seccion")?.id;
    if (!id) return;
    if (!h.id) h.id = id;
    const a = document.createElement("a");
    a.className = "ancla";
    a.href = `#${h.id}`;
    a.textContent = "#";
    a.setAttribute("aria-label", `Enlace a ${h.textContent.trim()}`);
    h.appendChild(a);
  });

  // Qué sección se está leyendo. Se marca la ÚLTIMA cuyo comienzo quedó por
  // encima del cuarto superior de la ventana: con IntersectionObserver a
  // secas, dos secciones visibles a la vez se disputaban la marca y el índice
  // parpadeaba.
  const enlaces = Array.from(nav.querySelectorAll("a"));
  const destinos = enlaces
    .map((a) => ({ a, el: document.querySelector(a.getAttribute("href")) }))
    .filter((d) => d.el);

  let pendiente = false;
  function marcar() {
    pendiente = false;
    const limite = window.scrollY + window.innerHeight * 0.25;
    let activo = destinos[0];
    for (const d of destinos) {
      if (d.el.getBoundingClientRect().top + window.scrollY <= limite) activo = d;
    }
    enlaces.forEach((a) => a.classList.remove("activo"));
    activo?.a.classList.add("activo");
  }
  window.addEventListener(
    "scroll",
    () => {
      if (pendiente) return;
      pendiente = true;
      requestAnimationFrame(marcar);
    },
    { passive: true },
  );
  marcar();
}

/* ══ 6 · buscador ═══════════════════════════════════════════════════════ */
function montarBuscador() {
  const entrada = document.getElementById("buscador");
  const cuenta = document.getElementById("buscador-cuenta");
  if (!entrada) return;

  const bloques = Array.from(document.querySelectorAll(".comando, .motor-doc"));
  const secciones = Array.from(document.querySelectorAll(".docs-seccion"));
  const grupos = Array.from(document.querySelectorAll(".lateral-grupo"));

  // El texto de cada sección se indexa UNA vez: recalcularlo en cada tecla
  // sobre un documento de este tamaño se nota al escribir.
  const indice = secciones.map((s) => ({
    el: s,
    texto: (s.textContent || "").toLowerCase(),
  }));
  const indiceBloques = bloques.map((b) => ({
    el: b,
    texto: ((b.dataset.busca || "") + " " + (b.textContent || "")).toLowerCase(),
  }));

  let vacio = null;

  function limpiar() {
    indice.forEach((s) => s.el.classList.remove("oculto-por-busqueda"));
    indiceBloques.forEach((b) => b.el.classList.remove("oculto-por-busqueda"));
    grupos.forEach((g) => g.classList.remove("oculto"));
    cuenta.textContent = "";
    vacio?.remove();
    vacio = null;
  }

  function buscar(termino) {
    const q = termino.trim().toLowerCase();
    if (q.length < 2) return limpiar();

    let encontradas = 0;
    for (const s of indice) {
      const dentro = s.texto.includes(q);
      s.el.classList.toggle("oculto-por-busqueda", !dentro);
      if (dentro) encontradas++;
    }
    // Dentro de una sección visible, las fichas que no casan se esconden: si
    // buscas "squawk" no tiene sentido darte los diecinueve motores.
    for (const b of indiceBloques) {
      const seccion = b.el.closest(".docs-seccion");
      if (seccion?.classList.contains("oculto-por-busqueda")) continue;
      b.el.classList.toggle("oculto-por-busqueda", !b.texto.includes(q));
    }
    // El índice lateral acompaña.
    grupos.forEach((g, i) => {
      g.classList.toggle("oculto", secciones[i]?.classList.contains("oculto-por-busqueda"));
    });

    cuenta.textContent = encontradas
      ? `${encontradas} ${encontradas === 1 ? "sección" : "secciones"}`
      : "sin resultados";

    vacio?.remove();
    vacio = null;
    if (!encontradas) {
      vacio = document.createElement("p");
      vacio.className = "sin-resultados";
      vacio.textContent = `No hay nada sobre «${termino.trim()}» en esta página.`;
      document.getElementById("docs-contenido").appendChild(vacio);
    }
  }

  let temporizador = null;
  entrada.addEventListener("input", () => {
    clearTimeout(temporizador);
    temporizador = setTimeout(() => buscar(entrada.value), 110);
  });
  entrada.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      entrada.value = "";
      limpiar();
    }
  });

  // La barra ya no cabe en la cabecera de la documentación, así que la tecla
  // «/» la enfoca — como en cualquier documentación que se use de verdad.
  document.addEventListener("keydown", (e) => {
    if (e.key !== "/" || e.ctrlKey || e.metaKey || e.altKey) return;
    const activo = document.activeElement;
    if (activo && ["INPUT", "TEXTAREA", "SELECT"].includes(activo.tagName)) return;
    e.preventDefault();
    entrada.focus();
    entrada.select();
  });
}

/* ══ arranque ═══════════════════════════════════════════════════════════ */
function arrancar() {
  montarMarca();
  pintarComandos();
  pintarMotores();
  pintarTablas();
  // El índice se construye DESPUÉS de pintar: si no, no vería los títulos que
  // acaban de aparecer.
  montarIndice();
  montarBuscador();

  // Si se llegó con un ancla, el navegador ya saltó antes de que existiera el
  // contenido pintado. Se repite el salto una vez todo está en su sitio.
  if (location.hash) {
    const destino = document.querySelector(location.hash);
    destino?.scrollIntoView({ block: "start" });
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", arrancar);
} else {
  arrancar();
}
