/* ══════════════════════════════════════════════════════════════════════════
   El recorrido: la rama por la que se baja.

   La geometría NO está escrita a mano en el HTML, y no puede estarlo: la rama
   tiene que pasar exactamente por la marca de cada nodo, y dónde acaba cada
   marca depende de cuánto texto tenga el nodo, del ancho de la ventana y de
   la tipografía cargada. Así que se mide el DOM ya maquetado y se construye
   el `d` desde ahí. Al cambiar el tamaño se vuelve a medir.

   El scroll DIRIGE: no hay ninguna animación corriendo por su cuenta. Cada
   fotograma es función de la posición de scroll, que es lo que hace que se
   sienta como bajar por el camino y no como mirar un vídeo.
   ══════════════════════════════════════════════════════════════════════════ */

import { crearOrbe } from "./orbe.js";

const NS = "http://www.w3.org/2000/svg";

/** Cuántos puntos tiene la tabla de consulta del camino. */
const MUESTRAS = 420;

/**
 * Convierte una lista de puntos en una curva suave (Catmull-Rom pasada a
 * Bézier cúbica). Pasa POR los puntos, que es justo lo que hace falta: la
 * curva tiene que tocar la marca de cada nodo, no acercarse.
 */
function caminoSuave(puntos) {
  if (puntos.length < 2) return "";
  const p = puntos;
  let d = `M ${p[0].x.toFixed(2)} ${p[0].y.toFixed(2)}`;
  for (let i = 0; i < p.length - 1; i++) {
    const p0 = p[i - 1] || p[i];
    const p1 = p[i];
    const p2 = p[i + 1];
    const p3 = p[i + 2] || p2;
    // 1/6 es la tensión estándar de Catmull-Rom uniforme. Más alto y la curva
    // se pasa de frenada en los cambios de lado.
    const c1x = p1.x + (p2.x - p0.x) / 6;
    const c1y = p1.y + (p2.y - p0.y) / 6;
    const c2x = p2.x - (p3.x - p1.x) / 6;
    const c2y = p2.y - (p3.y - p1.y) / 6;
    d += ` C ${c1x.toFixed(2)} ${c1y.toFixed(2)}, ${c2x.toFixed(2)} ${c2y.toFixed(2)}, ${p2.x.toFixed(2)} ${p2.y.toFixed(2)}`;
  }
  return d;
}

function crearNodoSVG(tipo, clase, atributos = {}) {
  const el = document.createElementNS(NS, tipo);
  if (clase) el.setAttribute("class", clase);
  for (const [k, v] of Object.entries(atributos)) el.setAttribute(k, v);
  return el;
}

export function montarRecorrido({ gsap, ScrollTrigger, reducido }) {
  const pista = document.getElementById("pista");
  const svg = document.getElementById("rama");
  const viajero = document.getElementById("viajero");
  if (!pista || !svg || !viajero) return;

  const nodos = Array.from(pista.querySelectorAll(".nodo"));
  if (!nodos.length) return;

  // El orbe que hace el camino. Pequeño: es un viajero, no el protagonista —
  // el grande ya está en la portada.
  const orbe = crearOrbe({ tam: 46, estado: "idle", aura: true });
  viajero.appendChild(orbe.el);
  // Se centra sobre el punto del camino: el contenedor mide 0x0 a propósito,
  // así que su hijo se coloca respecto al punto exacto.
  orbe.el.style.marginLeft = "-23px";
  orbe.el.style.marginTop = "-23px";

  let viaFondo, viaViva, hebras = [], viaMuerta, topeMuerto;
  let tabla = [];          // tabla de consulta: puntos del camino ya calculados
  let largoViva = 0;       // longitud del trazo, para el dasharray
  let marcasY = [];        // la y de cada marca, para saber a qué nodo llegó
  let disparador = null;

  function construir() {
    const rectPista = pista.getBoundingClientRect();
    const alto = pista.offsetHeight;
    const carril = parseFloat(getComputedStyle(pista).getPropertyValue("--carril")) || 60;
    const eje = carril / 2;

    svg.setAttribute("viewBox", `0 0 ${carril} ${alto}`);
    svg.setAttribute("width", carril);
    svg.setAttribute("height", alto);
    svg.replaceChildren();

    // ── los puntos por los que TIENE que pasar la rama ──
    const anclas = nodos.map((n) => {
      const marca = n.querySelector(".nodo-marca");
      const r = marca.getBoundingClientRect();
      return { x: eje, y: r.top - rectPista.top + r.height / 2, nodo: n };
    });
    marcasY = anclas.map((a) => a.y);

    // El vaivén: entre nodo y nodo la rama se desvía a un lado y vuelve. Sin
    // esto sería una recta, y una recta no se parece a una rama de git.
    // La amplitud sale del carril para que en móvil se estreche con él.
    const vaiven = Math.min(carril * 0.3, 26);
    const puntos = [{ x: eje, y: 0 }];
    anclas.forEach((a, i) => {
      const previo = i === 0 ? { x: eje, y: 0 } : anclas[i - 1];
      const medio = (previo.y + a.y) / 2;
      // El lado alterna; el primer tramo va a la derecha para que la rama
      // "salga" del hilo de la portada hacia el contenido.
      const lado = i % 2 === 0 ? 1 : -1;
      puntos.push({ x: eje + vaiven * lado, y: medio });
      puntos.push({ x: a.x, y: a.y });
    });
    puntos.push({ x: eje, y: alto });

    const d = caminoSuave(puntos);

    viaFondo = crearNodoSVG("path", "via-fondo", { d });
    viaViva = crearNodoSVG("path", "via-viva", { d });
    svg.append(viaFondo, viaViva);

    // ── el abanico: los motores corriendo en paralelo ──
    // Va del nodo de las capas al del veredicto, que es exactamente el tramo
    // en el que los motores corren a la vez y luego se consolidan.
    const iCapas = nodos.findIndex((n) => n.id === "nodo-capas");
    const iVeredicto = nodos.findIndex((n) => n.id === "nodo-veredicto");
    if (iCapas >= 0 && iVeredicto === iCapas + 1) {
      const a = anclas[iCapas];
      const b = anclas[iVeredicto];
      const HEBRAS = 8;
      for (let k = 0; k < HEBRAS; k++) {
        // Se reparten a los dos lados, más abiertas cuanto más lejos del eje.
        const lado = k % 2 === 0 ? 1 : -1;
        const paso = Math.floor(k / 2) + 1;
        const ancho = Math.min(carril * 0.42, 30) * paso * 0.42 * lado;
        const y1 = a.y + (b.y - a.y) * 0.18;
        const y2 = a.y + (b.y - a.y) * 0.82;
        const hebra = crearNodoSVG("path", "hebra", {
          d: `M ${a.x} ${a.y} C ${a.x + ancho} ${y1}, ${b.x + ancho} ${y2}, ${b.x} ${b.y}`,
        });
        svg.appendChild(hebra);
        hebras.push(hebra);
      }
      // Se pintan por debajo del trazo principal: el camino manda.
      hebras.forEach((h) => svg.insertBefore(h, viaFondo));
    }

    // ── la rama que muere: el commit bloqueado no llega a existir ──
    if (iVeredicto >= 0) {
      const v = anclas[iVeredicto];
      const largo = Math.min(64, (alto - v.y) * 0.22);
      const dx = Math.min(carril * 0.42, 26);
      viaMuerta = crearNodoSVG("path", "via-muerta", {
        d: `M ${v.x} ${v.y} C ${v.x + dx} ${v.y + largo * 0.4}, ${v.x + dx} ${v.y + largo * 0.7}, ${v.x + dx} ${v.y + largo}`,
      });
      topeMuerto = crearNodoSVG("circle", "tope-muerto", {
        cx: v.x + dx, cy: v.y + largo, r: 3.4,
      });
      svg.append(viaMuerta, topeMuerto);
      // Empiezan invisibles: aparecen cuando el viajero llega al veredicto.
      viaMuerta.style.opacity = "0";
      topeMuerto.style.opacity = "0";
      viaMuerta.style.transition = "opacity .5s ease";
      topeMuerto.style.transition = "opacity .5s ease .1s";
    }

    // ── tabla de consulta del camino ──
    largoViva = viaViva.getTotalLength();
    tabla = new Array(MUESTRAS + 1);
    for (let i = 0; i <= MUESTRAS; i++) {
      const p = viaViva.getPointAtLength((i / MUESTRAS) * largoViva);
      tabla[i] = { x: p.x, y: p.y };
    }
    viaViva.style.strokeDasharray = `${largoViva}`;
    viaViva.style.strokeDashoffset = `${largoViva}`;
  }

  // ── lo que se aplica en cada fotograma ─────────────────────────────────
  let ultimoNodo = -1;

  function puntoEn(t) {
    const i = Math.max(0, Math.min(MUESTRAS, Math.round(t * MUESTRAS)));
    return tabla[i] || { x: 0, y: 0 };
  }

  function aplicar(progreso) {
    const t = Math.max(0, Math.min(1, progreso));
    const p = puntoEn(t);

    viaViva.style.strokeDashoffset = `${largoViva * (1 - t)}`;
    viajero.style.transform = `translate3d(${p.x}px, ${p.y}px, 0)`;

    // ¿Por qué nodo va? El último cuya marca ya quedó por encima del viajero.
    let indice = -1;
    for (let i = 0; i < marcasY.length; i++) {
      if (p.y >= marcasY[i] - 6) indice = i;
    }
    if (indice === ultimoNodo) return;

    // Hacia adelante enciende; hacia atrás apaga. Bajar y volver a subir tiene
    // que deshacer lo hecho, o el camino queda encendido entero desde el
    // primer paso y deja de significar nada.
    if (indice > ultimoNodo) {
      for (let i = ultimoNodo + 1; i <= indice; i++) nodos[i]?.classList.add("alcanzado");
    } else {
      for (let i = ultimoNodo; i > indice; i--) nodos[i]?.classList.remove("alcanzado");
    }
    ultimoNodo = indice;

    const nodoActual = nodos[indice];
    orbe.estado(nodoActual?.dataset.estado || "idle");

    // La rama muerta sólo existe a partir del veredicto.
    const enVeredicto = nodoActual?.id === "nodo-veredicto";
    if (viaMuerta) {
      viaMuerta.style.opacity = enVeredicto ? "1" : "0";
      topeMuerto.style.opacity = enVeredicto ? "1" : "0";
    }
  }

  // ── enganche con el scroll ─────────────────────────────────────────────
  function enganchar() {
    disparador?.kill();
    disparador = ScrollTrigger.create({
      trigger: pista,
      // Empieza cuando la pista entra por abajo y termina cuando su final
      // llega a media pantalla: así el último nodo se enciende ANTES de que
      // se vaya de la vista, no justo al salir.
      start: "top 62%",
      end: "bottom 72%",
      onUpdate: (self) => aplicar(self.progress),
      onRefresh: (self) => aplicar(self.progress),
    });
  }

  construir();

  if (reducido) {
    // Sin movimiento: el camino se muestra entero y recorrido, y todos los
    // nodos encendidos. No se pierde ni una palabra del contenido — lo que
    // se pierde es el viaje.
    aplicar(1);
    viajero.style.display = "none";
    return;
  }

  enganchar();
  aplicar(0);

  // Al cambiar de tamaño hay que volver a medir: los nodos cambian de alto
  // cuando el texto se reajusta, y con el `d` viejo la rama pasaría al lado
  // de las marcas en vez de por ellas.
  let temporizador = null;
  const observador = new ResizeObserver(() => {
    clearTimeout(temporizador);
    temporizador = setTimeout(() => {
      hebras = [];
      ultimoNodo = -1;
      nodos.forEach((n) => n.classList.remove("alcanzado"));
      construir();
      ScrollTrigger.refresh();
    }, 160);
  });
  observador.observe(pista);
}
