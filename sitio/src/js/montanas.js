/* ══════════════════════════════════════════════════════════════════════════
   La cordillera de la portada.

   No es un paisaje inventado para el sitio: es la MISMA escena de marca del
   instalador, con la misma matemática. Sale de `dist/build-wizard-art.ps1`,
   que dibuja el splash del asistente (300×340) con `Draw-Cordillera`:

     tri(t)  = 1 - 2·|frac(t) - 0.5|            ← onda triangular
     y(x)    = baseY - amp · ( 0.65·tri(x·f + φ) + 0.35·tri(x·f·2.6 + φ·1.7) )

   Dos armónicos triangulares: el primero pone las cumbres grandes y el
   segundo, a 2.6 veces la frecuencia, les rompe las laderas para que no
   parezcan dientes de sierra. Sobre las dos crestas de delante va el filo de
   nieve, que es una línea de #e6ebef a poca opacidad.

   Los parámetros del splash, tal cual (baseY, amp, freq, faseX, r,g,b, α, αNieve):

     @(310, 26, 0.012, 0.3, 42, 48, 58, 255, 55)
     @(326, 22, 0.017, 1.9, 28, 33, 41, 255, 32)
     @(342, 16, 0.023, 4.1, 18, 21, 27, 255,  0)

   Lo que hay que traducir son las dos cosas que dependen del tamaño del
   lienzo, y las dos por el mismo motivo: allí el lienzo mide 300 px y aquí
   mide lo que mida la ventana.

     · La FRECUENCIA está en píxeles (0.012 por píxel). A 1440 px darían 17
       cumbres en vez de las 3.6 del original: otro paisaje. Se guarda en
       ciclos —300 · 0.012 = 3.6— y se reparte sobre el ancho que toque.
     · La AMPLITUD se escala con el ancho, no con el alto de la franja, para
       que cada pico conserve su relación alto/ancho. El porqué, abajo.

   Con eso la silueta es la misma a cualquier tamaño, que es justo lo que no
   consigue una imagen.
   ══════════════════════════════════════════════════════════════════════════ */

const NS = "http://www.w3.org/2000/svg";

/** Onda triangular de periodo 1. Idéntica a la `tri` del script. */
const tri = (t) => {
  const f = t - Math.floor(t);
  return 1 - 2 * Math.abs(f - 0.5);
};

/* ── Cómo se lleva el paisaje del splash a una portada ancha ──────────────
   Todo lo que sigue es UNA decisión: la cordillera se escala como un dibujo,
   no se estira para llenar la caja.

   Se intentó al revés —amplitudes como fracción del alto de la franja— y el
   resultado no era la montaña del instalador: era un muro de picos de 140 px
   que se comía el texto de la portada. La razón es geométrica. La silueta de
   una montaña la define la proporción entre lo que sube y lo ANCHO que es su
   pico; atar la altura al alto de la caja y el ancho al de la ventana rompe
   esa proporción en cuanto las dos no crecen igual.

   Así que hay un solo factor de escala, aplicado a todo: `escala = ancho/300`,
   porque el lienzo original mide 300 px de ancho. Con eso, cada pico conserva
   exactamente su relación alto/ancho.

   Y se limita a 2.8. Escalar 4.75 veces (que es lo que pide una ventana de
   1440) daría 275 px de crestas: fiel al dibujo y equivocado para una
   portada, porque el instalador enseña su paisaje en una ventana de 300 px y
   aquí compite con un titular. Con el tope son ~162 px, y ahí las cumbres
   pasan por debajo de la fila de cifras en vez de por detrás de ella.

   Las crestas se anclan ABAJO — y = alto − (342 − y_original)·escala — para
   que el resto de la franja sea cielo. Ahí es donde va el texto: sobre el
   cielo, que es oscuro y uniforme, nunca sobre las laderas.                */
const SUELO = 342;               // la última capa del splash toca aquí
const ESCALA_MAX = 2.8;

const CAPAS = [
  { dy: SUELO - 310, amp: 26, ciclos: 300 * 0.012, fase: 0.3, color: "42,48,58", nieve: 55 / 255 },
  { dy: SUELO - 326, amp: 22, ciclos: 300 * 0.017, fase: 1.9, color: "28,33,41", nieve: 32 / 255 },
  { dy: SUELO - 342, amp: 16, ciclos: 300 * 0.023, fase: 4.1, color: "18,21,27", nieve: 0 },
];

/* La bruma que deriva entre las crestas. En el splash son dos elipses de
   #e6ebef muy transparentes a y=302 y y=318, que van y vienen con un seno. */
const BRUMAS = [
  { dy: SUELO - 302, alfa: 26 / 255, deriva: 20, periodo: 23 },
  { dy: SUELO - 318, alfa: 18 / 255, deriva: 14, periodo: 31 },
];

const escalaDe = (ancho) => Math.min(ancho / 300, ESCALA_MAX);

/** El color de la nieve, #e6ebef. */
const NIEVE = "230,235,239";

/* Generador reproducible para las estrellas: tienen que caer siempre en el
   mismo sitio, o cada cambio de tamaño de ventana redibujaría otro cielo. */
function azarSemilla(semilla) {
  let s = semilla >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 4294967296;
  };
}

/**
 * Calcula la cresta de una capa: la lista de puntos de su perfil.
 * El paso de 4 px es el del original; a más resolución no se gana nada
 * visible y el `d` del path se hace innecesariamente largo.
 */
function cresta(capa, ancho, alto) {
  const puntos = [];
  const f = capa.ciclos / ancho;          // ciclos por píxel para ESTE ancho
  const escala = escalaDe(ancho);
  const baseY = alto - capa.dy * escala;  // anclada al suelo de la franja
  const amp = capa.amp * escala;
  for (let x = -2; x <= ancho + 2; x += 4) {
    const y = baseY - amp * (0.65 * tri(x * f + capa.fase) + 0.35 * tri(x * f * 2.6 + capa.fase * 1.7));
    puntos.push([x, y]);
  }
  return puntos;
}

const aPath = (puntos) => puntos.map(([x, y], i) => `${i ? "L" : "M"}${x.toFixed(1)} ${y.toFixed(1)}`).join("");

function crear(tipo, atributos = {}) {
  const el = document.createElementNS(NS, tipo);
  for (const [k, v] of Object.entries(atributos)) el.setAttribute(k, v);
  return el;
}

/**
 * Dibuja la cordillera dentro de un contenedor.
 * @param {HTMLElement} caja  el contenedor; se rellena entero
 * @param {boolean} reducido  sin movimiento: la bruma no deriva
 */
export function montarMontanas(caja, { reducido = false } = {}) {
  if (!caja) return;

  let svg = null;

  function dibujar() {
    const ancho = Math.max(320, caja.clientWidth);
    const alto = Math.max(180, caja.clientHeight);

    const nuevo = crear("svg", {
      class: "cordillera",
      viewBox: `0 0 ${ancho} ${alto}`,
      width: ancho,
      height: alto,
      preserveAspectRatio: "none",
      "aria-hidden": "true",
    });

    // ── el cielo ────────────────────────────────────────────────────────
    // Esto no es decoración: es lo que hace VISIBLES las crestas. Sus grises
    // —42,48,58 · 28,33,41 · 18,21,27— están elegidos contra el fondo del
    // splash, que es una noche de #101216 a #171a1f. El fondo del sitio es
    // #1a1c20, más claro que dos de esas tres capas: sin el cielo del
    // instalador, la cordillera se dibujaba entera y no se veía —la de
    // delante quedaba más oscura que la página y se leía como una sombra—.
    // Es el mismo `Draw-FondoGrad $g $W $H $pizarraBg $pizarraBg2` del script.
    const fondo = crear("defs");
    const gradCielo = crear("linearGradient", { id: "cielo-montanas", x1: "0", y1: "0", x2: "0", y2: "1" });
    gradCielo.appendChild(crear("stop", { offset: "0%", "stop-color": "#101216" }));
    gradCielo.appendChild(crear("stop", { offset: "100%", "stop-color": "#171a1f" }));
    fondo.appendChild(gradCielo);
    nuevo.appendChild(fondo);
    nuevo.appendChild(crear("rect", { x: 0, y: 0, width: ancho, height: alto, fill: "url(#cielo-montanas)" }));

    // ── unas pocas estrellas, como en el splash ──
    // Van sólo por encima de la primera cresta: una estrella dibujada sobre
    // la ladera de una montaña delata que esto son capas, no un paisaje.
    const azar = azarSemilla(7);
    const escala = escalaDe(ancho);
    const techoCrestas = alto - (CAPAS[0].dy + CAPAS[0].amp) * escala;
    const cielo = crear("g", { class: "cielo" });
    for (let i = 0; i < 34; i++) {
      const x = azar() * ancho;
      const y = azar() * techoCrestas;
      const a = 0.07 + azar() * 0.14;          // el original: alfa 18..55 de 255
      const r = azar() > 0.85 ? 1.15 : 0.7;
      cielo.appendChild(crear("circle", { cx: x.toFixed(1), cy: y.toFixed(1), r, fill: `rgba(239,243,246,${a.toFixed(3)})` }));
    }
    nuevo.appendChild(cielo);

    // ── las tres capas, de fondo a frente ──
    CAPAS.forEach((capa, i) => {
      const puntos = cresta(capa, ancho, alto);
      const relleno = `${aPath(puntos)}L${ancho + 2} ${alto + 2}L-2 ${alto + 2}Z`;
      nuevo.appendChild(crear("path", { d: relleno, fill: `rgb(${capa.color})` }));

      if (capa.nieve > 0) {
        nuevo.appendChild(crear("path", {
          d: aPath(puntos),
          fill: "none",
          stroke: `rgba(${NIEVE},${capa.nieve.toFixed(3)})`,
          "stroke-width": 1.3,
          "stroke-linejoin": "round",
        }));
      }

      // La bruma va INTERCALADA entre las crestas, no toda encima: es lo que
      // da la sensación de profundidad, porque una capa de niebla que tapa la
      // montaña de delante se lee como suciedad en la pantalla.
      const bruma = BRUMAS[i];
      if (!bruma) return;
      const gid = `bruma-${i}`;
      const defs = crear("defs");
      const grad = crear("radialGradient", { id: gid });
      grad.appendChild(crear("stop", { offset: "0%", "stop-color": `rgba(${NIEVE},${bruma.alfa.toFixed(3)})` }));
      grad.appendChild(crear("stop", { offset: "100%", "stop-color": `rgba(${NIEVE},0)` }));
      defs.appendChild(grad);
      nuevo.appendChild(defs);

      const banda = crear("ellipse", {
        class: "bruma",
        cx: ancho / 2,
        cy: (alto - bruma.dy * escala).toFixed(1),
        rx: ancho * 0.8,
        ry: (14 * escala).toFixed(1),
        fill: `url(#${gid})`,
      });
      if (!reducido) {
        // La deriva del original es un seno; aquí es una animación CSS de ida
        // y vuelta sobre transform, que el compositor lleva sin repintar.
        banda.style.setProperty("--deriva", `${bruma.deriva}px`);
        banda.style.animationDuration = `${bruma.periodo}s`;
        if (i % 2) banda.style.animationDirection = "alternate-reverse";
      }
      nuevo.appendChild(banda);
    });

    svg?.remove();
    svg = nuevo;
    caja.appendChild(svg);
  }

  dibujar();

  // Al cambiar el ancho hay que rehacer el perfil: si sólo se estirara el
  // SVG, las cumbres se deformarían y el filo de nieve engordaría con ellas.
  let temporizador = null;
  new ResizeObserver(() => {
    clearTimeout(temporizador);
    temporizador = setTimeout(dibujar, 180);
  }).observe(caja);
}
