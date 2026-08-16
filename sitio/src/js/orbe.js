/* ══════════════════════════════════════════════════════════════════════════
   Fábrica de orbes.

   El orbe del escritorio mide 84 px y suelda sus tres capas con un filtro
   gooey de stdDeviation 5. Ese 5 no es un número mágico: es la proporción con
   la que el desenfoque funde el núcleo y el destello en un solo cuerpo. Si el
   orbe crece a 300 px y el desenfoque sigue en 5, las capas dejan de fundirse
   y se ven dos manchas separadas — el plasma se pierde.

   Así que el filtro se genera por tamaño: stdDeviation = tam / 16.8, que es
   justo lo que da 5 a 84 px. Los filtros se reutilizan entre orbes del mismo
   tamaño; no se crea uno por instancia.
   ══════════════════════════════════════════════════════════════════════════ */

const NS = "http://www.w3.org/2000/svg";
const filtrosCreados = new Set();
let defs = null;

function contenedorDeFiltros() {
  if (defs) return defs;
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("width", "0");
  svg.setAttribute("height", "0");
  svg.style.cssText = "position:absolute;width:0;height:0;overflow:hidden";
  defs = document.createElementNS(NS, "defs");
  svg.appendChild(defs);
  document.body.appendChild(svg);
  return defs;
}

/** Crea (una vez) el filtro gooey para un desenfoque dado y devuelve su id. */
function filtroGoo(desviacion) {
  const id = `goo-${String(desviacion).replace(".", "_")}`;
  if (filtrosCreados.has(id)) return id;
  filtrosCreados.add(id);

  const filtro = document.createElementNS(NS, "filter");
  filtro.setAttribute("id", id);
  // La caja del filtro se agranda: con la de por defecto (-10%/+20%) el
  // desenfoque se recorta en el borde y el plasma sale con el canto cortado.
  filtro.setAttribute("x", "-50%");
  filtro.setAttribute("y", "-50%");
  filtro.setAttribute("width", "200%");
  filtro.setAttribute("height", "200%");
  filtro.setAttribute("color-interpolation-filters", "sRGB");

  const blur = document.createElementNS(NS, "feGaussianBlur");
  blur.setAttribute("in", "SourceGraphic");
  blur.setAttribute("stdDeviation", String(desviacion));
  blur.setAttribute("result", "blur");

  // La misma matriz del widget: sube el alfa por 22 y le resta 10, lo que
  // convierte el degradado del desenfoque en un borde definido. Ahí está el
  // efecto "gota": dos manchas cercanas se sueldan en una sola silueta.
  const matriz = document.createElementNS(NS, "feColorMatrix");
  matriz.setAttribute("in", "blur");
  matriz.setAttribute("mode", "matrix");
  matriz.setAttribute("values", "1 0 0 0 0  0 1 0 0 0  0 0 1 0 0  0 0 0 22 -10");
  matriz.setAttribute("result", "goo");

  const mezcla = document.createElementNS(NS, "feBlend");
  mezcla.setAttribute("in", "SourceGraphic");
  mezcla.setAttribute("in2", "goo");

  filtro.append(blur, matriz, mezcla);
  contenedorDeFiltros().appendChild(filtro);
  return id;
}

const ESTADOS_VALIDOS = new Set(["idle", "working", "pass", "blocked", "degraded", "offline"]);

/* ── Los orbes fuera de pantalla se paran ────────────────────────────────
   El plasma es tres capas animadas bajo un filtro SVG, y eso repinta en cada
   fotograma. La página llega a tener doce orbes: los seis climas de la
   sección del emblema, el de la portada, el viajero, el de la demo, el del
   cierre y el de la marca. Con todos animando a la vez, el scroll pagaba el
   repintado de orbes que nadie estaba mirando — medido en el recorrido de la
   rama, que es donde más trabajo hay por fotograma.

   Pararlos fuera de pantalla no cambia nada de lo que se ve: al volver a
   entrar, la animación sigue donde la dejó. */
let vigiaOrbes = null;
function vigilar(orbe) {
  if (!("IntersectionObserver" in window)) return;
  if (!vigiaOrbes) {
    vigiaOrbes = new IntersectionObserver(
      (entradas) => {
        for (const e of entradas) e.target.classList.toggle("fuera", !e.isIntersecting);
      },
      // Un margen generoso: reanudar justo en el borde se notaría como un
      // tirón al entrar.
      { rootMargin: "220px 0px" },
    );
  }
  vigiaOrbes.observe(orbe);
}

/**
 * Crea un orbe.
 *
 * @param {object} opciones
 * @param {number} opciones.tam        lado en px
 * @param {string} opciones.estado     idle | working | pass | blocked | degraded | offline
 * @param {boolean} opciones.aura      el resplandor de detrás (falso para las viñetas pequeñas)
 * @param {boolean|"lateral"} opciones.burbuja  cápsula de susurro; "lateral"
 *        la saca por el costado en vez de por debajo
 * @param {string} opciones.etiqueta   texto accesible
 */
export function crearOrbe({ tam = 84, estado = "idle", aura = true, burbuja = false, etiqueta = "" } = {}) {
  const raiz = document.createElement("div");
  raiz.className = "orbe" + (aura ? "" : " sin-aura");
  raiz.style.setProperty("--orbe-tam", `${tam}px`);
  raiz.dataset.estado = ESTADOS_VALIDOS.has(estado) ? estado : "idle";
  if (etiqueta) {
    raiz.setAttribute("role", "img");
    raiz.setAttribute("aria-label", etiqueta);
  } else {
    raiz.setAttribute("aria-hidden", "true");
  }

  const cuerpo = document.createElement("div");
  cuerpo.className = "orbe-cuerpo";
  // El desenfoque se redondea a un decimal: sin eso cada orbe de tamaño
  // ligeramente distinto crearía su propio filtro y acabaríamos con docenas.
  const desviacion = Math.round((tam / 16.8) * 10) / 10;
  cuerpo.style.filter = `url(#${filtroGoo(desviacion)})`;

  const nucleo = document.createElement("div");
  nucleo.className = "orbe-capa orbe-nucleo";
  const destello = document.createElement("div");
  destello.className = "orbe-capa orbe-destello";
  cuerpo.append(nucleo, destello);
  raiz.appendChild(cuerpo);

  let capsula = null;
  let texto = null;
  if (burbuja) {
    capsula = document.createElement("div");
    capsula.className = "orbe-burbuja" + (burbuja === "lateral" ? " lateral" : "");
    capsula.setAttribute("role", "status");
    capsula.setAttribute("aria-live", "polite");
    const punto = document.createElement("span");
    punto.className = "punto";
    texto = document.createElement("span");
    texto.className = "texto";
    capsula.append(punto, texto);
    raiz.appendChild(capsula);
  }

  let temporizador = null;
  vigilar(raiz);

  return {
    el: raiz,

    /** Cambia el clima. Las paletas se funden en 0.8 s: nunca saltan. */
    estado(nuevo) {
      if (!ESTADOS_VALIDOS.has(nuevo)) return;
      raiz.dataset.estado = nuevo;
    },

    get actual() {
      return raiz.dataset.estado;
    },

    /**
     * El susurro. Con `permanente` se queda hasta que otro lo reemplace, que
     * es lo que hace el avance del análisis: una capa lenta puede tardar más
     * que la caducidad del susurro efímero, y quedarse mudo a media revisión
     * es justo lo que el susurro viene a evitar.
     */
    susurrar(mensaje, { permanente = false, ms = 3400 } = {}) {
      if (!capsula) return;
      clearTimeout(temporizador);
      texto.textContent = mensaje;
      capsula.classList.add("visible");
      if (!permanente) {
        temporizador = setTimeout(() => capsula.classList.remove("visible"), ms);
      }
    },

    callar() {
      if (!capsula) return;
      clearTimeout(temporizador);
      capsula.classList.remove("visible");
    },
  };
}
