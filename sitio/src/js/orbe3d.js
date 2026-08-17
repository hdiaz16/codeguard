/* ══════════════════════════════════════════════════════════════════════════
   El orbe, en volumen.

   El orbe plano (orbe.js) es tres divs fundidos por un filtro gooey: convincente
   de cerca, pero sigue siendo una silueta 2D. Para el héroe de la portada —el
   único sitio que se lo puede permitir— esto lo dibuja de verdad en volumen:
   una esfera con la superficie deformada por ruido (el mismo "líquido en
   gravedad cero" de orbe-morph, pero como geometría, no como border-radius),
   que respira, gira despacio y responde un poco al puntero.

   La decisión que pesa: NO se vendorea three.js. Un shader de pantalla
   completa con raymarching no necesita ni escena, ni cámara, ni malla — sólo
   un triángulo y un fragment shader. Cargar ~150 KB de librería para eso
   sería exactamente el "adorno con peso" que el presupuesto del sitio no se
   puede permitir. Esto pesa unas pocas líneas de más en main.js, minificadas
   junto al resto.

   La regla que manda sobre todo lo demás: si algo falla —WebGL apagado, el
   contexto no aparece, un shader no compila— esta función devuelve `null` y
   quien llama cae al orbe plano de siempre. Un héroe roto es peor que uno
   sin volumen.
   ══════════════════════════════════════════════════════════════════════════ */

import { crearBurbuja } from "./orbe.js";

const VERT = `
attribute vec2 pos;
varying vec2 vUv;
void main() {
  vUv = pos * 0.5 + 0.5;
  gl_Position = vec4(pos, 0.0, 1.0);
}`;

/* Un raymarch sobre una esfera cuya "superficie" es 1.0 más dos octavas de
   ruido de valor, muestreadas sobre un punto que gira con el tiempo — así el
   bulto se desplaza sobre la esfera en vez de quedarse fijo, que es lo que
   lee como GIRO en vez de como textura pintada. Y el radio entero respira
   con un seno lento: el mismo latido de orbe-latido, en volumen. */
const FRAG = `
precision highp float;
varying vec2 vUv;

uniform vec2  u_res;
uniform float u_tiempo;
uniform vec3  u_colorA;
uniform vec3  u_colorB;
uniform vec3  u_spark;
uniform vec2  u_tilt;

float hash(vec3 p) {
  p = fract(p * 0.3183099 + vec3(0.1, 0.2, 0.3));
  p *= 17.0;
  return fract(p.x * p.y * p.z * (p.x + p.y + p.z));
}

float ruido(vec3 p) {
  vec3 i = floor(p);
  vec3 f = fract(p);
  f = f * f * (3.0 - 2.0 * f);
  float n000 = hash(i);
  float n100 = hash(i + vec3(1.0, 0.0, 0.0));
  float n010 = hash(i + vec3(0.0, 1.0, 0.0));
  float n110 = hash(i + vec3(1.0, 1.0, 0.0));
  float n001 = hash(i + vec3(0.0, 0.0, 1.0));
  float n101 = hash(i + vec3(1.0, 0.0, 1.0));
  float n011 = hash(i + vec3(0.0, 1.0, 1.0));
  float n111 = hash(i + vec3(1.0, 1.0, 1.0));
  return mix(
    mix(mix(n000, n100, f.x), mix(n010, n110, f.x), f.y),
    mix(mix(n001, n101, f.x), mix(n011, n111, f.x), f.y),
    f.z);
}

float fbm(vec3 p) {
  return ruido(p) * 0.6 + ruido(p * 2.1) * 0.3 + ruido(p * 4.3) * 0.1;
}

float mapa(vec3 p, float t) {
  float ang = t * 0.16;
  float c = cos(ang), s = sin(ang);
  vec3 q = vec3(p.x * c - p.z * s, p.y, p.x * s + p.z * c);
  float respira = 1.0 + sin(t * 0.9) * 0.03;
  float r = respira
          + fbm(q * 1.6 + vec3(0.0, 0.0, t * 0.05)) * 0.12
          - fbm(q * 3.1 - vec3(t * 0.03, 0.0, 0.0)) * 0.05;
  return length(p) - r;
}

vec3 normalEn(vec3 p, float t) {
  vec2 e = vec2(0.0015, 0.0);
  return normalize(vec3(
    mapa(p + e.xyy, t) - mapa(p - e.xyy, t),
    mapa(p + e.yxy, t) - mapa(p - e.yxy, t),
    mapa(p + e.yyx, t) - mapa(p - e.yyx, t)
  ));
}

void main() {
  vec2 uv = (vUv * u_res - 0.5 * u_res) / min(u_res.x, u_res.y);
  uv += u_tilt;

  /* Cámara a 5.2 y no a 2.5, medido con una captura real: a 2.5 la esfera
     (radio ~1.1 con el ruido) cubre un ángulo mayor que el que el lienzo
     alcanza a ver (su borde caía en uv≈0.7 y el lienzo llega a 0.5), así que
     TODOS los rayos la golpeaban y el orbe se pintaba como un cuadrado gris
     macizo. A 5.2 el borde queda en uv≈0.36: esfera al ~72% del lienzo, con
     sitio para el halo y para el tilt de 0.12 sin recortar contra el borde. */
  vec3 ro = vec3(0.0, 0.0, 5.2);
  vec3 rd = normalize(vec3(uv, -1.6));

  float t = u_tiempo;
  float dist = 0.0;
  float distMin = 1e9;
  vec3 p = ro;
  bool tocado = false;

  for (int i = 0; i < 56; i++) {
    p = ro + rd * dist;
    float d = mapa(p, t);
    distMin = min(distMin, d);
    if (d < 0.0015) { tocado = true; break; }
    dist += d * 0.7;
    /* 9.0 y no 6.0: con la cámara a 5.2, un rayo que roza la esfera alcanza
       su mínima distancia cerca de dist≈5.2 — cortar en 6.0 truncaba el halo. */
    if (dist > 9.0) break;
  }

  if (!tocado) {
    /* Fuera de la esfera: un halo suave — el mismo resplandor que en CSS
       pinta el ::before del orbe plano detrás del cuerpo. */
    float halo = exp(-7.0 * max(distMin, 0.0));
    gl_FragColor = vec4(u_spark * halo * 0.8, halo * 0.5);
    return;
  }

  vec3 n = normalEn(p, t);
  vec3 luz = normalize(vec3(-0.5, 0.6, 0.65));
  float difusa = max(dot(n, luz), 0.0);
  float fresnel = pow(1.0 - max(dot(n, -rd), 0.0), 2.3);

  vec3 base = mix(u_colorB, u_colorA, difusa * 0.7 + 0.3);
  vec3 color = mix(base, u_spark, clamp(fresnel * 0.85 + 0.05, 0.0, 1.0));

  float alfa = clamp(0.7 + fresnel * 0.3, 0.0, 1.0);
  gl_FragColor = vec4(color, alfa);
}`;

function compilar(gl, tipo, fuente) {
  const s = gl.createShader(tipo);
  gl.shaderSource(s, fuente);
  gl.compileShader(s);
  if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) {
    console.warn("orbe3d: el shader no compiló —", gl.getShaderInfoLog(s));
    gl.deleteShader(s);
    return null;
  }
  return s;
}

function enlazar(gl, vert, frag) {
  const p = gl.createProgram();
  gl.attachShader(p, vert);
  gl.attachShader(p, frag);
  gl.linkProgram(p);
  if (!gl.getProgramParameter(p, gl.LINK_STATUS)) {
    console.warn("orbe3d: el programa no enlazó —", gl.getProgramInfoLog(p));
    return null;
  }
  return p;
}

/** #rrggbb → [r,g,b] en 0..1. Sin librería de color: son tres cifras fijas. */
function hexARgb(hex) {
  const n = parseInt(hex.slice(1), 16);
  return [((n >> 16) & 255) / 255, ((n >> 8) & 255) / 255, (n & 255) / 255];
}

/**
 * Monta el orbe 3D. Devuelve `null` si el navegador no puede —y entonces
 * quien llama debe caer al orbe plano de `crearOrbe`—, o un objeto con la
 * misma forma que éste ({el, susurrar, callar}) si todo salió bien.
 *
 * @param {object} opciones
 * @param {number} opciones.tam       lado en px, igual que crearOrbe
 * @param {string} opciones.etiqueta  texto accesible del envoltorio
 */
export function montarOrbe3D({ tam = 176, etiqueta = "" } = {}) {
  let gl = null;
  const lienzo = document.createElement("canvas");
  try {
    const opts = { alpha: true, antialias: true, premultipliedAlpha: false };
    gl = lienzo.getContext("webgl", opts) || lienzo.getContext("experimental-webgl", opts);
  } catch {
    gl = null;
  }
  if (!gl) return null;

  const vert = compilar(gl, gl.VERTEX_SHADER, VERT);
  const frag = vert && compilar(gl, gl.FRAGMENT_SHADER, FRAG);
  const programa = vert && frag && enlazar(gl, vert, frag);
  if (!programa) return null;

  // Un triángulo que cubre todo el lienzo — el truco de siempre para un
  // shader de pantalla completa: sin costura en la diagonal, y una llamada
  // de dibujo menos que con dos triángulos.
  const buffer = gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
  const posLoc = gl.getAttribLocation(programa, "pos");
  gl.enableVertexAttribArray(posLoc);
  gl.vertexAttribPointer(posLoc, 2, gl.FLOAT, false, 0, 0);

  const u = {
    res: gl.getUniformLocation(programa, "u_res"),
    tiempo: gl.getUniformLocation(programa, "u_tiempo"),
    colorA: gl.getUniformLocation(programa, "u_colorA"),
    colorB: gl.getUniformLocation(programa, "u_colorB"),
    spark: gl.getUniformLocation(programa, "u_spark"),
    tilt: gl.getUniformLocation(programa, "u_tilt"),
  };

  // Las mismas tres cifras del estado "idle" en orbe.css — no un color
  // nuevo inventado para el héroe: es EL MISMO orbe, sólo con más profundidad.
  gl.useProgram(programa);
  gl.uniform3fv(u.colorA, hexARgb("#8e979e"));
  gl.uniform3fv(u.colorB, hexARgb("#565f66"));
  gl.uniform3fv(u.spark, hexARgb("#c9d2d8"));
  gl.uniform2f(u.tilt, 0, 0);
  gl.clearColor(0, 0, 0, 0);

  // Tope de densidad de píxeles: un raymarch paga por muestra dentro de cada
  // píxel, y un DPR de 3 sin tope cuadruplica el trabajo por nada que se note
  // en un orbe de ~176 px. 1.5 es un tope prudente para que en un móvil de
  // gama media esto no le quite fotogramas a Lenis.
  const dpr = Math.min(window.devicePixelRatio || 1, 1.5);
  lienzo.width = Math.round(tam * dpr);
  lienzo.height = Math.round(tam * dpr);
  gl.viewport(0, 0, lienzo.width, lienzo.height);
  gl.uniform2f(u.res, lienzo.width, lienzo.height);
  lienzo.className = "orbe-3d-lienzo";
  lienzo.setAttribute("aria-hidden", "true");

  // El envoltorio lleva las MISMAS clases que el orbe plano, así la burbuja
  // del susurro hereda --plasma-hot-a y --plasma-glow del estado "idle" sin
  // tocar una sola línea de orbe.css. `sin-aura` apaga el resplandor CSS de
  // detrás: aquí el resplandor lo pinta el propio shader (el halo del `else`
  // en el fragment shader).
  const raiz = document.createElement("div");
  raiz.className = "orbe sin-aura";
  raiz.style.setProperty("--orbe-tam", `${tam}px`);
  raiz.dataset.estado = "idle";
  if (etiqueta) {
    raiz.setAttribute("role", "img");
    raiz.setAttribute("aria-label", etiqueta);
  }
  raiz.appendChild(lienzo);

  const burbuja = crearBurbuja("lateral");
  raiz.appendChild(burbuja.el);

  // ── el motor: pausado fuera de pantalla, con la pestaña oculta, o si el
  //    contexto WebGL se pierde (algunos navegadores lo hacen al quedarse
  //    sin memoria de vídeo) ──
  let enPantalla = true;
  let pestanaVisible = document.visibilityState === "visible";
  let perdido = false;
  let idFrame = null;
  const inicio = performance.now();
  let tiltX = 0;
  let tiltY = 0;

  const activo = () => enPantalla && pestanaVisible && !perdido;

  function planificar() {
    if (idFrame != null || !activo()) return;
    idFrame = requestAnimationFrame(fotograma);
  }

  function fotograma(ahora) {
    idFrame = null;
    if (!activo()) return;
    gl.uniform1f(u.tiempo, (ahora - inicio) / 1000);
    gl.uniform2f(u.tilt, tiltX, tiltY);
    gl.clear(gl.COLOR_BUFFER_BIT);
    gl.drawArrays(gl.TRIANGLES, 0, 3);
    planificar();
  }
  planificar();

  lienzo.addEventListener("webglcontextlost", (e) => {
    e.preventDefault();
    perdido = true;
  });

  if ("IntersectionObserver" in window) {
    new IntersectionObserver(
      (entradas) => {
        for (const e of entradas) enPantalla = e.isIntersecting;
        planificar();
      },
      { rootMargin: "220px 0px" },
    ).observe(raiz);
  }
  document.addEventListener("visibilitychange", () => {
    pestanaVisible = document.visibilityState === "visible";
    planificar();
  });

  // La inclinación: el orbe "mira" un poco hacia el puntero. Sólo un indicio
  // —el tope es 0.12, contra un margen de encuadre de ~0.16— para que nunca
  // llegue a recortar la esfera contra el borde del lienzo. Un orbe que
  // persigue el cursor del todo deja de respirar solo y pasa a perseguir.
  window.addEventListener("pointermove", (e) => {
    const r = raiz.getBoundingClientRect();
    if (r.width === 0) return;
    const cx = r.left + r.width / 2;
    const cy = r.top + r.height / 2;
    const dx = (e.clientX - cx) / (window.innerWidth / 2);
    const dy = (e.clientY - cy) / (window.innerHeight / 2);
    tiltX = Math.max(-1, Math.min(1, dx)) * 0.12;
    tiltY = Math.max(-1, Math.min(1, dy)) * 0.12;
  }, { passive: true });

  return {
    el: raiz,
    susurrar: burbuja.susurrar,
    callar: burbuja.callar,
  };
}
