/* ══════════════════════════════════════════════════════════════════════════
   La niebla serena, en vivo.

   El sitio ya tenía niebla: body::before pinta dos manchas radiales tenues,
   fijas, detrás de todo. Esto la pone EN MOVIMIENTO — un campo de niebla y
   motas de viento dibujado por shader que vive detrás del sitio ENTERO y
   acompaña el scroll — al estilo de atmos.leeroy.ca, pero en el idioma del
   producto: «niebla serena» es literalmente el clima del estado idle del orbe.

   LA REGLA QUE MANDA, aprendida de un intento anterior que salió mal: la
   atmósfera está SUBORDINADA al contenido. La primera versión de esta idea
   inundó el héroe entero de blanco y el titular se leía a través de una
   nube. Por eso aquí el alfa lleva TOPE DURO en el propio shader (la niebla
   nunca pasa de 0.16 y las motas de 0.30 en puntos de un par de píxeles):
   por construcción, no por buenas intenciones, el texto siempre gana.

   Sin three.js, por lo mismo que el orbe del héroe: un campo de niebla es un
   fragment shader de pantalla completa — se midió que la escena equivalente
   con three.js pesaba 189 KB gzip; esto pesa ~3 KB dentro del bundle.

   Reacciona al scroll de dos maneras, las dos discretas:
   - la niebla tiene PARALLAX: bajar por la página la desplaza despacio, como
     atravesarla;
   - la VELOCIDAD del scroll sopla: una ráfaga breve acelera la deriva de las
     motas y las aviva un poco, y decae sola al soltar.

   Si algo falla —sin WebGL, shader que no compila, contexto perdido— se
   devuelve null y no pasa nada: body::before sigue ahí, que es exactamente
   el mismo cuadro en quieto.
   ══════════════════════════════════════════════════════════════════════════ */

const VERT = `
attribute vec2 pos;
varying vec2 vUv;
void main() {
  vUv = pos * 0.5 + 0.5;
  gl_Position = vec4(pos, 0.0, 1.0);
}`;

const FRAG = `
precision mediump float;
varying vec2 vUv;

uniform vec2  u_res;
uniform float u_t;
uniform float u_scroll;  /* avance por la página, 0..1 */
uniform float u_vel;     /* ráfaga por velocidad de scroll, con signo, ya suavizada */
uniform vec3  u_tintA;   /* menta, la de body::before */
uniform vec3  u_tintB;   /* azul,  la de body::before */

float hash(vec2 p) {
  return fract(sin(dot(p, vec2(127.1, 311.7))) * 43758.5453123);
}

float ruido(vec2 p) {
  vec2 i = floor(p);
  vec2 f = fract(p);
  f = f * f * (3.0 - 2.0 * f);
  return mix(
    mix(hash(i),                    hash(i + vec2(1.0, 0.0)), f.x),
    mix(hash(i + vec2(0.0, 1.0)),   hash(i + vec2(1.0, 1.0)), f.x),
    f.y);
}

float fbm(vec2 p) {
  return ruido(p) * 0.55 + ruido(p * 2.13) * 0.28 + ruido(p * 4.41) * 0.17;
}

void main() {
  vec2 uv = vUv * u_res / min(u_res.x, u_res.y);
  float t = u_t;

  /* Dos capas de niebla a escalas distintas, derivando en sentidos opuestos
     — lo que hace que se lea como profundidad y no como una textura que se
     mueve. El scroll las desplaza a ritmos distintos: parallax. */
  vec2 p1 = uv * 1.25 + vec2(t * 0.014 + u_vel * 0.30, -u_scroll * 0.50);
  vec2 p2 = uv * 2.60 - vec2(t * 0.009 + u_vel * 0.18, u_scroll * 0.95 - 7.3);
  float f = fbm(p1) * 0.62 + fbm(p2) * 0.38;

  /* El TOPE DURO: smoothstep recorta lo tenue (que quede aire limpio de
     verdad, no un velo uniforme) y el 0.16 es el máximo absoluto de alfa que
     la niebla puede alcanzar en su punto más denso. */
  float niebla = smoothstep(0.48, 0.88, f) * 0.16;

  /* El tinte respira entre las dos luces que body::before ya usa. */
  vec3 tinte = mix(u_tintB, u_tintA, fbm(uv * 0.8 + t * 0.006));

  /* Motas de viento: ruido de alta frecuencia umbralizado — puntos sueltos de
     un par de píxeles que derivan de lado. La ráfaga del scroll los acelera y
     los aviva; en calma casi ni se ven. El umbral alto (0.965) es lo que los
     hace ESCASOS: bajarlo convierte el cielo en estática de televisor. */
  vec2 pm = uv * 24.0 + vec2(t * 0.10 + u_vel * 2.6, -u_scroll * 3.2);
  float m = ruido(pm);
  float mota = smoothstep(0.965, 0.995, m) * (0.10 + min(abs(u_vel) * 4.0, 0.20));

  float alfa = min(niebla + mota, 0.30);
  gl_FragColor = vec4(tinte, alfa);
}`;

function compilar(gl, tipo, fuente) {
  const s = gl.createShader(tipo);
  gl.shaderSource(s, fuente);
  gl.compileShader(s);
  if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) {
    console.warn("ambiente3d: el shader no compiló —", gl.getShaderInfoLog(s));
    gl.deleteShader(s);
    return null;
  }
  return s;
}

function hexARgb(hex) {
  const n = parseInt(hex.slice(1), 16);
  return [((n >> 16) & 255) / 255, ((n >> 8) & 255) / 255, (n & 255) / 255];
}

/**
 * Monta la niebla detrás del sitio entero. Devuelve el lienzo, o `null` si el
 * navegador no puede — y entonces queda body::before, que es la misma niebla
 * en quieto.
 *
 * @param {object}  opciones
 * @param {boolean} opciones.reducido  prefers-reduced-motion: un solo cuadro,
 *                                     sin bucle — la niebla existe pero no fluye.
 */
export function montarAmbiente({ reducido = false } = {}) {
  let gl = null;
  const lienzo = document.createElement("canvas");
  try {
    gl = lienzo.getContext("webgl", { alpha: true, antialias: false, premultipliedAlpha: false });
  } catch {
    gl = null;
  }
  if (!gl) return null;

  const vert = compilar(gl, gl.VERTEX_SHADER, VERT);
  const frag = vert && compilar(gl, gl.FRAGMENT_SHADER, FRAG);
  if (!vert || !frag) return null;
  const programa = gl.createProgram();
  gl.attachShader(programa, vert);
  gl.attachShader(programa, frag);
  gl.linkProgram(programa);
  if (!gl.getProgramParameter(programa, gl.LINK_STATUS)) {
    console.warn("ambiente3d: el programa no enlazó —", gl.getProgramInfoLog(programa));
    return null;
  }

  const buffer = gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
  const posLoc = gl.getAttribLocation(programa, "pos");
  gl.enableVertexAttribArray(posLoc);
  gl.vertexAttribPointer(posLoc, 2, gl.FLOAT, false, 0, 0);

  gl.useProgram(programa);
  const u = {
    res: gl.getUniformLocation(programa, "u_res"),
    t: gl.getUniformLocation(programa, "u_t"),
    scroll: gl.getUniformLocation(programa, "u_scroll"),
    vel: gl.getUniformLocation(programa, "u_vel"),
    tintA: gl.getUniformLocation(programa, "u_tintA"),
    tintB: gl.getUniformLocation(programa, "u_tintB"),
  };
  // Las mismas dos luces de body::before — no un clima nuevo.
  gl.uniform3fv(u.tintA, hexARgb("#b8f7e4"));
  gl.uniform3fv(u.tintB, hexARgb("#9fd0ea"));
  gl.clearColor(0, 0, 0, 0);

  // La niebla es de baja frecuencia: se dibuja a MEDIA resolución y el CSS la
  // estira. Nadie distingue el detalle en un degradado suave, y el shader
  // paga un cuarto de los píxeles — esto corre en cada fotograma del scroll.
  function medir() {
    const w = Math.max(1, Math.round(window.innerWidth / 2));
    const h = Math.max(1, Math.round(window.innerHeight / 2));
    if (lienzo.width !== w || lienzo.height !== h) {
      lienzo.width = w;
      lienzo.height = h;
      gl.viewport(0, 0, w, h);
      gl.uniform2f(u.res, w, h);
    }
  }
  medir();

  lienzo.id = "ambiente-lienzo";
  lienzo.setAttribute("aria-hidden", "true");
  // Al PRINCIPIO del body: en la misma capa fija (z 0) que body::before, y
  // por orden de árbol debajo de todo lo que viene después. El contenido vive
  // en .envoltura con z-index 1 — la niebla no puede taparlo por construcción.
  document.body.insertBefore(lienzo, document.body.firstChild);

  const inicio = performance.now();
  let scrollPrevio = window.scrollY;
  let rafaga = 0;
  let visible = document.visibilityState === "visible";
  let perdido = false;
  let idFrame = null;

  function cuadro(ahora) {
    idFrame = null;
    if (!visible || perdido) return;

    const alto = Math.max(1, document.documentElement.scrollHeight - window.innerHeight);
    const y = window.scrollY;
    // La ráfaga: cuánto se movió el scroll este cuadro, suavizado con decaimiento
    // — sopla al desplazarse y se apaga sola al soltar.
    rafaga += ((y - scrollPrevio) / window.innerHeight - rafaga) * 0.10;
    scrollPrevio = y;

    medir();
    gl.uniform1f(u.t, (ahora - inicio) / 1000);
    gl.uniform1f(u.scroll, y / alto);
    gl.uniform1f(u.vel, Math.max(-1.5, Math.min(1.5, rafaga)));
    gl.clear(gl.COLOR_BUFFER_BIT);
    gl.drawArrays(gl.TRIANGLES, 0, 3);

    idFrame = requestAnimationFrame(cuadro);
  }

  lienzo.addEventListener("webglcontextlost", (e) => {
    e.preventDefault();
    perdido = true;
    // Sin contexto no hay niebla que enseñar: se quita el lienzo y queda
    // body::before. Un canvas muerto pintado de nada no le debe nada a nadie.
    lienzo.remove();
  });

  if (reducido) {
    // Un solo cuadro, quieto: la niebla como paisaje, no como animación.
    gl.uniform1f(u.t, 0);
    gl.uniform1f(u.scroll, 0);
    gl.uniform1f(u.vel, 0);
    gl.clear(gl.COLOR_BUFFER_BIT);
    gl.drawArrays(gl.TRIANGLES, 0, 3);
    return lienzo;
  }

  document.addEventListener("visibilitychange", () => {
    visible = document.visibilityState === "visible";
    if (visible && idFrame == null) idFrame = requestAnimationFrame(cuadro);
  });
  window.addEventListener("resize", medir, { passive: true });

  idFrame = requestAnimationFrame(cuadro);
  return lienzo;
}
