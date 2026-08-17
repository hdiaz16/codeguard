/* ══════════════════════════════════════════════════════════════════════════
   El descenso por los climas.

   El sitio entero tiene atmósfera en volumen detrás del contenido, y el
   scroll la CONDUCE: arriba, la «niebla serena» del estado idle — motas
   escasas cayendo despacio; al bajar por el recorrido se levanta la
   «ventisca» — el viento gira a diagonal, las motas se multiplican y
   aceleran—; y hacia el cierre amaina: «montaña dormida». No son nombres
   inventados para el sitio: son los climas del propio orbe (ESTADOS en
   datos.js). El scroll no decora — narra.

   Dos capas, dos papeles:
   - la NIEBLA: un fbm de pantalla completa con tope duro de 0.055 de alfa —
     exactamente el nivel de las luces que body::before ya se permitía. Es el
     lecho de profundidad; en quieto casi no está.
   - las MOTAS: cientos de partículas por gl.POINTS, cada una con su
     PROFUNDIDAD — las cercanas más grandes, más rápidas y con más parallax
     que las lejanas, que es lo que hace que el campo se lea en 3D y no como
     confeti pegado al cristal. Son puntos de 2-5 px: brillan individualmente
     sin poder velar el texto jamás. Y sin estado: la posición de cada mota
     es función pura de (semilla, t, scroll) — no hay simulación que integrar
     ni deriva numérica que corregir.

   La lección cara de las dos versiones anteriores sigue mandando: la
   atmósfera está SUBORDINADA al contenido, por construcción. Alfa
   premultiplicado (inmune al driver que compone mal), topes duros en el
   shader, y el contenido en z-1 sobre esta capa fija en z-0.

   Sin three.js: se midió que la escena equivalente pesaba 189 KB gzip; esto
   son ~5 KB dentro del bundle. Si algo falla —sin WebGL, shader que no
   compila, contexto perdido— se devuelve null y queda body::before: el mismo
   cielo, en quieto.
   ══════════════════════════════════════════════════════════════════════════ */

const VERT_NIEBLA = `
attribute vec2 pos;
varying vec2 vUv;
void main() {
  vUv = pos * 0.5 + 0.5;
  gl_Position = vec4(pos, 0.0, 1.0);
}`;

const FRAG_NIEBLA = `
precision mediump float;
varying vec2 vUv;

uniform vec2  u_res;
uniform float u_t;
uniform float u_scroll;
uniform float u_vel;
uniform vec3  u_tintA;
uniform vec3  u_tintB;

float hash(vec2 p) {
  return fract(sin(dot(p, vec2(127.1, 311.7))) * 43758.5453123);
}
float ruido(vec2 p) {
  vec2 i = floor(p);
  vec2 f = fract(p);
  f = f * f * (3.0 - 2.0 * f);
  return mix(
    mix(hash(i),                  hash(i + vec2(1.0, 0.0)), f.x),
    mix(hash(i + vec2(0.0, 1.0)), hash(i + vec2(1.0, 1.0)), f.x),
    f.y);
}
float fbm(vec2 p) {
  return ruido(p) * 0.55 + ruido(p * 2.13) * 0.28 + ruido(p * 4.41) * 0.17;
}

void main() {
  vec2 uv = vUv * u_res / min(u_res.x, u_res.y);
  float t = u_t;

  vec2 p1 = uv * 1.25 + vec2(t * 0.014 + u_vel * 0.30, -u_scroll * 0.50);
  vec2 p2 = uv * 2.60 - vec2(t * 0.009 + u_vel * 0.18, u_scroll * 0.95 - 7.3);
  float f = fbm(p1) * 0.62 + fbm(p2) * 0.38;

  /* Tope duro calibrado contra el propio sitio: body::before nunca pasa de
     0.055, y una niebla que hable otro idioma es una mancha, no atmósfera. */
  float niebla = smoothstep(0.50, 0.90, f) * 0.055;
  vec3 tinte = mix(u_tintB, u_tintA, fbm(uv * 0.8 + t * 0.006));

  /* Premultiplicado: inmune al driver que compone el buffer como si ya
     viniera multiplicado — el quemado blanco es imposible por construcción. */
  gl_FragColor = vec4(tinte * niebla, niebla);
}`;

/* ── las motas: la ventisca que el scroll conduce ─────────────────────────
   Cada mota nace de una SEMILLA y nada más. De ella salen, por hashes, su
   punto de partida, su profundidad, su tamaño y su fase de parpadeo. La
   posición es fract(origen + viento·t + parallax·scroll): función pura del
   tiempo, y el wrap de fract() recicla cada mota por el borde contrario. */
const VERT_MOTAS = `
precision mediump float;
attribute float semilla;

uniform float u_t;
uniform float u_scroll;
uniform float u_vel;
uniform float u_dpr;

varying float vAlfa;
varying float vMezcla;

float h(float s, float k) { return fract(sin(s * k) * 43758.5453123); }

void main() {
  float h1 = h(semilla, 12.9898);   /* x de origen */
  float h2 = h(semilla, 78.2330);   /* y de origen */
  float h3 = h(semilla, 43.7585);   /* profundidad */
  float h4 = h(semilla, 91.2228);   /* densidad: quién existe en cada clima */
  float h5 = h(semilla, 26.6519);   /* fase de parpadeo y tinte */

  /* LA CURVA DEL DESCENSO — el guion de los climas sobre el scroll (0..1):
     niebla serena arriba, la ventisca se levanta entre el 8% y el 38% del
     recorrido, sopla plena por el centro, y amaina desde el 62% hasta la
     montaña dormida del cierre. */
  float vent = smoothstep(0.08, 0.38, u_scroll)
             * (1.0 - 0.80 * smoothstep(0.62, 0.92, u_scroll));

  /* En calma vive un tercio de las motas; la ventisca las despierta a todas.
     Las que no tocan, este cuadro no existen. */
  float dens = 0.32 + 0.68 * vent;
  float vive = step(h4, dens);

  float d = mix(0.35, 1.0, h3);     /* profundidad: lejos..cerca */

  /* El viento: en calma cae mansa (x casi nada); con la ventisca el empuje
     lateral crece un orden de magnitud y la caída se sesga a diagonal. Todo
     escala con la profundidad: lo cercano corre más — eso es el 3D. */
  vec2 viento = vec2(
    -(0.010 + 0.140 * vent) * d,
    -(0.016 + 0.075 * vent) * d
  );
  /* La ráfaga del scroll empuja en X al instante y decae fuera; el parallax
     desliza el campo entero al bajar — el mundo pasando, más deprisa cuanto
     más cerca. */
  vec2 p = fract(vec2(h1, h2)
                 + viento * u_t
                 + vec2(u_vel * 0.055 * d, u_scroll * 0.45 * d));

  gl_Position = vec4(p * 2.0 - 1.0, 0.0, 1.0);

  /* Tamaño por profundidad y clima, en píxeles físicos (por eso el dpr). */
  gl_PointSize = (1.3 + 2.9 * d + 1.1 * vent * d) * u_dpr;

  /* Brillo: las cercanas más vivas, con parpadeo lento propio; la ventisca
     las aviva. El tope queda lejos del blanco: son chispas de un par de
     píxeles, no luces. */
  float parpadeo = 0.75 + 0.25 * sin(u_t * (0.6 + h5 * 1.4) + h5 * 6.2831);
  vAlfa = vive * mix(0.14, 0.44, d) * parpadeo * (0.70 + 0.50 * vent);
  vMezcla = h5;
}`;

const FRAG_MOTAS = `
precision mediump float;
uniform vec3 u_tintA;
uniform vec3 u_tintB;
varying float vAlfa;
varying float vMezcla;

void main() {
  /* Un disco suave dentro del punto: sin esto cada mota es un cuadrado. */
  float r = length(gl_PointCoord - 0.5);
  float a = smoothstep(0.5, 0.14, r) * vAlfa;
  vec3 tinte = mix(u_tintB, u_tintA, vMezcla);
  gl_FragColor = vec4(tinte * a, a); /* premultiplicado, como la niebla */
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

function programa(gl, vertSrc, fragSrc) {
  const v = compilar(gl, gl.VERTEX_SHADER, vertSrc);
  const f = v && compilar(gl, gl.FRAGMENT_SHADER, fragSrc);
  if (!v || !f) return null;
  const p = gl.createProgram();
  gl.attachShader(p, v);
  gl.attachShader(p, f);
  gl.linkProgram(p);
  if (!gl.getProgramParameter(p, gl.LINK_STATUS)) {
    console.warn("ambiente3d: el programa no enlazó —", gl.getProgramInfoLog(p));
    return null;
  }
  return p;
}

function hexARgb(hex) {
  const n = parseInt(hex.slice(1), 16);
  return [((n >> 16) & 255) / 255, ((n >> 8) & 255) / 255, (n & 255) / 255];
}

const MOTAS = 1400;

/**
 * Monta la atmósfera detrás del sitio entero: la niebla y la ventisca que el
 * scroll conduce. Devuelve el lienzo, o `null` si el navegador no puede — y
 * entonces queda body::before, el mismo cielo en quieto.
 */
export function montarAmbiente({ reducido = false } = {}) {
  let gl = null;
  const lienzo = document.createElement("canvas");
  try {
    gl = lienzo.getContext("webgl", { alpha: true, antialias: false, premultipliedAlpha: true });
  } catch {
    gl = null;
  }
  if (!gl) return null;

  const pNiebla = programa(gl, VERT_NIEBLA, FRAG_NIEBLA);
  const pMotas = programa(gl, VERT_MOTAS, FRAG_MOTAS);
  if (!pNiebla || !pMotas) return null;

  /* geometría: el triángulo de la niebla y las semillas de las motas */
  const bufQuad = gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, bufQuad);
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
  const locPos = gl.getAttribLocation(pNiebla, "pos");

  const semillas = new Float32Array(MOTAS);
  for (let i = 0; i < MOTAS; i++) semillas[i] = (i + 1) * 0.61803398875; /* áurea: reparte sin patrones */
  const bufSemillas = gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, bufSemillas);
  gl.bufferData(gl.ARRAY_BUFFER, semillas, gl.STATIC_DRAW);
  const locSemilla = gl.getAttribLocation(pMotas, "semilla");

  const uN = {
    res: gl.getUniformLocation(pNiebla, "u_res"),
    t: gl.getUniformLocation(pNiebla, "u_t"),
    scroll: gl.getUniformLocation(pNiebla, "u_scroll"),
    vel: gl.getUniformLocation(pNiebla, "u_vel"),
    tintA: gl.getUniformLocation(pNiebla, "u_tintA"),
    tintB: gl.getUniformLocation(pNiebla, "u_tintB"),
  };
  const uM = {
    t: gl.getUniformLocation(pMotas, "u_t"),
    scroll: gl.getUniformLocation(pMotas, "u_scroll"),
    vel: gl.getUniformLocation(pMotas, "u_vel"),
    dpr: gl.getUniformLocation(pMotas, "u_dpr"),
    tintA: gl.getUniformLocation(pMotas, "u_tintA"),
    tintB: gl.getUniformLocation(pMotas, "u_tintB"),
  };

  const tintA = hexARgb("#b8f7e4");
  const tintB = hexARgb("#9fd0ea");
  gl.clearColor(0, 0, 0, 0);
  /* Las dos pasadas escriben premultiplicado; su mezcla es
     (ONE, ONE_MINUS_SRC_ALPHA): las motas se posan SOBRE la niebla sin
     sumarse hacia el blanco. */
  gl.enable(gl.BLEND);
  gl.blendFunc(gl.ONE, gl.ONE_MINUS_SRC_ALPHA);

  /* Las motas son puntos de un par de píxeles: a media resolución serían
     borrones. El lienzo va a resolución física con tope de DPR 1.5 — la
     niebla paga más píxeles, pero son tres octavas de fbm: barato. */
  const dpr = Math.min(window.devicePixelRatio || 1, 1.5);
  function medir() {
    const w = Math.max(1, Math.round(window.innerWidth * dpr));
    const h = Math.max(1, Math.round(window.innerHeight * dpr));
    if (lienzo.width !== w || lienzo.height !== h) {
      lienzo.width = w;
      lienzo.height = h;
      gl.viewport(0, 0, w, h);
    }
  }
  medir();

  lienzo.id = "ambiente-lienzo";
  lienzo.setAttribute("aria-hidden", "true");
  document.body.insertBefore(lienzo, document.body.firstChild);

  const inicio = performance.now();
  let scrollPrevio = window.scrollY;
  let rafaga = 0;
  let visible = document.visibilityState === "visible";
  let perdido = false;
  let idFrame = null;

  function pintar(t, scroll, vel) {
    medir();
    gl.clear(gl.COLOR_BUFFER_BIT);

    gl.useProgram(pNiebla);
    gl.bindBuffer(gl.ARRAY_BUFFER, bufQuad);
    gl.enableVertexAttribArray(locPos);
    gl.vertexAttribPointer(locPos, 2, gl.FLOAT, false, 0, 0);
    gl.uniform2f(uN.res, lienzo.width, lienzo.height);
    gl.uniform1f(uN.t, t);
    gl.uniform1f(uN.scroll, scroll);
    gl.uniform1f(uN.vel, vel);
    gl.uniform3fv(uN.tintA, tintA);
    gl.uniform3fv(uN.tintB, tintB);
    gl.drawArrays(gl.TRIANGLES, 0, 3);

    gl.useProgram(pMotas);
    gl.bindBuffer(gl.ARRAY_BUFFER, bufSemillas);
    gl.enableVertexAttribArray(locSemilla);
    gl.vertexAttribPointer(locSemilla, 1, gl.FLOAT, false, 0, 0);
    gl.uniform1f(uM.t, t);
    gl.uniform1f(uM.scroll, scroll);
    gl.uniform1f(uM.vel, vel);
    gl.uniform1f(uM.dpr, dpr);
    gl.uniform3fv(uM.tintA, tintA);
    gl.uniform3fv(uM.tintB, tintB);
    gl.drawArrays(gl.POINTS, 0, MOTAS);
  }

  function cuadro(ahora) {
    idFrame = null;
    if (!visible || perdido) return;

    const alto = Math.max(1, document.documentElement.scrollHeight - window.innerHeight);
    const y = window.scrollY;
    rafaga += ((y - scrollPrevio) / window.innerHeight - rafaga) * 0.10;
    scrollPrevio = y;

    pintar((ahora - inicio) / 1000, y / alto, Math.max(-1.5, Math.min(1.5, rafaga)));
    idFrame = requestAnimationFrame(cuadro);
  }

  lienzo.addEventListener("webglcontextlost", (e) => {
    e.preventDefault();
    perdido = true;
    lienzo.remove();
  });

  if (reducido) {
    /* Un solo cuadro quieto del clima sereno: el paisaje, sin la película. */
    pintar(0, 0, 0);
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
