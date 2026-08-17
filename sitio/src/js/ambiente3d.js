/* ══════════════════════════════════════════════════════════════════════════
   El descenso por los climas — v2, con las técnicas de los que ganan premios.

   La v1 se veía «regular» y el porqué es de manual: todas las motas eran
   puntos del mismo tamaño — confeti plano. Lo que separa un fondo premiado de
   uno corriente (mirado en los ganadores de Awwwards de 2026) son cuatro
   cosas, y las cuatro están aquí:

   1. PROFUNDIDAD POR ESCALA, no por cantidad: tres bandas de partículas —
      polvo lejano (diminuto, lento, tenue), copos medios, y BOKEH cercano:
      pocos discos GRANDES fuera de foco, de borde suavísimo, rápidos y con
      mucho parallax. El bokeh es lo que convierte una pantalla en una LENTE:
      de pronto hay un espacio delante y detrás del contenido.
   2. GRADACIÓN DE COLOR ATADA A LA NARRATIVA: cada clima tiene su paleta y el
      scroll las funde — serena en menta suave, la ventisca enfría a
      azul-blanco, y la montaña dormida apaga a pizarra cálida y tenue.
   3. ESTELAS EN EL VIENTO: con la ventisca arriba, los copos cercanos se
      alargan en la dirección del viento (anisotropía en el fragment, sin
      geometría extra) — velocidad que SE VE, no que se supone.
   4. FÍSICA CON INERCIA: la ráfaga del scroll empuja y decae sola (ya estaba).

   Y la regla que no cambia desde el incendio blanco: la atmósfera está
   SUBORDINADA al contenido — topes duros de alfa en el shader, todo
   premultiplicado (el quemado es imposible por driver), capa fija z-0 con el
   contenido en z-1. El bokeh es grande pero casi transparente: presencia, no
   velo.

   Mando de afinación: añadir `?clima=0.7` a la URL fija ese punto del guion
   (0 = serena, 0.5 = ventisca plena, 1 = dormida) sin scrollear — para tunear
   los mandos y para capturas. En producción nadie lo pisa por accidente.

   Sin three.js (189 KB gzip medidos por una escena equivalente); esto son
   ~6 KB dentro del bundle. Si algo falla, null y queda body::before.
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
uniform vec3  u_tintA;   /* graduado por clima desde JS */
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
     0.055 — la niebla habla el idioma del sitio o es una mancha. */
  float niebla = smoothstep(0.50, 0.90, f) * 0.055;
  vec3 tinte = mix(u_tintB, u_tintA, fbm(uv * 0.8 + t * 0.006));

  gl_FragColor = vec4(tinte * niebla, niebla); /* premultiplicado */
}`;

/* ── las motas: tres bandas de profundidad y estelas en el viento ────────── */
const VERT_MOTAS = `
precision mediump float;
attribute float semilla;

uniform float u_t;
uniform float u_scroll;
uniform float u_clima;    /* el guion ya evaluado: 0 calma .. 1 ventisca */
uniform float u_vel;
uniform float u_dpr;
uniform float u_maxPunto; /* tope de gl_PointSize del driver */

varying float vAlfa;
varying float vMezcla;
varying float vEstira;    /* 1 = disco; >1 = estela a lo largo del viento */
varying vec2  vViento;    /* cos/sin de la dirección del viento, para girar el punto */

float h(float s, float k) { return fract(sin(s * k) * 43758.5453123); }

void main() {
  float h1 = h(semilla, 12.9898);
  float h2 = h(semilla, 78.2330);
  float h3 = h(semilla, 43.7585);   /* banda de profundidad */
  float h4 = h(semilla, 91.2228);   /* densidad por clima */
  float h5 = h(semilla, 26.6519);   /* parpadeo y tinte */

  float vent = u_clima;

  /* Las TRES BANDAS salen de h3: 55% polvo lejano, 39% copos medios, 6%
     bokeh cercano. d es la profundidad continua dentro de su banda. */
  float lejos = step(h3, 0.55);
  float medio = step(0.55, h3) * step(h3, 0.94);
  float cerca = step(0.94, h3);
  float d = lejos * mix(0.20, 0.45, h3 / 0.55)
          + medio * mix(0.45, 0.85, (h3 - 0.55) / 0.39)
          + cerca * mix(0.85, 1.00, (h3 - 0.94) / 0.06);

  /* En calma vive un tercio; la ventisca las despierta a todas. El bokeh
     cercano vive SIEMPRE: es el que sostiene la sensación de lente. */
  float dens = 0.32 + 0.68 * vent;
  float vive = max(cerca, step(h4, dens));

  /* El viento: manso y casi vertical en calma; con la ventisca el empuje
     lateral crece un orden de magnitud. Escala con la profundidad. */
  vec2 viento = vec2(
    -(0.010 + 0.150 * vent) * d,
    -(0.016 + 0.070 * vent) * d
  );
  vec2 p = fract(vec2(h1, h2)
                 + viento * u_t
                 + vec2(u_vel * 0.055 * d, u_scroll * 0.45 * d));

  gl_Position = vec4(p * 2.0 - 1.0, 0.0, 1.0);

  /* Tamaño por banda, en píxeles físicos:
     polvo 1.2-2.4 · copos 2.5-6 · BOKEH 18-44 (px CSS; ×dpr físicos).
     El bokeh respira un poco con el clima. El tope del driver manda. */
  float px = lejos * (1.2 + 1.2 * (d / 0.45))
           + medio * (2.5 + 3.5 * ((d - 0.45) / 0.40))
           + cerca * (18.0 + 26.0 * ((d - 0.85) / 0.15) + 6.0 * vent);

  /* LA ESTELA: con la ventisca, copos y bokeh se alargan en la dirección del
     viento — hasta 3.5× los cercanos. El punto crece para contenerla y el
     fragment la dibuja anisótropa. El polvo lejano no se estira: a esa
     distancia el ojo no resuelve estelas, sólo brillo. */
  vEstira = 1.0 + vent * (medio * 1.6 + cerca * 2.5) * (0.5 + 0.5 * d);
  float lado = min(px * vEstira * u_dpr, u_maxPunto);
  gl_PointSize = lado;

  float ang = atan(viento.y, viento.x - u_vel * 0.03);
  vViento = vec2(cos(ang), sin(ang));

  /* Brillo por banda: el bokeh es GRANDE, así que va casi transparente —
     presencia sin velo (0.05-0.09). Los copos brillan más con la ventisca;
     el polvo apenas existe y parpadea lento. */
  float parpadeo = 0.72 + 0.28 * sin(u_t * (0.5 + h5 * 1.3) + h5 * 6.2831);
  float alfaBanda = lejos * 0.16
                  + medio * (0.26 + 0.22 * vent)
                  + cerca * (0.055 + 0.030 * vent);
  vAlfa = vive * alfaBanda * parpadeo;
  vMezcla = h5;
}`;

const FRAG_MOTAS = `
precision mediump float;
uniform vec3 u_tintA;
uniform vec3 u_tintB;
varying float vAlfa;
varying float vMezcla;
varying float vEstira;
varying vec2  vViento;

void main() {
  /* El punto se gira a la dirección del viento y se COMPRIME el eje del
     viento en el espacio de la distancia: eso alarga el disco en pantalla —
     la estela — sin un solo vértice extra. */
  vec2 q = gl_PointCoord - 0.5;
  vec2 r = vec2(q.x * vViento.x + q.y * vViento.y,
               -q.x * vViento.y + q.y * vViento.x);
  r.x /= vEstira;
  float dist = length(r) * (1.0 + (vEstira - 1.0) * 0.25);

  /* Borde suavísimo: el bokeh vive o muere por este falloff. */
  float a = smoothstep(0.5, 0.10, dist) * vAlfa;
  vec3 tinte = mix(u_tintB, u_tintA, vMezcla);
  gl_FragColor = vec4(tinte * a, a); /* premultiplicado */
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

/* mezcla lineal de dos colores rgb ya normalizados */
function lerp3(a, b, t) {
  return [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t];
}

const MOTAS = 1400;

/* LA GRADACIÓN: cada clima tiene su paleta y el scroll las funde.
   serena  — la menta y el azul de body::before, suaves;
   ventisca— enfría y aclara: azul-blanco de nieve al viento;
   dormida — apaga a pizarra cálida: la montaña respirando bajito. */
const PALETA = {
  serenaA: hexARgb("#b8f7e4"), serenaB: hexARgb("#9fd0ea"),
  ventA:   hexARgb("#e8f2fb"), ventB:   hexARgb("#a9c6e8"),
  duermeA: hexARgb("#9aa3b2"), duermeB: hexARgb("#7d8696"),
};

/* El guion del descenso, compartido por color y partículas: la ventisca se
   levanta del 8% al 38%, sopla plena por el centro, amaina del 62% al 92%. */
function guion(scroll) {
  const sube = Math.min(1, Math.max(0, (scroll - 0.08) / 0.30));
  const baja = Math.min(1, Math.max(0, (scroll - 0.62) / 0.30));
  const s = sube * sube * (3 - 2 * sube);
  const b = baja * baja * (3 - 2 * baja);
  return { vent: s * (1 - 0.8 * b), duerme: b };
}

/**
 * Monta la atmósfera detrás del sitio entero. Devuelve el lienzo, o `null` si
 * el navegador no puede — y entonces queda body::before, el cielo en quieto.
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

  const bufQuad = gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, bufQuad);
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
  const locPos = gl.getAttribLocation(pNiebla, "pos");

  const semillas = new Float32Array(MOTAS);
  for (let i = 0; i < MOTAS; i++) semillas[i] = (i + 1) * 0.61803398875;
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
    clima: gl.getUniformLocation(pMotas, "u_clima"),
    vel: gl.getUniformLocation(pMotas, "u_vel"),
    dpr: gl.getUniformLocation(pMotas, "u_dpr"),
    maxPunto: gl.getUniformLocation(pMotas, "u_maxPunto"),
    tintA: gl.getUniformLocation(pMotas, "u_tintA"),
    tintB: gl.getUniformLocation(pMotas, "u_tintB"),
  };

  gl.clearColor(0, 0, 0, 0);
  gl.enable(gl.BLEND);
  gl.blendFunc(gl.ONE, gl.ONE_MINUS_SRC_ALPHA);

  /* El bokeh pide puntos de hasta ~66 px físicos; hay GPUs (móviles sobre
     todo) que capan gl_PointSize en 64. Se pregunta el tope real y el shader
     lo respeta: en una GPU capada el bokeh sale algo menor, nunca roto. */
  const rango = gl.getParameter(gl.ALIASED_POINT_SIZE_RANGE);
  const maxPunto = Math.min(rango ? rango[1] : 64, 160);

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

  /* ?clima=0.6 fija el punto del guion para tunear y capturar. */
  let climaFijo = null;
  try {
    const q = new URLSearchParams(location.search).get("clima");
    if (q !== null && q !== "" && !isNaN(+q)) climaFijo = Math.min(1, Math.max(0, +q));
  } catch {
    climaFijo = null; // sin URLSearchParams no hay mando de afinación — y no pasa nada
  }

  const inicio = performance.now();
  let scrollPrevio = window.scrollY;
  let rafaga = 0;
  let visible = document.visibilityState === "visible";
  let perdido = false;
  let idFrame = null;

  function pintar(t, scroll, vel) {
    medir();
    const g = guion(scroll);

    /* la paleta del momento: serena -> ventisca -> dormida */
    let tA = lerp3(PALETA.serenaA, PALETA.ventA, g.vent);
    let tB = lerp3(PALETA.serenaB, PALETA.ventB, g.vent);
    tA = lerp3(tA, PALETA.duermeA, g.duerme);
    tB = lerp3(tB, PALETA.duermeB, g.duerme);

    gl.clear(gl.COLOR_BUFFER_BIT);

    gl.useProgram(pNiebla);
    gl.bindBuffer(gl.ARRAY_BUFFER, bufQuad);
    gl.enableVertexAttribArray(locPos);
    gl.vertexAttribPointer(locPos, 2, gl.FLOAT, false, 0, 0);
    gl.uniform2f(uN.res, lienzo.width, lienzo.height);
    gl.uniform1f(uN.t, t);
    gl.uniform1f(uN.scroll, scroll);
    gl.uniform1f(uN.vel, vel);
    gl.uniform3fv(uN.tintA, tA);
    gl.uniform3fv(uN.tintB, tB);
    gl.drawArrays(gl.TRIANGLES, 0, 3);

    gl.useProgram(pMotas);
    gl.bindBuffer(gl.ARRAY_BUFFER, bufSemillas);
    gl.enableVertexAttribArray(locSemilla);
    gl.vertexAttribPointer(locSemilla, 1, gl.FLOAT, false, 0, 0);
    gl.uniform1f(uM.t, t);
    gl.uniform1f(uM.scroll, scroll);
    gl.uniform1f(uM.clima, g.vent);
    gl.uniform1f(uM.vel, vel);
    gl.uniform1f(uM.dpr, dpr);
    gl.uniform1f(uM.maxPunto, maxPunto);
    gl.uniform3fv(uM.tintA, tA);
    gl.uniform3fv(uM.tintB, tB);
    gl.drawArrays(gl.POINTS, 0, MOTAS);
  }

  function cuadro(ahora) {
    idFrame = null;
    if (!visible || perdido) return;

    const alto = Math.max(1, document.documentElement.scrollHeight - window.innerHeight);
    const y = window.scrollY;
    rafaga += ((y - scrollPrevio) / window.innerHeight - rafaga) * 0.10;
    scrollPrevio = y;

    const scroll = climaFijo != null ? climaFijo : y / alto;
    pintar((ahora - inicio) / 1000, scroll, Math.max(-1.5, Math.min(1.5, rafaga)));
    idFrame = requestAnimationFrame(cuadro);
  }

  lienzo.addEventListener("webglcontextlost", (e) => {
    e.preventDefault();
    perdido = true;
    lienzo.remove();
  });

  if (reducido) {
    pintar(0, climaFijo != null ? climaFijo : 0, 0);
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
