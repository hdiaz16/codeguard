/* ══════════════════════════════════════════════════════════════════════════
   El mar de nubes — v3, con el listón de mont-fort.com.

   Héctor puso la referencia sobre la mesa: mont-fort.com — montañas nevadas
   con NUBES VOLUMÉTRICAS de verdad flotando entre ellas, luz, calma, cine.
   Las dos versiones anteriores de este archivo eran partículas: confeti con
   mejor o peor gusto. Lo que hace bello a mont-fort no son puntos: son MASAS
   — nubes con forma, con lado iluminado y lado en sombra, moviéndose
   despacio. Eso es lo que hay aquí, en la versión nocturna que le toca a
   CodeGuard: la cordillera del producto, de noche, con un mar de nubes
   iluminado por la luna.

   Cómo se consigue el volumen sin un solo vértice (técnica de manual de
   shaders, la misma familia que usan los sitios premiados):
   - DEFORMACIÓN DE DOMINIO: fbm(p + fbm(p)) — la nube deja de ser ruido
     uniforme y gana billows, jirones, bordes que se enroscan.
   - AUTOSOMBREADO: se muestrea la densidad un paso HACIA LA LUNA; donde la
     propia nube se tapa, se oscurece — eso es lo que el ojo lee como masa.
   - SILVER LINING: el borde fino a contraluz brilla — la firma de una nube
     iluminada por detrás.
   - EL CLARO: la densidad se rebaja en un óvalo suave alrededor del titular
     — exactamente como mont-fort abre un claro alrededor de su logo. La
     composición manda: el contenido no pelea con el cielo.
   - GRANO DE PELÍCULA y VIÑETA: lo que separa «render» de «fotografía».

   El scroll DESCIENDE por el manto: cada estrato se desplaza a su velocidad
   (parallax), y el guion de los climas sigue mandando — serena (nubes altas,
   finas, lentas), la ventisca (el manto se cierra, el viento arrastra jirones
   y nieva DENTRO del viento), y la montaña dormida (el manto queda arriba y
   el aire se despeja). La nieve de puntos ya no es el espectáculo: es un
   detalle que sólo existe dentro de la ventisca.

   Las reglas de siempre, intactas: todo premultiplicado (el quemado por
   driver es imposible), luminancia de nube ACOTADA (esto es un cielo de
   noche: la nube más iluminada queda muy por debajo del blanco del texto),
   capa fija z-0 con el contenido en z-1, `?clima=` para afinar, reduced
   motion = un cuadro quieto, y sin three.js (~7 KB en el bundle contra los
   189 KB gzip medidos de la alternativa).
   ══════════════════════════════════════════════════════════════════════════ */

const VERT_QUAD = `
attribute vec2 pos;
varying vec2 vUv;
void main() {
  vUv = pos * 0.5 + 0.5;
  gl_Position = vec4(pos, 0.0, 1.0);
}`;

const FRAG_NUBES = `
precision mediump float;
varying vec2 vUv;

uniform vec2  u_res;
uniform float u_t;
uniform float u_scroll;   /* avance 0..1 por la página */
uniform float u_clima;    /* guion: 0 serena .. 1 ventisca plena */
uniform float u_duerme;   /* guion: 0 .. 1 montaña dormida */
uniform float u_vel;      /* ráfaga del scroll, con signo */

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
/* cinco octavas: las nubes viven o mueren por el detalle del borde */
float fbm(vec2 p) {
  float v = 0.0, a = 0.5;
  for (int i = 0; i < 5; i++) {
    v += ruido(p) * a;
    p = p * 2.03 + vec2(17.3, 9.1);
    a *= 0.5;
  }
  return v;
}

/* densidad de un estrato: fbm deformado por otro fbm (los billows) */
float nube(vec2 p, float t, float viento) {
  vec2 warp = vec2(fbm(p * 0.85 + vec2(t * 0.020 * viento, 0.0)),
                   fbm(p * 0.85 - vec2(0.0, t * 0.013 * viento)));
  return fbm(p * 1.15 + warp * 1.35 + vec2(t * 0.035 * viento, t * 0.006));
}

void main() {
  vec2 uv = (vUv * u_res) / min(u_res.x, u_res.y);
  float t = u_t;
  float vent = u_clima;

  /* La luna vive arriba-centro — donde el orbe del héroe. Es la luz. */
  vec2 luna = vec2(0.5 * u_res.x / min(u_res.x, u_res.y), 0.98);
  vec2 haciaLuna = normalize(luna - uv);

  /* EL CLARO compositivo: un óvalo suave donde vive el titular (centro,
     levemente alto). La ventisca lo estrecha un poco — el clima aprieta —
     pero nunca lo cierra: el texto siempre tiene su aire. */
  vec2 c = uv - vec2(0.5 * u_res.x / min(u_res.x, u_res.y), 0.52);
  c.y *= 1.45;
  float claro = 1.0 - smoothstep(0.34 - 0.06 * vent, 0.85, length(c)) * 0.0
              - (1.0 - smoothstep(0.30 - 0.05 * vent, 0.72, length(c))) * 0.75;

  /* viento y descenso */
  float viento = 0.6 + 2.6 * vent;
  float rafaga = u_vel * 0.10;

  vec3 color = vec3(0.0);
  float alfa = 0.0;

  /* TRES ESTRATOS, de fondo a frente. Cada uno: su escala, su altura de
     banda en pantalla, su velocidad de descenso con el scroll (parallax) y
     su cobertura por clima. La banda se mueve con el scroll: DESCENDEMOS. */
  for (int i = 0; i < 3; i++) {
    float fi = float(i);
    float prof = (fi + 1.0) / 3.0;                 /* 0.33 lejos .. 1 cerca */

    /* dónde vive la banda de este estrato AHORA: sube al bajar la página
       (nosotros descendemos), cada estrato a su ritmo */
    float centroBanda = 0.78 - fi * 0.34 + u_scroll * (0.55 + 0.65 * prof)
                      - u_duerme * (0.55 + 0.45 * prof);
    float banda = 1.0 - smoothstep(0.12, 0.55 + 0.18 * vent, abs(uv.y - centroBanda));
    if (banda <= 0.001) continue;

    vec2 p = uv * (1.35 + fi * 0.85)
           + vec2(t * (0.008 + 0.012 * fi) * viento + rafaga * prof,
                  -u_scroll * (0.35 + 0.55 * prof));

    float d = nube(p, t, viento);

    /* cobertura: serena = manto abierto (0.56); ventisca lo cierra (0.40).
       smoothstep estrecho = bordes de nube definidos, no bruma uniforme. */
    float cobertura = 0.56 - 0.16 * vent + 0.10 * u_duerme;
    float dens = smoothstep(cobertura, cobertura + 0.24, d) * banda * claro;
    if (dens <= 0.001) continue;

    /* autosombra: densidad un paso hacia la luna; si la nube se tapa a sí
       misma, ese punto está en su lado oscuro */
    float dl = nube(p + haciaLuna * 0.14, t, viento);
    float sombra = clamp((dl - d) * 2.2, 0.0, 1.0);
    float luz = 1.0 - sombra;

    /* silver lining: borde fino y denso de cara a la luna */
    float borde = smoothstep(cobertura, cobertura + 0.10, d)
                - smoothstep(cobertura + 0.10, cobertura + 0.30, d);
    float plata = borde * luz * (0.35 + 0.25 * vent);

    /* la paleta de una nube DE NOCHE: base en sombra azulada, cara lunar en
       gris plateado, y el lining apenas más claro. Nada llega al blanco —
       el texto del sitio siempre gana. La ventisca enfría y aclara un poco;
       la dormida lo apaga todo. */
    vec3 sombraCol = mix(vec3(0.086, 0.106, 0.133), vec3(0.102, 0.125, 0.157), vent);
    vec3 lunarCol  = mix(vec3(0.290, 0.333, 0.392), vec3(0.365, 0.427, 0.502), vent);
    lunarCol = mix(lunarCol, vec3(0.184, 0.208, 0.239), u_duerme);
    vec3 plataCol  = mix(vec3(0.545, 0.612, 0.686), vec3(0.647, 0.729, 0.808), vent);

    vec3 col = mix(sombraCol, lunarCol, luz * (0.55 + 0.25 * prof)) + plataCol * plata;

    /* el resplandor de la luna atraviesa más el estrato lejano */
    float cercaniaLuna = exp(-1.6 * distance(uv, luna));
    col += vec3(0.16, 0.18, 0.20) * cercaniaLuna * (1.0 - prof) * luz;

    float a = dens * (0.30 + 0.22 * prof) * (1.0 - 0.55 * u_duerme);

    /* composición front-to-back premultiplicada, estrato sobre estrato */
    color = color + col * a * (1.0 - alfa);
    alfa = alfa + a * (1.0 - alfa);
  }

  /* VIÑETA: las esquinas se hunden un poco — el encuadre de cine. Es color
     negro, así que solo puede OSCURECER: jamás quema nada. */
  vec2 vq = vUv - 0.5;
  float vineta = smoothstep(0.55, 0.95, length(vq * vec2(1.15, 1.0))) * 0.30;
  color *= (1.0 - vineta * 0.5);
  alfa = alfa + vineta * (1.0 - alfa) * 0.55;
  /* (la viñeta añade alfa de negro: oscurece el fondo, no el contenido) */

  /* GRANO DE PELÍCULA: un velo de ±1.5% que respira cada cuadro. Es lo que
     separa un degradado de ordenador de una fotografía. */
  float grano = (hash(vUv * u_res + fract(t) * 61.7) - 0.5) * 0.03;
  color += grano * alfa;

  gl_FragColor = vec4(color, alfa); /* ya premultiplicado por construcción */
}`;

/* ── la nieve: SOLO dentro de la ventisca, como detalle del viento ──────── */
const VERT_NIEVE = `
precision mediump float;
attribute float semilla;

uniform float u_t;
uniform float u_scroll;
uniform float u_clima;
uniform float u_vel;
uniform float u_dpr;
uniform float u_maxPunto;

varying float vAlfa;
varying float vEstira;
varying vec2  vViento;

float h(float s, float k) { return fract(sin(s * k) * 43758.5453123); }

void main() {
  float h1 = h(semilla, 12.9898);
  float h2 = h(semilla, 78.2330);
  float h3 = h(semilla, 43.7585);
  float h4 = h(semilla, 91.2228);

  float vent = u_clima;
  float d = mix(0.35, 1.0, h3);

  /* la nieve existe SOLO con ventisca: aparece gradualmente con ella */
  float vive = step(h4, vent * vent);

  vec2 viento = vec2(-(0.05 + 0.22 * vent) * d, -(0.05 + 0.09 * vent) * d);
  vec2 p = fract(vec2(h1, h2)
                 + viento * u_t
                 + vec2(u_vel * 0.06 * d, u_scroll * 0.5 * d));

  gl_Position = vec4(p * 2.0 - 1.0, 0.0, 1.0);

  float px = 1.4 + 2.8 * d;
  vEstira = 1.0 + vent * 2.6 * d;
  gl_PointSize = min(px * vEstira * u_dpr, u_maxPunto);

  float ang = atan(viento.y, viento.x - u_vel * 0.04);
  vViento = vec2(cos(ang), sin(ang));

  vAlfa = vive * mix(0.10, 0.34, d) * (0.6 + 0.4 * vent);
}`;

const FRAG_NIEVE = `
precision mediump float;
varying float vAlfa;
varying float vEstira;
varying vec2  vViento;

void main() {
  vec2 q = gl_PointCoord - 0.5;
  vec2 r = vec2(q.x * vViento.x + q.y * vViento.y,
               -q.x * vViento.y + q.y * vViento.x);
  r.x /= vEstira;
  float a = smoothstep(0.5, 0.12, length(r)) * vAlfa;
  gl_FragColor = vec4(vec3(0.72, 0.78, 0.85) * a, a); /* premultiplicado */
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

const COPOS = 700;

/* El guion del descenso: la ventisca sube del 8% al 38%, plena por el centro,
   amaina del 62% al 92% hacia la montaña dormida. */
function guion(scroll) {
  const sube = Math.min(1, Math.max(0, (scroll - 0.08) / 0.30));
  const baja = Math.min(1, Math.max(0, (scroll - 0.62) / 0.30));
  const s = sube * sube * (3 - 2 * sube);
  const b = baja * baja * (3 - 2 * baja);
  return { vent: s * (1 - 0.85 * b), duerme: b };
}

/**
 * Monta el mar de nubes detrás del sitio entero. Devuelve el lienzo, o `null`
 * si el navegador no puede — y queda body::before: el cielo, en quieto.
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

  const pNubes = programa(gl, VERT_QUAD, FRAG_NUBES);
  const pNieve = programa(gl, VERT_NIEVE, FRAG_NIEVE);
  if (!pNubes || !pNieve) return null;

  const bufQuad = gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, bufQuad);
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
  const locPos = gl.getAttribLocation(pNubes, "pos");

  const semillas = new Float32Array(COPOS);
  for (let i = 0; i < COPOS; i++) semillas[i] = (i + 1) * 0.61803398875;
  const bufSemillas = gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, bufSemillas);
  gl.bufferData(gl.ARRAY_BUFFER, semillas, gl.STATIC_DRAW);
  const locSemilla = gl.getAttribLocation(pNieve, "semilla");

  const uC = {};
  for (const n of ["u_res", "u_t", "u_scroll", "u_clima", "u_duerme", "u_vel"])
    uC[n] = gl.getUniformLocation(pNubes, n);
  const uN = {};
  for (const n of ["u_t", "u_scroll", "u_clima", "u_vel", "u_dpr", "u_maxPunto"])
    uN[n] = gl.getUniformLocation(pNieve, n);

  gl.clearColor(0, 0, 0, 0);
  gl.enable(gl.BLEND);
  gl.blendFunc(gl.ONE, gl.ONE_MINUS_SRC_ALPHA);

  const rango = gl.getParameter(gl.ALIASED_POINT_SIZE_RANGE);
  const maxPunto = Math.min(rango ? rango[1] : 64, 96);

  /* Las nubes son masas suaves: se pintan a ~0.62 de la resolución física y
     el CSS estira — cinco octavas con warp por píxel no son gratis, y a esta
     escala nadie distingue la diferencia en un degradado. */
  const dpr = Math.min(window.devicePixelRatio || 1, 1.5);
  const escala = 0.62 * dpr;
  function medir() {
    const w = Math.max(1, Math.round(window.innerWidth * escala));
    const h = Math.max(1, Math.round(window.innerHeight * escala));
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

  /* ?clima=0.5 fija el punto del guion, para afinar y capturar. */
  let climaFijo = null;
  try {
    const q = new URLSearchParams(location.search).get("clima");
    if (q !== null && q !== "" && !isNaN(+q)) climaFijo = Math.min(1, Math.max(0, +q));
  } catch {
    climaFijo = null; // sin URLSearchParams no hay mando — y no pasa nada
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

    gl.clear(gl.COLOR_BUFFER_BIT);

    gl.useProgram(pNubes);
    gl.bindBuffer(gl.ARRAY_BUFFER, bufQuad);
    gl.enableVertexAttribArray(locPos);
    gl.vertexAttribPointer(locPos, 2, gl.FLOAT, false, 0, 0);
    gl.uniform2f(uC.u_res, lienzo.width, lienzo.height);
    gl.uniform1f(uC.u_t, t);
    gl.uniform1f(uC.u_scroll, scroll);
    gl.uniform1f(uC.u_clima, g.vent);
    gl.uniform1f(uC.u_duerme, g.duerme);
    gl.uniform1f(uC.u_vel, vel);
    gl.drawArrays(gl.TRIANGLES, 0, 3);

    if (g.vent > 0.02) {
      gl.useProgram(pNieve);
      gl.bindBuffer(gl.ARRAY_BUFFER, bufSemillas);
      gl.enableVertexAttribArray(locSemilla);
      gl.vertexAttribPointer(locSemilla, 1, gl.FLOAT, false, 0, 0);
      gl.uniform1f(uN.u_t, t);
      gl.uniform1f(uN.u_scroll, scroll);
      gl.uniform1f(uN.u_clima, g.vent);
      gl.uniform1f(uN.u_vel, vel);
      gl.uniform1f(uN.u_dpr, escala);
      gl.uniform1f(uN.u_maxPunto, maxPunto);
      gl.drawArrays(gl.POINTS, 0, COPOS);
    }
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
