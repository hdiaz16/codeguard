// Arnés del orbe: corre el JS DE VERDAD de widget.html contra un DOM de mentira.
//
// Existe porque las dos reglas que impiden que el orbe se quede colgado viven en
// ese JS y en ningún otro sitio: no se pinta un avance si el análisis ya terminó,
// y el contador no retrocede. Una prueba de contrato en Go ata los NOMBRES del
// cable (evento y campos) y no puede decir nada de la lógica; sin esto, borrar
// cualquiera de las dos guardas no pone nada en rojo.
//
// Vive en testdata/ y no en frontend/ a propósito: el daemon embebe frontend
// entero con //go:embed, así que un arnés ahí dentro viajaría en el instalador.

import { readFileSync } from "node:fs";
import vm from "node:vm";

const rutaHTML = process.argv[2];
const html = readFileSync(rutaHTML, "utf8");

// ── el guion real, sacado del HTML ───────────────────────────────────────────
const m = html.match(/<script type="module">([\s\S]*?)<\/script>/);
if (!m) fallar("no se encontró el <script type=\"module\"> en widget.html");
// El import del runtime de Wails es lo único que no puede correr aquí: se
// sustituye por el doble de abajo. Todo lo demás se ejecuta tal cual.
const fuente = m[1].replace(/^\s*import\s+\{\s*Events\s*\}.*$/m, "");
if (fuente === m[1]) fallar("no se encontró el import de Events: el arnés estaría probando otra cosa");

// ── DOM de mentira, con lo justo que el guion toca ───────────────────────────
class Elemento {
  constructor(id) {
    this.id = id;
    this._clases = new Set();
    this.className = "";
    this._texto = "";
    this._html = "";
    this._oyentes = {};
    // Cero: caja() devuelve null y el recorte de la ventana se queda callado,
    // que es lo que queremos — aquí se prueba el estado, no la geometría.
    this.offsetWidth = 0;
    this.offsetHeight = 0;
    this.offsetLeft = 0;
    this.offsetTop = 0;
    this.offsetParent = null;
    const self = this;
    this.classList = {
      add: (c) => self._clases.add(c),
      remove: (c) => self._clases.delete(c),
      contains: (c) => self._clases.has(c),
    };
  }
  // Los dos se pisan, como en un DOM de verdad: escribir textContent tira el
  // HTML que hubiera dentro y al revés. Sin esto, el arnés podía leer el
  // tooltip anterior debajo de un susurro nuevo y dar por bueno lo que ya no
  // se ve — se comprobó rompiendo una guarda a propósito.
  get textContent() { return this._texto; }
  set textContent(v) { this._texto = v; this._html = ""; }
  get innerHTML() { return this._html; }
  set innerHTML(v) { this._html = v; this._texto = ""; }

  addEventListener(nombre, fn) { this._oyentes[nombre] = fn; }
  disparar(nombre) { if (this._oyentes[nombre]) this._oyentes[nombre](); }
}

const elementos = {
  stage: new Elemento("stage"),
  orb: new Elemento("orb"),
  burbuja: new Elemento("burbuja"),
  "burbuja-texto": new Elemento("burbuja-texto"),
};

const oyentesBus = {};
const contexto = {
  document: {
    body: new Elemento("body"),
    getElementById: (id) => elementos[id] ?? new Elemento(id),
  },
  window: { devicePixelRatio: 1 },
  // Los temporizadores no se dejan correr: aquí se comprueba lo que el orbe
  // enseña al llegar cada evento, no cuándo se desvanece. Además, un
  // setInterval vivo dejaría este proceso sin terminar nunca.
  setTimeout: () => 0,
  clearTimeout: () => {},
  setInterval: () => 0,
  ResizeObserver: class { observe() {} },
  MutationObserver: class { observe() {} },
  JSON,
  console,
  Events: {
    On: (nombre, fn) => { oyentesBus[nombre] = fn; },
    Emit: () => {},
  },
};
contexto.globalThis = contexto;
vm.createContext(contexto);
vm.runInContext(fuente, contexto);

// ── el arnés ─────────────────────────────────────────────────────────────────

// Lo que el usuario ve DE VERDAD: la cápsula sólo se dibuja con la clase "on",
// y el texto vive en el span de dentro (plano si es susurro, HTML si es
// tooltip). Preguntar sólo por el texto daría por visible lo que está oculto.
function loQueSeVe() {
  if (!elementos.burbuja.classList.contains("on")) return "";
  const t = elementos["burbuja-texto"];
  return t.innerHTML || t.textContent;
}

function emitir(nombre, data) {
  const fn = oyentesBus[nombre];
  if (!fn) fallar(`el orbe no escucha ${nombre}`);
  fn({ data });
}
function estado(s, tooltip) { emitir("state", { state: s, tooltip }); }
function avance(texto, detalle, hechas, total) {
  emitir("progreso", { texto, detalle, hechas, total });
}
function exigir(cond, mensaje) { if (!cond) fallar(mensaje); }
function fallar(mensaje) {
  console.error("FALLO: " + mensaje);
  process.exit(1);
}

// 1. Con el análisis corriendo, cada avance se ve.
estado("working", "demo · rama master");
avance("1 de 3 · gofmt listo", "demo · rama master · 1 revisó · faltan 2", 1, 3);
exigir(loQueSeVe() === "1 de 3 · gofmt listo",
  `el avance no llegó a la burbuja: se ve ${JSON.stringify(loQueSeVe())}`);

// 2. El contador no retrocede: dos capas terminan a la vez y el bus de Wails no
//    garantiza el orden entre emisiones.
avance("3 de 3 · trivy listo", "demo · rama master · 3 revisaron", 3, 3);
avance("2 de 3 · semgrep listo", "demo · rama master · 2 revisaron · faltan 1", 2, 3);
exigir(loQueSeVe() === "3 de 3 · trivy listo",
  `un avance rezagado hizo retroceder el contador a ${JSON.stringify(loQueSeVe())}`);

// 3. LA REGLA: tras el veredicto, un avance rezagado no puede volver a poner al
//    orbe a contar capas de un commit ya decidido.
estado("pass", "demo · rama master · sin observaciones");
const trasElVeredicto = loQueSeVe();
avance("3 de 3 · staticcheck listo", "demo · rama master · 3 revisaron", 3, 3);
exigir(loQueSeVe() === trasElVeredicto,
  `un avance llegado DESPUÉS del veredicto repintó el orbe: ${JSON.stringify(loQueSeVe())}`);
exigir(elementos.stage.className === "stage orb-pass",
  `el orbe se quedó en ${elementos.stage.className} tras el veredicto`);

// 4. Y el análisis siguiente empieza de cero: el contador se reinicia, o los
//    avances del nuevo commit se descartarían por "viejos".
estado("working", "demo · rama master");
avance("1 de 9 · gofmt listo", "demo · rama master · 1 revisó · faltan 8", 1, 9);
exigir(loQueSeVe() === "1 de 9 · gofmt listo",
  `el análisis siguiente no pudo contar desde 1: se ve ${JSON.stringify(loQueSeVe())}`);

// 5. Con el ratón encima manda el tooltip, y también en vivo.
elementos.orb.disparar("mouseenter");
avance("2 de 9 · semgrep listo", "demo · rama master · 2 revisaron · faltan 7", 2, 9);
exigir(loQueSeVe().includes("2 revisaron"),
  `el tooltip abierto no se refrescó con el avance: ${JSON.stringify(loQueSeVe())}`);

// 6. Con el panel abierto la burbuja no se asoma: lo taparía, y el panel ya
//    enseña el veredicto con detalle.
elementos.orb.disparar("mouseleave");
emitir("panel-show", null);
avance("3 de 9 · trivy listo", "demo · rama master · 3 revisaron · faltan 6", 3, 9);
exigir(loQueSeVe() === "",
  `la burbuja se asomó con el panel abierto: ${JSON.stringify(loQueSeVe())}`);

console.log("arnés del orbe: 6 comprobaciones en verde");
