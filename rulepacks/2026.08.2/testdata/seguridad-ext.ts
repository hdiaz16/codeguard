// Fixture de semgrep --test — no es código del producto.
// Casos positivos (ruleid) y negativos (ok) para las reglas ts-* y
// cors-wildcard-con-credenciales de seguridad-ext.yaml.

import * as cp from "child_process";
import * as crypto from "crypto";
import * as fs from "fs";
import * as https from "https";
import * as path from "path";

function sqlConcat(db, idUsuario, nombre) {
  // ruleid: ts-sql-concat
  db.raw(`SELECT id, nombre FROM usuarios WHERE id = ${idUsuario}`);
  // ruleid: ts-sql-concat
  db.execute(`SELECT id, nombre FROM usuarios WHERE nombre = ${nombre}`);
  // La plantilla interpolada en query() y la concatenación con + estaban
  // muertas hasta la curación de 2026-08-11 (el AND del regex de $M y un
  // pattern-not demasiado ancho las anulaban).
  // ruleid: ts-sql-concat
  db.query(`SELECT id FROM usuarios WHERE nombre = ${nombre}`);
  // ruleid: ts-sql-concat
  db.query("SELECT id FROM usuarios WHERE id = " + idUsuario);
  // ok: ts-sql-concat
  db.query("SELECT id, nombre FROM usuarios WHERE id = $1", [idUsuario]);
  // ok: ts-sql-concat
  db.query(`SELECT id, nombre FROM usuarios WHERE id = $1`, [idUsuario]);
}

function comandos(archivo, directorio) {
  // ruleid: ts-command-injection
  cp.exec(`convertir ${archivo}`);
  // ruleid: ts-command-injection
  cp.spawn("tar", ["xf", archivo], { shell: true });
  // ok: ts-command-injection
  cp.execFile("ls", [directorio]);
}

function deserializar(datos) {
  // ruleid: ts-unsafe-deserialization
  const serializador = require("node-serialize");
  // ruleid: ts-unsafe-deserialization
  const objeto = serializador.unserialize(datos);
  // ok: ts-unsafe-deserialization
  const seguro = JSON.parse(datos);
  return { objeto, seguro };
}

function resumenes(clave, iv) {
  // ruleid: ts-crypto-debil
  const resumenInseguro = crypto.createHash("md5");
  // ruleid: ts-crypto-debil
  const cifradorEcb = crypto.createCipheriv("aes-128-ecb", clave, iv);
  // ok: ts-crypto-debil
  const resumenSeguro = crypto.createHash("sha256");
  return { resumenInseguro, cifradorEcb, resumenSeguro };
}

function aleatorios() {
  // ruleid: ts-random-inseguro
  const sessionToken = Math.random().toString(36);
  // ok: ts-random-inseguro
  const factorMezcla = Math.random();
  return { sessionToken, factorMezcla };
}

function agentes() {
  // ruleid: ts-tls-verify-off
  const agenteInseguro = new https.Agent({ rejectUnauthorized: false });
  // ruleid: ts-tls-verify-off
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  // ok: ts-tls-verify-off
  const agenteSeguro = new https.Agent({ keepAlive: true });
  return { agenteInseguro, agenteSeguro };
}

function leerArchivo(req, directorioBase, manejador) {
  // ruleid: ts-path-traversal
  fs.readFile(path.join(directorioBase, req.params.archivo), manejador);
  // ok: ts-path-traversal
  fs.readFile(path.join(directorioBase, "config.json"), manejador);
}

function configurar(app) {
  // ruleid: ts-debug-en-prod
  app.set("env", "development");
  // ruleid: ts-debug-en-prod
  const opcionesErrores = { detalle: true, stacktrace: true };
  // ok: ts-debug-en-prod
  app.set("env", "production");
  return opcionesErrores;
}

async function proxyAbierto(req, res) {
  const destino = req.query.destino;
  // ruleid: ts-ssrf
  const respuesta = await fetch(destino);
  res.send(respuesta);
}

async function estadoInterno() {
  // ok: ts-ssrf
  return await fetch("https://api.interna.ejemplo.com/estado");
}

function renderizar(el, datosUsuario) {
  // ruleid: ts-innerhtml-var
  el.innerHTML = datosUsuario;
  // ok: ts-innerhtml-var
  el.innerHTML = "<b>texto estatico</b>";
  // ok: ts-innerhtml-var
  el.innerHTML = DOMPurify.sanitize(datosUsuario);
}

function politicasCors(app, cors) {
  // ruleid: cors-wildcard-con-credenciales
  app.use(cors({ origin: "*", credentials: true }));
  // ok: cors-wildcard-con-credenciales
  app.use(cors({ origin: "https://app.ejemplo.com", credentials: true }));
}
