// Fixture de semgrep --test — no es código del producto.
import jwt from "jsonwebtoken";

export function ejecutarExpresion(datos: string) {
  // ruleid: ts-eval
  return eval(datos);
}

export function parsearDatos(datos: string) {
  // ok: ts-eval
  return JSON.parse(datos);
}

export function configurarCorsAbierto(res: Respuesta) {
  // ruleid: cors-wildcard
  res.setHeader("Access-Control-Allow-Origin", "*");
}

export function configurarCorsRestringido(res: Respuesta) {
  // ok: cors-wildcard
  res.setHeader("Access-Control-Allow-Origin", "https://app.ejemplo.mx");
}

export function leerToken(token: string) {
  // ruleid: ts-jwt-decode-no-verify
  return jwt.decode(token);
}

export function leerTokenVerificado(token: string, secreto: string) {
  // ok: ts-jwt-decode-no-verify
  return jwt.verify(token, secreto);
}
