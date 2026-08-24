// Fixture de semgrep --test — no es código del producto.

export async function buscarUsuarios(prisma: ClientePrisma, nombre: string) {
  // ruleid: orm-raw-interpolado-ts
  return prisma.$queryRawUnsafe(`SELECT id FROM usuarios WHERE nombre = '${nombre}'`);
}

export async function buscarUsuariosBien(prisma: ClientePrisma, nombre: string) {
  // ok: orm-raw-interpolado-ts
  return prisma.$queryRawUnsafe("SELECT id FROM usuarios WHERE nombre = $1", nombre);
}

export function crearSesion(res: Respuesta, token: string) {
  // ruleid: cookie-sin-httponly
  res.cookie("sesion", token);
}

export function crearSesionExpuesta(res: Respuesta, token: string) {
  // ruleid: cookie-sin-httponly
  res.cookie("sesion", token, { httpOnly: false, secure: true });
}

export function crearSesionBien(res: Respuesta, token: string) {
  // ok: cookie-sin-httponly
  res.cookie("sesion", token, { httpOnly: true, secure: true, sameSite: "lax" });
}

export function guardarPreferencia(res: Respuesta, valor: string) {
  // ruleid: cookie-sin-secure
  res.cookie("tema", valor, { httpOnly: true });
}

export function guardarPreferenciaBien(res: Respuesta, valor: string) {
  // ok: cookie-sin-secure
  res.cookie("tema", valor, { httpOnly: true, secure: true });
}
