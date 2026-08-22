// Fixture de semgrep --test — no es código del producto.
// Caso JSX de react-unvalidated-href-javascript (necesita extensión .tsx).

export function Enlace({ url }: { url: string }) {
  // ruleid: react-unvalidated-href-javascript
  return <a href={url}>perfil</a>;
}

export function EnlaceSeguro({ ruta }: { ruta: string }) {
  // ok: react-unvalidated-href-javascript
  return <a href={"/" + ruta}>interno</a>;
}
