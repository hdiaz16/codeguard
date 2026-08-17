import { defineConfig } from "vite";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const raiz = dirname(fileURLToPath(import.meta.url));

// Dos páginas: la portada y la documentación. La documentación es una página
// aparte y no una sección más de la portada a propósito — se llega a ella por
// enlace directo, se busca dentro, y no tiene por qué pagar las animaciones
// del recorrido para leer la ayuda de un comando.
export default defineConfig({
  root: raiz,
  base: "./",
  build: {
    outDir: "dist",
    emptyOutDir: true,
    rollupOptions: {
      input: {
        portada: resolve(raiz, "index.html"),
        docs: resolve(raiz, "docs.html"),
      },
    },
  },
  server: {
    port: 5175,
    strictPort: false,
    open: false,
  },
});
