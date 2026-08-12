package linters

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"

	"codeguard/internal/engines/proc"
)

// runTool ejecuta una herramienta y devuelve stdout+stderr combinados.
// Un exit code != 0 NO es error si hubo salida (los linters salen con 1
// cuando encuentran problemas); sin salida sí es fallo de ejecución.
func runTool(ctx context.Context, dir, bin string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	// Herramientas Python en Windows: sin esto leen/escriben en cp1252
	// y rompen los acentos (mismo fix que en el adaptador de semgrep).
	cmd.Env = proc.Entorno("PYTHONUTF8=1", "PYTHONIOENCODING=utf-8")
	salida, err := proc.Correr(ctx, cmd, proc.MaxSalida)
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) && !salida.Recortada {
		return "", err // no arrancó (binario ausente, permisos...)
	}
	// Los linters se leen línea por línea: un texto recortado sigue siendo
	// útil, a diferencia de un JSON a medias.
	return string(salida.Combinada()), nil
}

// (runToolStdin vivió aquí para preguntarle a gofmt por stdin; se fue cuando
// el motor de formato pasó a go/format en proceso — lo señaló U1000 del
// propio staticcheck recién estrenado.)

// relTo pasa la ruta que reportó un motor a relativa-al-repo, y NO se fía de
// que filepath.Rel haya tenido éxito.
//
// Rel devuelve error sólo cuando no puede construir una relación (unidades
// distintas). Si las dos rutas son del mismo disco pero apuntan a sitios
// distintos, tiene "éxito" y devuelve algo como `..\..\..\..\otro\sitio`. Esa
// ruta no la abre ningún editor, no casa con ninguna huella de la baseline y no
// coincide con ningún archivo del diff: el hallazgo DESAPARECE en silencio, que
// es el peor final posible para un hallazgo real.
//
// El caso que lo destapó: Windows tiene dos nombres para el mismo directorio,
// el corto 8.3 (HECTOR~1.BOD) y el largo. Python resuelve el corto antes de
// imprimir rutas absolutas; Node no. Así que con la raíz en forma corta y el
// motor respondiendo en forma larga, Rel devolvía nueve `..` y el hallazgo se
// evaporaba. Lo encontró una prueba de integración de mypy, no un usuario —
// esta vez.
//
// La defensa no depende de conocer ese caso: si el resultado se sale de la
// raíz, se reintenta con la raíz canónica, y si aún se sale se devuelve la ruta
// cruda. Una ruta rara es incómoda; una ruta inventada esconde el hallazgo.
func relTo(root, p string) string {
	if rel, ok := relDentroDe(root, p); ok {
		return rel
	}
	if canon, err := filepath.EvalSymlinks(root); err == nil && canon != root {
		if rel, ok := relDentroDe(canon, p); ok {
			return rel
		}
	}
	return filepath.ToSlash(p)
}

// relDentroDe devuelve la ruta relativa sólo si de verdad cae DENTRO de la
// raíz. Un resultado que empieza por ".." es Rel diciendo "está en otro sitio",
// no una ruta utilizable.
func relDentroDe(root, p string) (string, bool) {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return "", false
	}
	rel = filepath.ToSlash(rel)
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return "", false
	}
	return rel, true
}
