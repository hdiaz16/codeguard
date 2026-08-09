package codegraph

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

//go:embed assets
var assets embed.FS

// WriteExplorer escribe el explorador interactivo autocontenido: una carpeta
// con la página + Sigma.js y graphology embebidos (funciona offline, sin CDN).
func WriteExplorer(g *Graph, outDir string) (string, error) {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", err
	}
	// librerías tal cual
	for _, name := range []string{"graphology.js", "sigma.js"} {
		raw, err := assets.ReadFile("assets/" + name)
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(outDir, name), raw, 0o644); err != nil {
			return "", err
		}
	}
	// página con los datos inyectados
	page, err := assets.ReadFile("assets/explorer.html")
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(g)
	if err != nil {
		return "", err
	}
	const marker = `/*__GRAPH_DATA__*/ {"nodes":[],"edges":[],"lang":"go","root":""}`
	html := strings.Replace(string(page), marker, string(data), 1)
	if !strings.Contains(html, `"nodes"`) {
		return "", fmt.Errorf("no se pudo inyectar el grafo en la plantilla")
	}
	out := filepath.Join(outDir, "index.html")
	if err := os.WriteFile(out, []byte(html), 0o644); err != nil {
		return "", err
	}
	return out, nil
}
